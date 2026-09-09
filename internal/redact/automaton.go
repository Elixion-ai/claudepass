package redact

// automaton is a compiled multi-pattern matcher over a fixed set of
// Patterns. It replaces a per-pattern bytes.Index scan with a single pass
// over the buffer that costs one array lookup per byte in the common case
// (no Pattern present), and only walks a shared trie of every Pattern's
// bytes at the rare position where a Pattern could plausibly start.
//
// scan's per-byte gate check has no dependency between one byte and the
// next, so consecutive bytes pipeline; the only place bytes are consumed one
// at a time in a true dependency chain (each byte's lookup address depends
// on the previous byte's result) is the trie walk, and that only runs for
// the few positions the gate lets through, and only as far as the buffer's
// actual content agrees with some Pattern's bytes. Building every occurrence
// this way, and resolving them to the leftmost-longest set afterwards
// (scan, in writer.go), is equivalent to a full Aho-Corasick automaton for
// this package's purpose: finding every occurrence and reporting them
// leftmost-longest, non-overlapping.
type automaton struct {
	gate     [256]bool    // gate[b] is true when some Pattern starts with byte b; the fast, dependency-free reject for scan's outer loop
	children [][256]int32 // children[state][b] -> state, or -1 when no Pattern's bytes continue this way; a plain trie, walked only from a gate hit
	own      [][]uint16   // own[state] lists the pattern indices whose full Bytes end exactly at state

	// The remaining fields serve only partialLen's small-window check for
	// the suffix that might still complete a Pattern with more bytes, where
	// throughput does not matter: a proper Aho-Corasick DFA (goto with
	// failure resolved, so failure never needs walking at scan time).
	next   [][256]int32 // next[state][b] -> state, failure-resolved
	fail   []int32      // fail[state] -> the longest-proper-suffix state
	depth  []int32      // depth[state] is the length of the string state represents
	hasKid []bool       // hasKid[state] is true when some Pattern is strictly longer with state's string as a prefix

	patLen []int32 // patLen[pidx] is len(patterns[pidx].Bytes)
	maxLen int     // longest Pattern, in bytes; bounds the hold-back window
}

const acRoot int32 = 0

// acMatch is one occurrence of patterns[pidx] at buf[start:start+length].
// Occurrences found by automaton.find may overlap; scan resolves them to the
// leftmost-longest, non-overlapping set.
type acMatch struct {
	start, length, pidx int
}

func newRow() [256]int32 {
	var row [256]int32
	for i := range row {
		row[i] = -1
	}
	return row
}

// buildAutomaton compiles patterns into an automaton. patterns must be
// non-empty.
func buildAutomaton(patterns []Pattern) *automaton {
	// Trie construction: children[state][b] == -1 means no child yet.
	children := [][256]int32{newRow()}
	depth := []int32{0}
	hasKid := []bool{false}
	own := [][]uint16{nil}

	newNode := func(parent int32) int32 {
		children = append(children, newRow())
		depth = append(depth, depth[parent]+1)
		hasKid = append(hasKid, false)
		own = append(own, nil)
		return int32(len(children) - 1)
	}

	var gate [256]bool
	maxLen := 0
	patLen := make([]int32, len(patterns))
	for pidx, p := range patterns {
		patLen[pidx] = int32(len(p.Bytes))
		if len(p.Bytes) > maxLen {
			maxLen = len(p.Bytes)
		}
		gate[p.Bytes[0]] = true
		cur := acRoot
		for _, ch := range p.Bytes {
			nx := children[cur][ch]
			if nx == -1 {
				nx = newNode(cur)
				children[cur][ch] = nx
				hasKid[cur] = true
			}
			cur = nx
		}
		own[cur] = append(own[cur], uint16(pidx))
	}

	// Breadth-first over the trie resolves, for every state, the failure
	// link and the goto-with-failure transition for every byte. This table
	// is used only by partialLen, over a short window, so its size is never
	// on the hot path.
	n := len(children)
	next := make([][256]int32, n)
	fail := make([]int32, n)

	var queue []int32
	for c := 0; c < 256; c++ {
		v := children[acRoot][c]
		if v == -1 {
			next[acRoot][c] = acRoot
			continue
		}
		next[acRoot][c] = v
		fail[v] = acRoot
		queue = append(queue, v)
	}
	for qi := 0; qi < len(queue); qi++ {
		u := queue[qi]
		for c := 0; c < 256; c++ {
			v := children[u][c]
			if v == -1 {
				next[u][c] = next[fail[u]][c]
				continue
			}
			next[u][c] = v
			fail[v] = next[fail[u]][c]
			queue = append(queue, v)
		}
	}

	return &automaton{
		gate:     gate,
		children: children,
		own:      own,
		next:     next,
		fail:     fail,
		depth:    depth,
		hasKid:   hasKid,
		patLen:   patLen,
		maxLen:   maxLen,
	}
}

// find appends every occurrence of any pattern in buf to dst and returns the
// extended slice.
//
// The outer loop is a plain gate lookup per byte: independent from one
// position to the next, so the compiler and CPU can overlap it across
// positions instead of serializing on it. Only a byte that could start some
// Pattern (rare, for a Pattern's worth of real Secret entropy) pays for a
// trie descent, and that descent is bounded by how far the buffer's actual
// content agrees with some Pattern, not by the buffer's length.
func (a *automaton) find(buf []byte, dst []acMatch) []acMatch {
	n := len(buf)
	for i := 0; i < n; i++ {
		if !a.gate[buf[i]] {
			continue
		}
		state := acRoot
		for j := i; j < n; j++ {
			nx := a.children[state][buf[j]]
			if nx == -1 {
				break
			}
			state = nx
			for _, pidx := range a.own[state] {
				dst = append(dst, acMatch{start: i, length: int(a.patLen[pidx]), pidx: int(pidx)})
			}
		}
	}
	return dst
}

// partialLen returns the length of the longest suffix of tail that is a
// proper prefix of some Pattern, i.e. could still complete with more bytes.
// tail must already be free of any complete match.
func (a *automaton) partialLen(tail []byte) int {
	if len(tail) == 0 || a.maxLen <= 1 {
		return 0
	}
	start := len(tail) - (a.maxLen - 1)
	if start < 0 {
		start = 0
	}
	// A single continuous walk from the root over the window leaves the
	// automaton in the state for the longest suffix of the window that is
	// some Pattern's prefix: that is exactly what the failure function
	// guarantees, whether or not that suffix starts at the window's start.
	// This window is at most maxLen-1 bytes regardless of how large tail
	// is, so this cost never scales with the buffer.
	state := acRoot
	for _, c := range tail[start:] {
		state = a.next[state][c]
	}
	// The state found may be a dead end (its string is not shorter than any
	// Pattern sharing it, i.e. it IS a Pattern with nothing longer). Fall
	// back along the same failure chain to the longest suffix that still has
	// room to grow into a longer Pattern.
	for state != acRoot {
		if a.hasKid[state] {
			return int(a.depth[state])
		}
		state = a.fail[state]
	}
	return 0
}
