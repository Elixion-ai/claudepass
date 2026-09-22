package e2e

// This file guards a regression found during review of CLA-90 (og:url and
// rel=canonical per page): declaring a canonical URL is not enough — it has
// to be the URL that actually serves the page with no intervening redirect.
// deploy/Caddyfile's `file_server` directive enables Caddy's default
// "canonical URIs" behaviour, which 308-redirects a bare directory path
// (e.g. /docs) to its trailing-slash form (/docs/) before serving 200. Six
// of the nine served pages are directory indexes (site/<name>/index.html),
// so their declared canonical had to carry the trailing slash too, or it
// would point one redirect hop away from the page it names. Root, 404.html
// and 500.html are literal files, never redirected, and keep their bare
// path.
//
// The test below runs deploy/Caddyfile's actual routing directives — not a
// hand-copied approximation of them — against this worktree's site/, the
// same way the review that found this bug verified it (`caddy run` plus a
// curl per path), so a future change to the Caddyfile's routing is checked
// against the pages' declared canonical URLs automatically instead of
// relying on someone noticing a live redirect.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// sitePages lists every page deploy/Caddyfile serves from site/, paired
// with the URL path its declared canonical must resolve to with a direct
// 200 — no redirect.
var sitePages = []struct {
	file string // path under site/
	path string // the path its own og:url/canonical must declare
}{
	{"index.html", "/"},
	{"404.html", "/404.html"},
	{"500.html", "/500.html"},
	{"docs/index.html", "/docs/"},
	{"install/index.html", "/install/"},
	{"security/index.html", "/security/"},
	{"privacy/index.html", "/privacy/"},
	{"terms/index.html", "/terms/"},
	{"brand/index.html", "/brand/"},
}

var metaURLRe = regexp.MustCompile(`property="og:url" content="([^"]+)"|rel="canonical" href="([^"]+)"`)

// declaredCanonicalURLs returns the og:url and rel=canonical values a page
// declares for itself, in source order.
func declaredCanonicalURLs(t *testing.T, siteFile string) []string {
	t.Helper()
	src := readRepoFile(t, filepath.Join("site", siteFile))
	var got []string
	for _, m := range metaURLRe.FindAllStringSubmatch(src, -1) {
		if m[1] != "" {
			got = append(got, m[1])
		}
		if m[2] != "" {
			got = append(got, m[2])
		}
	}
	return got
}

// TestSitePagesDeclareUniqueCanonicalURLs is CLA-90's own acceptance
// criterion: no two distinct pages may share an og:url, or Facebook's
// Sharing Debugger (which caches an unfurl by og:url) capitons a shared
// link for one page using whatever it crawled for another.
func TestSitePagesDeclareUniqueCanonicalURLs(t *testing.T) {
	seen := map[string]string{} // url -> first file that declared it
	for _, p := range sitePages {
		for _, u := range declaredCanonicalURLs(t, p.file) {
			if owner, ok := seen[u]; ok && owner != p.file {
				t.Errorf("og:url/canonical %q is declared by both %s and %s", u, owner, p.file)
			} else {
				seen[u] = p.file
			}
		}
	}
}

// TestSitePagesCanonicalURLServes200WithNoRedirect is the regression test:
// every declared og:url/canonical, requested against deploy/Caddyfile's
// real routing directives, must serve 200 directly. A bare directory path
// that 308-redirects to its trailing-slash form fails this check.
func TestSitePagesCanonicalURLServes200WithNoRedirect(t *testing.T) {
	if _, err := exec.LookPath("caddy"); err != nil {
		t.Skip("caddy not installed on this machine; skipping live routing check")
	}

	root := repoRoot(t)
	base := startTestSiteServer(t, root)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, p := range sitePages {
		p := p
		t.Run(p.path, func(t *testing.T) {
			for _, u := range declaredCanonicalURLs(t, p.file) {
				if !strings.HasSuffix(u, p.path) {
					t.Fatalf("%s declares canonical %q, want it to end in %q (its own served path)", p.file, u, p.path)
				}
			}
			resp, err := client.Get(base + p.path)
			if err != nil {
				t.Fatalf("GET %s%s: %v", base, p.path, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				loc := resp.Header.Get("Location")
				t.Fatalf("GET %s%s = %d (Location: %q), want 200 with no redirect — "+
					"the declared canonical URL is one hop away from the page it names",
					base, p.path, resp.StatusCode, loc)
			}
		})
	}
}

// startTestSiteServer runs deploy/Caddyfile's real claudepass.com routing
// block — `root`, `handle /dl/*`, `handle {}` and their file_server
// directives, extracted from the file verbatim rather than reimplemented —
// against this worktree's site/ directory, listening on a free local port.
// It returns the server's base URL and registers cleanup to stop it.
func startTestSiteServer(t *testing.T, root string) string {
	t.Helper()

	caddyfile := readRepoFile(t, filepath.Join("deploy", "Caddyfile"))

	snippet, ok := extractBraceBlock(caddyfile, "(security_headers)")
	if !ok {
		t.Fatal("deploy/Caddyfile: could not find the (security_headers) snippet definition")
	}
	site, ok := extractBraceBlock(caddyfile, "\nclaudepass.com ")
	if !ok {
		t.Fatal("deploy/Caddyfile: could not find the claudepass.com server block")
	}

	// Drop the `log { output file /var/log/caddy/access.log }` directive:
	// irrelevant to routing, and that path isn't writable as a test user.
	if logBlock, ok := extractBraceBlock(site, "log "); ok {
		site = strings.Replace(site, "log {"+logBlock+"}", "", 1)
	}

	// Point root at this worktree's site/ instead of the production path.
	sitePath := filepath.Join(root, "site")
	site = strings.Replace(site, "root * /srv/claudepass/site", "root * "+sitePath, 1)
	if !strings.Contains(site, "root * "+sitePath) {
		t.Fatal("deploy/Caddyfile: could not rewrite the `root *` directive to this worktree's site/")
	}

	port := freeTCPPort(t)
	testCaddyfile := fmt.Sprintf("(security_headers) {%s}\n\nhttp://127.0.0.1:%d {%s}\n", snippet, port, site)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cfgPath, []byte(testCaddyfile), 0o600); err != nil {
		t.Fatalf("write test Caddyfile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "caddy", "run", "--config", cfgPath, "--adapter", "caddyfile")
	cmd.Dir = dir
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatalf("caddy stderr pipe: %v", err)
	}
	var log strings.Builder
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			log.WriteString(sc.Text())
			log.WriteByte('\n')
		}
	}()
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/")
		if err == nil {
			_ = resp.Body.Close()
			return base
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("caddy never came up on %s within 10s; stderr:\n%s", base, log.String())
	return ""
}

// freeTCPPort asks the OS for a currently-unused TCP port on 127.0.0.1.
// Another process could in principle grab it before caddy binds — an
// inherent race in any "find a free port" helper — but the test's startup
// poll surfaces that as a clear timeout rather than a silent false pass.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// extractBraceBlock returns the text between the first balanced `{`...`}`
// pair found after marker, not including the braces themselves.
func extractBraceBlock(src, marker string) (string, bool) {
	i := strings.Index(src, marker)
	if i < 0 {
		return "", false
	}
	rest := src[i+len(marker):]
	ob := strings.Index(rest, "{")
	if ob < 0 {
		return "", false
	}
	depth := 0
	for j := ob; j < len(rest); j++ {
		switch rest[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[ob+1 : j], true
			}
		}
	}
	return "", false
}
