//go:build race

package e2e

// raceEnabled relaxes timing bounds: the race detector slows CPU-bound code
// several-fold, which says nothing about the real binary.
const raceEnabled = true
