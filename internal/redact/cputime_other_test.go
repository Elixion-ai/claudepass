//go:build !unix

package redact

// processCPUSeconds reports that process CPU time is unavailable on this
// platform (Windows builds are untested per ADR-0007; the throughput bar
// this feeds is skipped rather than checked against wall-clock time, which
// would be meaningless for the same reason it is avoided on unix).
func processCPUSeconds() (float64, bool) { return 0, false }
