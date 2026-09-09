//go:build race

package redact

// raceDetectorEnabled is true when the test binary was built with -race.
// The race detector instruments every memory access, which changes the
// per-byte cost of scan enough that a throughput bar measured under it
// reflects the instrumentation, not the algorithm.
const raceDetectorEnabled = true
