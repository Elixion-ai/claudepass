//go:build unix

package redact

import "syscall"

// processCPUSeconds returns the calling process's total CPU time consumed so
// far (user + system), in seconds. Used only by throughput checks: unlike
// wall-clock time, it does not count time this process spent runnable but
// not actually scheduled on a core, which is what makes it possible to check
// a throughput bar reliably on a host where other processes are contending
// for the same cores (see TestThroughputMeetsBar).
func processCPUSeconds() (float64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	toSeconds := func(tv syscall.Timeval) float64 {
		return float64(tv.Sec) + float64(tv.Usec)/1e6
	}
	return toSeconds(ru.Utime) + toSeconds(ru.Stime), true
}
