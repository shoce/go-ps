// ps provides an API for finding and listing processes in a platform-agnostic
// way.
//
// NOTE: If you're reading these docs online via GoDocs or some other system,
// you might only see the Unix docs. This project makes heavy use of
// platform-specific implementations. We recommend reading the source if you
// are interested.
package ps

// Process is the generic interface that is implemented on every platform
// and provides common operations for processes.
type Process interface {
	Pid() int

	PPid() int
	Pgrp() int
	Sid() int

	Executable() string
	Cmdline() string

	Utime() uint64
	Stime() uint64
	Starttime() uint64

	Vsize() uint64
	Rss() uint32

	Cgroup() string
}

// Processes returns all processes.
//
// This of course will be a point-in-time snapshot of when this method was
// called. Some operating systems don't provide snapshot capability of the
// process table, in which case the process table returned might contain
// ephemeral entities that happened to be running when this was called.
func Processes() ([]Process, error) {
	return processes()
}

// FindProcess looks up a single process by pid.
//
// Process will be nil and error will be nil if a matching process is
// not found.
func FindProcess(pid int) (Process, error) {
	return findProcess(pid)
}
