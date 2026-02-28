//go:build linux || solaris

package ps

import (
	"fmt"
	"io"
	"os"
	"strconv"
)

// UnixProcess is an implementation of Process that contains Unix-specific
// fields and information.
type UnixProcess struct {
	pid int

	binary  string
	cmdline string

	state  rune
	ppid   int
	pgrp   int
	sid    int
	tty_nr int
	tpgid  int

	utime  uint64
	stime  uint64
	cutime int64
	cstime int64

	starttime uint64

	vsize uint64
	rss   uint32

	cgroup string
}

func (p *UnixProcess) Pid() int {
	return p.pid
}

func (p *UnixProcess) PPid() int {
	return p.ppid
}

func (p *UnixProcess) Executable() string {
	return p.binary
}

func (p *UnixProcess) Cmdline() string {
	return p.cmdline
}

func (p *UnixProcess) Vsize() uint64 {
	return p.vsize
}

func (p *UnixProcess) Rss() uint32 {
	return p.rss
}

func (p *UnixProcess) Cgroup() string {
	return p.cgroup
}

func findProcess(pid int) (Process, error) {
	dir := fmt.Sprintf("/proc/%d", pid)
	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return newUnixProcess(pid)
}

func processes() ([]Process, error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer d.Close()

	results := make([]Process, 0, 50)
	for {
		names, err := d.Readdirnames(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		for _, name := range names {
			// We only care if the name starts with a numeric
			if name[0] < '0' || name[0] > '9' {
				continue
			}

			// From this point forward, any errors we just ignore, because
			// it might simply be that the process doesn't exist anymore.
			pid, err := strconv.ParseInt(name, 10, 0)
			if err != nil {
				continue
			}

			p, err := newUnixProcess(int(pid))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR %v \n", err)
				continue
			}

			results = append(results, p)
		}
	}

	return results, nil
}

func newUnixProcess(pid int) (*UnixProcess, error) {
	p := &UnixProcess{pid: pid}
	return p, p.Refresh()
}
