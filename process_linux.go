//go:build linux

package ps

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"
)

// Refresh reloads all the data associated with this process.
func (p *UnixProcess) Refresh() error {
	statPath := fmt.Sprintf("/proc/%d/stat", p.pid)
	dataBytes, err := ioutil.ReadFile(statPath)
	if err != nil {
		return err
	}

	// First, parse out the image name
	data := string(dataBytes)
	commStart := strings.IndexByte(data, '(')
	commEnd := strings.LastIndexByte(data, ')')
	p.comm = data[commStart+1 : commEnd]

	// Move past the image name and start parsing the rest
	data = data[commEnd+2:]
	var skip int64
	// https://pkg.go.dev/fmt#Sscanf
	_, err = fmt.Sscanf(data,
		"%c %d %d %d "+
			"%d %d "+
			"%d %d %d %d %d "+
			"%d %d %d %d "+
			"%d %d %d %d "+
			"%d "+
			"%d %d",
		&p.state, &p.ppid, &p.pgrp, &p.sid,
		&p.tty_nr, &p.tpgid,
		&skip, &skip, &skip, &skip, &skip,
		&p.utime, &p.stime, &p.cutime, &p.cstime,
		&skip, &skip, &skip, &skip,
		&p.starttime,
		&p.vsize, &p.rss,
	)
	if err != nil {
		return err
	}

	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", p.pid)
	cmdlineBytes, err := ioutil.ReadFile(cmdlinePath)
	if err != nil {
		return err
	}
	for _, a := range bytes.Split(cmdlineBytes, []byte{0}) {
		p.cmdline = append(p.cmdline, string(a))
	}

	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", p.pid)
	cgroupBytes, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		return err
	}
	p.cgroup = string(cgroupBytes)

	return nil
}
