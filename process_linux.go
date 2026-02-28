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
	binStart := strings.IndexRune(data, '(') + 1
	binEnd := strings.IndexRune(data[binStart:], ')')
	p.binary = data[binStart : binStart+binEnd]

	// Move past the image name and start parsing the rest
	data = data[binStart+binEnd+2:]
	// https://pkg.go.dev/fmt#Sscanf
	_, err = fmt.Sscanf(data,
		"%c %d %d %d "+
			"%d %d %d %d %d %d "+
			"%d %d %d %d %d %d %d %d %d %d "+
			"%d %d",
		&p.state, &p.ppid, &p.pgrp, &p.sid,
		&_, &_, &_, &_, &_, &_,
		&_, &_, &_, &_, &_, &_, &_, &_, &_, &_,
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
	cmdlineBytes = bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte(" "))
	cmdlineBytes = bytes.ReplaceAll(cmdlineBytes, []byte("\n"), []byte(" "))
	p.cmdline = string(cmdlineBytes)

	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", p.pid)
	cgroupBytes, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		return err
	}
	p.cgroup = string(cgroupBytes)

	return nil
}
