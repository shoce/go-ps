//go:build darwin
// +build darwin

package ps

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"unsafe"
)

type DarwinProcess struct {
	pid  int
	ppid int

	binary  string
	cmdline string

	utime     uint64
	stime     uint64
	cutime    int64
	cstime    int64
	starttime uint64

	vsize uint64
	rss   uint32

	cgroup string
}

func (p *DarwinProcess) Pid() int {
	return p.pid
}

func (p *DarwinProcess) PPid() int {
	return p.ppid
}

func (p *DarwinProcess) Executable() string {
	return p.binary
}

func (p *DarwinProcess) Cmdline() string {
	return p.cmdline
}

func (p *DarwinProcess) Utime() uint64 {
	return p.utime
}

func (p *DarwinProcess) Stime() uint64 {
	return p.stime
}

func (p *DarwinProcess) Cutime() int64 {
	return p.cutime
}

func (p *DarwinProcess) Cstime() int64 {
	return p.cstime
}

func (p *DarwinProcess) Starttime() uint64 {
	return p.starttime
}

func (p *DarwinProcess) Vsize() uint64 {
	return p.vsize
}

func (p *DarwinProcess) Rss() uint32 {
	return p.rss
}

func (p *DarwinProcess) Cgroup() string {
	return p.cgroup
}

func findProcess(pid int) (Process, error) {
	ps, err := processes()
	if err != nil {
		return nil, err
	}

	for _, p := range ps {
		if p.Pid() == pid {
			return p, nil
		}
	}

	return nil, nil
}

func processes() ([]Process, error) {
	buf, err := darwinSyscall()
	if err != nil {
		return nil, err
	}

	procs := make([]*kinfoProc, 0, 50)
	k := 0
	for i := _KINFO_STRUCT_SIZE; i < buf.Len(); i += _KINFO_STRUCT_SIZE {
		proc := &kinfoProc{}
		err = binary.Read(bytes.NewBuffer(buf.Bytes()[k:i]), binary.LittleEndian, proc)
		if err != nil {
			return nil, err
		}

		k = i
		procs = append(procs, proc)
	}

	darwinProcs := make([]Process, len(procs))
	for i, p := range procs {
		darwinProcs[i] = &DarwinProcess{
			pid:       int(p.Pid),
			ppid:      int(p.PPid),
			binary:    darwinCstring(p.Comm),
			cmdline:   darwinCstring(p.Comm),
			utime:     uint64(p.Uticks),
			stime:     uint64(p.Sticks),
			starttime: uint64(p.StartSec),
		}
	}

	return darwinProcs, nil
}

func darwinCstring(s [16]byte) string {
	i := 0
	for _, b := range s {
		if b != 0 {
			i++
		} else {
			break
		}
	}

	return string(s[:i])
}

func darwinSyscall() (*bytes.Buffer, error) {
	mib := [4]int32{_CTRL_KERN, _KERN_PROC, _KERN_PROC_ALL, 0}
	size := uintptr(0)

	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		0)

	if errno != 0 {
		return nil, errno
	}

	bs := make([]byte, size)
	_, _, errno = syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&bs[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		0)

	if errno != 0 {
		return nil, errno
	}

	return bytes.NewBuffer(bs[0:size]), nil
}

const (
	_CTRL_KERN         = 1
	_KERN_PROC         = 14
	_KERN_PROC_ALL     = 0
	_KINFO_STRUCT_SIZE = 648
)

type kinfoProc struct {
	_         [8]byte
	StartSec  int64
	StartUsec int32
	_         [20]byte
	Pid       int32
	_         [160]byte
	Uticks    uint32
	Sticks    uint32
	_         [31]byte
	Comm      [16]byte
	_         [301]byte
	PPid      int32
	_         [84]byte
}
