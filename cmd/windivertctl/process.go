package main

import (
	"errors"
	"github.com/shirou/gopsutil/v3/process"
)

func GetProcessImageFileName(pid uint32) (filename string, err error) {
	ps, err := process.Processes()
	if err != nil {
		return
	}

	for _, p := range ps {
		if p.Pid == int32(pid) {
			return p.Exe()
		}
	}

	return "", errors.New("process not found")
}

func KillProcess(pid uint32) (err error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return
	}

	return p.Kill()
}
