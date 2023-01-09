package diverter

import (
	ffi2 "github.com/jamesits/go-windivert/pkg/ffi"
)

const DefaultDLLPath = "WinDivert.dll"
const DefaultFilter = ffi2.Filter("true")

type Config struct {
	DLLPath string

	Filter   ffi2.Filter
	Layer    ffi2.Layer
	Priority ffi2.Priority
	Flag     ffi2.Flag

	SendChanSize      uint
	RecvChanSize      uint
	ReceiveBufferSize uint
}

func (c *Config) Defaults() {
	c.Layer = ffi2.Network
	c.Priority = ffi2.WinDivertPriorityDefault
	c.Flag = ffi2.Sniff | ffi2.ReceiveOnly | ffi2.Fragments
}

func (c *Config) fixMissingValue() {
	if len(c.DLLPath) == 0 {
		c.DLLPath = DefaultDLLPath
	}

	if len(c.Filter) == 0 {
		c.Filter = DefaultFilter
	}

	if c.ReceiveBufferSize <= 0 {
		c.ReceiveBufferSize = ffi2.WinDivertMTUMax // for loopback traffic, packet size might > 16384
	}
}

func NewDefaultDiverterConfig(dllPath string, filter string) (ret *Config) {
	ret = &Config{}
	ret.Defaults()
	ret.DLLPath = dllPath
	ret.Filter = ffi2.Filter(filter)
	return
}
