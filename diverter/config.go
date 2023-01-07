package diverter

import (
	"github.com/jamesits/go-windivert/ffi"
)

const DefaultDLLPath = "WinDivert.dll"
const DefaultFilter = ffi.Filter("true")

type Config struct {
	DLLPath string

	Filter   ffi.Filter
	Layer    ffi.Layer
	Priority ffi.Priority
	Flag     ffi.Flag

	SendChanSize      uint
	RecvChanSize      uint
	ReceiveBufferSize uint
}

func (c *Config) Defaults() {
	c.Layer = ffi.Network
	c.Priority = ffi.WinDivertPriorityDefault
	c.Flag = ffi.Sniff | ffi.ReceiveOnly | ffi.Fragments
}

func (c *Config) fixMissingValue() {
	if len(c.DLLPath) == 0 {
		c.DLLPath = DefaultDLLPath
	}

	if len(c.Filter) == 0 {
		c.Filter = DefaultFilter
	}

	if c.ReceiveBufferSize <= 0 {
		c.ReceiveBufferSize = ffi.WinDivertMTUMax // for loopback traffic, packet size might > 16384
	}
}

func NewDefaultDiverterConfig(dllPath string, filter string) (ret *Config) {
	ret = &Config{}
	ret.Defaults()
	ret.DLLPath = dllPath
	ret.Filter = ffi.Filter(filter)
	return
}
