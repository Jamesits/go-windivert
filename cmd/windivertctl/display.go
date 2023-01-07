package main

import (
	"github.com/jamesits/go-windivert/ffi"
	"strings"
)

func flagsToString(flags ffi.Flag) string {
	if flags == 0 {
		return "0"
	}

	sb := strings.Builder{}
	if flags&ffi.Sniff > 0 {
		sb.WriteString("|SNIFF")
	}

	if flags&ffi.Drop > 0 {
		sb.WriteString("|DROP")
	}

	if flags&ffi.ReceiveOnly > 0 {
		sb.WriteString("|RECV_ONLY")
	}

	if flags&ffi.SendOnly > 0 {
		sb.WriteString("|SEND_ONLY")
	}

	if flags&ffi.NoInstall > 0 {
		sb.WriteString("|NO_INSTALL")
	}

	return sb.String()[1:]
}
