package ffi

// wraps the filter string

import "C"
import (
	"golang.org/x/sys/windows"
	"strings"
	"unsafe"
)

type Filter string

func (f *Filter) unsafePointer() (ret unsafe.Pointer, err error) {
	// note: windows.BytePtrFromString does not accept strings with trailing zeroes
	bytePtr, err := windows.BytePtrFromString(f.String())
	if err != nil {
		return
	}

	return unsafe.Pointer(bytePtr), nil
}

// String returns the string representation of the filter, with trailing zeroes trimmed
func (f *Filter) String() string {
	return strings.TrimRight(string(*f), "\x00")
}
