package ffi

import (
	"reflect"
	"sync"
	"syscall"
)

// LibraryReference contains functions to a memory copy of WinDivert.dll.
type LibraryReference struct {
	dllHandle *syscall.LazyDLL
	initOnce  sync.Once

	// WinDivertOpen opens a WinDivert handle.
	WinDivertOpen *syscall.LazyProc `func:"WinDivertOpen"`

	// WinDivertRecv receives (reads) a packet from a WinDivert handle.
	WinDivertRecv *syscall.LazyProc `func:"WinDivertRecv"`

	// WinDivertRecvEx receives (reads) a packet from a WinDivert handle.
	WinDivertRecvEx *syscall.LazyProc `func:"WinDivertRecvEx"`

	// WinDivertSend sends (writes/injects) a packet to a WinDivert handle.
	WinDivertSend *syscall.LazyProc `func:"WinDivertSend"`

	// WinDivertSendEx sends (writes/injects) a packet to a WinDivert handle.
	WinDivertSendEx *syscall.LazyProc `func:"WinDivertSendEx"`

	// WinDivertShutdown shuts down a WinDivert handle.
	WinDivertShutdown *syscall.LazyProc `func:"WinDivertShutdown"`

	// WinDivertClose closes a WinDivert handle.
	WinDivertClose *syscall.LazyProc `func:"WinDivertClose"`

	// WinDivertSetParam sets a WinDivert handle parameter.
	WinDivertSetParam *syscall.LazyProc `func:"WinDivertSetParam"`

	// WinDivertGetParam gets a WinDivert handle parameter.
	WinDivertGetParam *syscall.LazyProc `func:"WinDivertGetParam"`

	WinDivertHelperParsePacket       *syscall.LazyProc `func:"WinDivertHelperParsePacket"`
	WinDivertHelperHashPacket        *syscall.LazyProc `func:"WinDivertHelperHashPacket"`
	WinDivertHelperParseIPv4Address  *syscall.LazyProc `func:"WinDivertHelperParseIPv4Address"`
	WinDivertHelperParseIPv6Address  *syscall.LazyProc `func:"WinDivertHelperParseIPv6Address"`
	WinDivertHelperFormatIPv4Address *syscall.LazyProc `func:"WinDivertHelperFormatIPv4Address"`
	WinDivertHelperFormatIPv6Address *syscall.LazyProc `func:"WinDivertHelperFormatIPv6Address"`
	WinDivertHelperCalcChecksums     *syscall.LazyProc `func:"WinDivertHelperCalcChecksums"`
	WinDivertHelperDecrementTTL      *syscall.LazyProc `func:"WinDivertHelperDecrementTTL"`
	WinDivertHelperCompileFilter     *syscall.LazyProc `func:"WinDivertHelperCompileFilter"`
	WinDivertHelperEvalFilter        *syscall.LazyProc `func:"WinDivertHelperEvalFilter"`
	WinDivertHelperFormatFilter      *syscall.LazyProc `func:"WinDivertHelperFormatFilter"`
	WinDivertHelperNtohs             *syscall.LazyProc `func:"WinDivertHelperNtohs"`
	WinDivertHelperNtohl             *syscall.LazyProc `func:"WinDivertHelperNtohl"`
	WinDivertHelperNtohll            *syscall.LazyProc `func:"WinDivertHelperNtohll"`
	WinDivertHelperNtohIPv6Address   *syscall.LazyProc `func:"WinDivertHelperNtohIPv6Address"`
	WinDivertHelperHtons             *syscall.LazyProc `func:"WinDivertHelperHtons"`
	WinDivertHelperHtonl             *syscall.LazyProc `func:"WinDivertHelperHtonl"`
	WinDivertHelperHtonll            *syscall.LazyProc `func:"WinDivertHelperHtonll"`
	WinDivertHelperHtonIPv6Address   *syscall.LazyProc `func:"WinDivertHelperHtonIPv6Address"`
}

// NewDLLReference loads the WinDivert DLL into the program and makes all function pointers available.
func NewDLLReference(dllPath string) (ret *LibraryReference, err error) {
	ret = &LibraryReference{
		dllHandle: syscall.NewLazyDLL(dllPath),
	}

	ret.initOnce.Do(func() {
		fillFunctions(ret)
	})

	err = ret.dllHandle.Load()
	return
}

// getStructTag returns the value of a named tag of a struct member
func getStructTag(f reflect.StructField, tagName string) string {
	return f.Tag.Get(tagName)
}

// fillFunctions searches for functions in the DLL and updates the function pointers.
func fillFunctions(d *LibraryReference) {
	// https://stackoverflow.com/a/46354875
	valueReference := reflect.ValueOf(d).Elem()
	typeReference := valueReference.Type()

	fieldCount := typeReference.NumField()
	for i := 0; i < fieldCount; i++ {
		typeField := typeReference.Field(i)
		tag := getStructTag(typeField, "func")

		valueField := valueReference.Field(i)
		if !valueField.IsValid() || !valueField.CanSet() || tag == "" {
			continue
		}

		// https://stackoverflow.com/a/53110731
		valueField.Set(reflect.ValueOf(d.dllHandle.NewProc(tag)).Convert(valueField.Type()))
	}
}
