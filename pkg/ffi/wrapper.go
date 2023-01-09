package ffi

// Wrapper functions for heavy-lifting library procedures

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Open opens a new WinDivert handle.
func (l *LibraryReference) Open(filter Filter, layer Layer, priority Priority, flag Flag) (handle uintptr, err error) {
	var filterPtr unsafe.Pointer

	filterPtr, err = filter.unsafePointer()
	if err != nil {
		return
	}

	handle, _, err = l.WinDivertOpen.Call(
		uintptr(filterPtr),
		uintptr(layer),
		uintptr(priority),
		uintptr(flag),
	)

	if handle == uintptr(windows.InvalidHandle) && err == nil {
		err = errors.New("invalid handle")
		return
	}

	return
}

func (l *LibraryReference) Shutdown(handle uintptr, how Shutdown) error {
	result, _, err := l.WinDivertShutdown.Call(handle, uintptr(how))
	if result == 0 {
		return err
	}
	return nil
}

// Close closes the handle
// See https://reqrypt.org/windivert-doc.html#divert_close
func (l *LibraryReference) Close(handle uintptr) error {
	result, _, err := l.WinDivertClose.Call(handle)
	if result == 0 {
		return err
	}
	return nil
}

// Recv diverts a packet from the network stack
// https://reqrypt.org/windivert-doc.html#divert_recv
func (l *LibraryReference) Recv(handle uintptr, receiveBufferSize uint) (*Packet, error) {
	packetBuffer := make([]byte, receiveBufferSize)

	var packetLen uint
	var addr WinDivertAddress
	success, _, err := l.WinDivertRecv.Call(
		handle,
		uintptr(unsafe.Pointer(&packetBuffer[0])),
		uintptr(receiveBufferSize),
		uintptr(unsafe.Pointer(&packetLen)),
		uintptr(unsafe.Pointer(&addr)),
	)

	if success == 0 {
		return nil, err
	}

	packet := &Packet{
		Content: packetBuffer[:packetLen],
		Address: &addr,
		Length:  packetLen,
	}
	return packet, nil
}

// Send injects the packet on the network stack
// https://reqrypt.org/windivert-doc.html#divert_send
func (l *LibraryReference) Send(handle uintptr, packet *Packet) (uint, error) {
	var sendLen uint

	success, _, err := l.WinDivertSend.Call(
		handle,
		uintptr(unsafe.Pointer(&(packet.Content[0]))),
		uintptr(packet.Length),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(packet.Address)))

	if success == 0 {
		return 0, err
	}

	return sendLen, nil
}

func (l *LibraryReference) SetParam(handle uintptr, param Param, value uint64) (err error) {
	success, _, err := l.WinDivertSetParam.Call(
		handle,
		uintptr(param),
		uintptr(value),
	)

	if success == 0 {
		return err
	}

	return nil
}

func (l *LibraryReference) GetParam(handle uintptr, param Param) (value uint64, err error) {
	success, _, err := l.WinDivertGetParam.Call(
		handle,
		uintptr(param),
		uintptr(unsafe.Pointer(&value)),
	)

	if success == 0 {
		return 0, err
	}

	return value, nil
}
