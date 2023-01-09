package ffi

import (
	"errors"
	"unsafe"
)

// (Re)calculates the checksum for any IPv4/ICMP/ICMPv6/TCP/UDP checksum present in the given packet. Individual checksum calculations may be disabled via the appropriate flag. Typically this function should be invoked on a modified packet before it is injected with WinDivertSend().
// By default this function will calculate each checksum from scratch, even if the existing checksum is correct. This may be inefficient for some applications. For better performance, incremental checksum calculations should be used instead (not provided by this API).
// If pAddr is non-NULL, this function sets the corresponding *Checksum flag (see WINDIVERT_ADDRESS). Normally, pAddr should point to the address passed to WinDivertSend() for packet injection.
// https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
func (l *LibraryReference) CalcChecksums(packet *Packet, flags ChecksumFlag) {
	_, _, _ = l.WinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Content[0])),
		uintptr(packet.Length),
		uintptr(unsafe.Pointer(&packet.Address)),
		uintptr(flags),
	)
}

// Decrements the ip.TTL or ipv6.HopHimit field by 1, and returns TRUE only if the result is non-zero. This is useful for applications where packet loops may be a problem.
// For IPv4, this function will preserve the validity of the IPv4 checksum. That is, if the packet had a valid checksum before the operation, the resulting checksum will also be valid after the operation. This function updates the checksum field incrementally.
// https://reqrypt.org/windivert-doc.html#divert_helper_dec_ttl
func (l *LibraryReference) DecrementTTL(packet *Packet) (bool, error) {
	success, _, err := l.WinDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Content[0])),
		uintptr(packet.Length),
	)

	if success == 0 {
		return false, err
	}

	return true, nil
}

// https://reqrypt.org/windivert-doc.html#divert_helper_compile_filter
func (l *LibraryReference) CompileFilter(filter Filter, layer Layer) (object Filter, errorPosition uint, err error) {
	filterBytePtr, err := filter.unsafePointer()
	if err != nil {
		return "", 0, err
	}

	objBuffer := make([]byte, filterBufferLength)
	var errorStringPtr uintptr

	success, _, _ := l.WinDivertHelperCompileFilter.Call(
		uintptr(filterBytePtr),
		uintptr(layer),
		uintptr(unsafe.Pointer(&objBuffer[0])),
		uintptr(filterBufferLength),
		uintptr(unsafe.Pointer(&errorStringPtr)),
		uintptr(unsafe.Pointer(&errorPosition)),
	)

	if success == 0 {
		return "", errorPosition, errors.New(uintptrToString(errorStringPtr))
	}

	return Filter(objBuffer[:]), 0, nil
}

// Evaluates the given packet against the given packet filter string. This function returns TRUE if the packet matches, and returns FALSE otherwise.
// This function also returns FALSE if an error occurs, in which case GetLastError() can be used to get the reason for the error. Otherwise, if no error occurred, GetLastError() will return 0.
// Note that this function is relatively slow since the packet filter string will be (re)compiled for each call. This overhead can be minimized by pre-compiling the filter string into the object representation using the WinDivertHelperCompileFilter() function.
// https://reqrypt.org/windivert-doc.html#divert_helper_eval_filter
func (l *LibraryReference) EvalFilter(packet *Packet, filter Filter) (bool, error) {
	filterBytePtr, err := filter.unsafePointer()
	if err != nil {
		return false, err
	}

	success, _, err := l.WinDivertHelperEvalFilter.Call(
		uintptr(filterBytePtr),
		uintptr(0),
		uintptr(unsafe.Pointer(&packet.Content[0])),
		uintptr(packet.Length),
		uintptr(unsafe.Pointer(&packet.Address)))

	if success == 0 {
		return false, err
	}

	return true, nil
}

// https://reqrypt.org/windivert-doc.html#divert_helper_format_filter
func (l *LibraryReference) FormatFilter(filter Filter, layer Layer) (object Filter, err error) {
	filterBytePtr, err := filter.unsafePointer()
	if err != nil {
		return "", err
	}

	objBuffer := make([]byte, filterBufferLength)
	var errorStringPtr uintptr

	success, _, _ := l.WinDivertHelperFormatFilter.Call(
		uintptr(filterBytePtr),
		uintptr(layer),
		uintptr(unsafe.Pointer(&objBuffer[0])),
		uintptr(filterBufferLength),
	)

	if success == 0 {
		return "", errors.New(uintptrToString(errorStringPtr))
	}

	return Filter(objBuffer[:]), nil
}
