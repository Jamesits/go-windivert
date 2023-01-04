package ffi

import "C"
import "unsafe"

// uintptrToString converts a raw "const char *" to a Go string.
// https://groups.google.com/g/golang-nuts/c/H77hcVt3AAI
func uintptrToString(ptr uintptr) string {
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}
