package ffi

import "encoding/binary"

var hostByteOrder = binary.LittleEndian
var networkByteOrder = binary.BigEndian

const filterBufferLength = 65536

// where to look for WinDivert DLL and SYS files for unit testing
const defaultDLLLookupPathForTesting = "..\\WinDivert.dll"
