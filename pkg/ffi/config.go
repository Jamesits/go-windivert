package ffi

import "encoding/binary"

var hostByteOrder = binary.LittleEndian
var networkByteOrder = binary.BigEndian

const filterBufferLength = 65536

// where to look for WinDivert DLL and SYS files for unit testing
const defaultDLLLookupPathForTesting = "..\\WinDivert.dll"

const WinDivertPriorityHighest = Priority(30000)
const WinDivertPriorityDefault = Priority(0)
const WinDivertPriorityLowest = Priority(-WinDivertPriorityHighest)
const WinDivertParamQueueLengthDefault = 4096
const WinDivertParamQueueLengthMin = 32
const WinDivertParamQueueLengthMax = 16384
const WinDivertParamQueueTimeDefault = 2000    /* 2s */
const WinDivertParamQueueTimeMin = 100         /* 100ms */
const WinDivertParamQueueTimeMax = 16000       /* 16s */
const WinDivertParamQueueSizeDefault = 4194304 /* 4MB */
const WinDivertParamQueueSizeMin = 65535       /* 64KB */
const WinDivertParamQueueSizeMax = 33554432    /* 32MB */
const WinDivertBatchMax = 0xFF                 /* 255 */
const WinDivertMTUMax = 40 + 0xFFFF
