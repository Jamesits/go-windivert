package ffi

import "strings"

// Contains constants defined in the library header.
//go:generate stringer -type=Layer,Event,Param,Shutdown,Direction,ChecksumFlag -output=enums_string.go -trimprefix=WinDivert -linecomment

// WINDIVERT_LAYER
// https://reqrypt.org/windivert-doc.html#divert_layers
type Layer int

const (
	// Network packets to/from the local machine.
	Network Layer = iota
	// Network packets passing through the local machine.
	NetworkForward
	// Network flow established/deleted events.
	Flow
	// Socket operation events.
	Socket
	// Reflect WinDivert handle events.
	Reflect
)

// WINDIVERT_EVENT
// https://reqrypt.org/windivert-doc.html#divert_events
type Event int

const (
	NetworkPacket Event = iota
	FlowEstablished
	FlowDeleted
	SocketBind
	SocketConnect
	SocketListen
	SocketAccept
	SocketClose
	ReflectOpen
	ReflectClose
)

type Flag uint8

const (
	None        Flag = 0x00
	Sniff       Flag = 0x01
	Drop        Flag = 0x02
	ReceiveOnly Flag = 0x04
	SendOnly    Flag = 0x08
	NoInstall   Flag = 0x10
	Fragments   Flag = 0x20
)

func (flags Flag) String() string {
	if flags == 0 {
		return "NONE"
	}

	sb := strings.Builder{}
	if flags&Sniff > 0 {
		sb.WriteString("|SNIFF")
	}

	if flags&Drop > 0 {
		sb.WriteString("|DROP")
	}

	if flags&ReceiveOnly > 0 {
		sb.WriteString("|RECV_ONLY")
	}

	if flags&SendOnly > 0 {
		sb.WriteString("|SEND_ONLY")
	}

	if flags&NoInstall > 0 {
		sb.WriteString("|NO_INSTALL")
	}

	if flags&Fragments > 0 {
		sb.WriteString("|FRAGMENTS")
	}

	return sb.String()[1:]
}

// WINDIVERT_PARAM
type Param int

const (
	QueueLength  Param = 0
	QueueTime    Param = 1
	QueueSize    Param = 2
	VersionMajor Param = 3
	VersionMinor Param = 4
)

// WINDIVERT_SHUTDOWN
type Shutdown int64

const (
	Recv Shutdown = 0x1
	Send Shutdown = 0x2
	Both Shutdown = 0x3
)

type Direction int

const (
	Outbound Direction = 1
	Inbound  Direction = 0
)

// Priority of the handles
// Multiple handles should not have the same priority.
type Priority int16

type ChecksumFlag int64

const (
	All      ChecksumFlag = 0x00
	NoIP     ChecksumFlag = 0x01
	NoICMP   ChecksumFlag = 0x02
	NoICMPv6 ChecksumFlag = 0x04
	NoTCP    ChecksumFlag = 0x08
	NoUDP    ChecksumFlag = 0x10
)
