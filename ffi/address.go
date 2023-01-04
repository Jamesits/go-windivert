package ffi

// contains WINDIVERT_ADDRESS and related data types

import "net/netip"

type addressInternalUnion [64]byte

// WINDIVERT_ADDRESS
// https://reqrypt.org/windivert-doc.html#divert_address
type WinDivertAddress struct {
	// A timestamp indicating when event occurred.
	Timestamp int64
	flags     uint64
	data      addressInternalUnion
}

// The handle's layer (WINDIVERT_LAYER_*).
func (a *WinDivertAddress) Layer() Layer {
	return Layer((a.flags >> 8) & 0xff)
}

// The captured event (WINDIVERT_EVENT_*).
func (a *WinDivertAddress) Event() Event {
	return Event(a.flags & 0xff)
}

// Set to 1 if the event was sniffed (i.e., not blocked), 0 otherwise.
func (a *WinDivertAddress) Sniffed() bool {
	return a.flags&0x00100000 > 0
}

// Direction returns the direction of the packet
func (a *WinDivertAddress) Direction() Direction {
	if a.flags&0x00200000 > 0 {
		return Outbound
	}
	return Inbound
}

// Set to 1 for loopback packets, 0 otherwise.
func (a *WinDivertAddress) Loopback() bool {
	return a.flags&0x00400000 > 0
}

// Set to 1 for impostor packets, 0 otherwise.
func (a *WinDivertAddress) Impostor() bool {
	return a.flags&0x00800000 > 0
}

// Set to 1 for IPv6 packets/events, 0 otherwise.
func (a *WinDivertAddress) IPv6() bool {
	return a.flags&0x01000000 > 0
}

// Set to 1 if the IPv4 checksum is valid, 0 otherwise.
func (a *WinDivertAddress) IPChecksumValid() bool {
	return a.flags&0x02000000 > 0
}

// Set to 1 if the TCP checksum is valid, 0 otherwise.
func (a *WinDivertAddress) TCPChecksumValid() bool {
	return a.flags&0x04000000 > 0
}

// Set to 1 if the UDP checksum is valid, 0 otherwise.
func (a *WinDivertAddress) UDPChecksumValid() bool {
	return a.flags&0x08000000 > 0
}

// WINDIVERT_DATA_NETWORK
type WinDivertDataNetwork addressInternalUnion

func (a *WinDivertAddress) Network() WinDivertDataNetwork {
	if (a.Layer() != Network) && (a.Layer() != NetworkForward) {
		panic("wrong layer")
	}
	return WinDivertDataNetwork(a.data)
}

// The interface index on which the packet arrived (for inbound packets), or is to be sent (for outbound packets).
func (d *WinDivertDataNetwork) IfIdx() uint32 {
	return hostByteOrder.Uint32(d[0:3])
}

// The sub-interface index for IfIdx.
func (d *WinDivertDataNetwork) SubIfIdx() uint32 {
	return hostByteOrder.Uint32(d[4:7])
}

// WINDIVERT_DATA_FLOW
type WinDivertDataFlow addressInternalUnion

func (a *WinDivertAddress) Flow() WinDivertDataFlow {
	if a.Layer() != Flow {
		panic("wrong layer")
	}
	return WinDivertDataFlow(a.data)
}

// The endpoint ID of the flow.
func (d *WinDivertDataFlow) Endpoint() uint64 {
	return hostByteOrder.Uint64(d[0:7])
}

// The parent endpoint ID of the flow.
func (d *WinDivertDataFlow) ParentEndpoint() uint64 {
	return hostByteOrder.Uint64(d[8:15])
}

// The ID of the process associated with the flow.
func (d *WinDivertDataFlow) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[16:19])
}

func (d *WinDivertDataFlow) LocalAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[20:35])
	return ip.Unmap()
}

func (d *WinDivertDataFlow) RemoteAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[36:51])
	return ip.Unmap()
}

func (d *WinDivertDataFlow) LocalPort() uint16 {
	return hostByteOrder.Uint16(d[52:53])
}

func (d *WinDivertDataFlow) RemotePort() uint16 {
	return hostByteOrder.Uint16(d[54:55])
}

func (d *WinDivertDataFlow) Protocol() uint8 {
	return d[56]
}

// WINDIVERT_DATA_SOCKET
type WinDivertDataSocket addressInternalUnion

func (a *WinDivertAddress) Socket() WinDivertDataSocket {
	if a.Layer() != Socket {
		panic("wrong layer")
	}
	return WinDivertDataSocket(a.data)
}

// The endpoint ID of the socket operation.
func (d *WinDivertDataSocket) Endpoint() uint64 {
	return hostByteOrder.Uint64(d[0:7])
}

// The parent endpoint ID of the socket operation.
func (d *WinDivertDataSocket) ParentEndpoint() uint64 {
	return hostByteOrder.Uint64(d[8:15])
}

// The ID of the process associated with the socket operation.
func (d *WinDivertDataSocket) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[16:19])
}

func (d *WinDivertDataSocket) LocalAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[20:35])
	return ip.Unmap()
}

func (d *WinDivertDataSocket) RemoteAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[36:51])
	return ip.Unmap()
}

func (d *WinDivertDataSocket) LocalPort() uint16 {
	return hostByteOrder.Uint16(d[52:53])
}

func (d *WinDivertDataSocket) RemotePort() uint16 {
	return hostByteOrder.Uint16(d[54:55])
}

func (d *WinDivertDataSocket) Protocol() uint8 {
	return d[56]
}

// WINDIVERT_DATA_REFLECT
type WinDivertDataReflect addressInternalUnion

func (a *WinDivertAddress) Reflect() WinDivertDataReflect {
	if a.Layer() != Reflect {
		panic("wrong layer")
	}
	return WinDivertDataReflect(a.data)
}

// A timestamp indicating when the handle was opened.
func (d *WinDivertDataReflect) Timestamp() int64 {
	return int64(hostByteOrder.Uint64(d[0:7]))
}

// The ID of the process that opened the handle.
func (d *WinDivertDataReflect) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[8:11])
}

func (d *WinDivertDataReflect) Layer() Layer {
	// Note: Defined as "WINDIVERT_LAYER Layer;" with no explicit byte ordering
	// TODO: should be tested
	return Layer(hostByteOrder.Uint64(d[12:19]))
}

func (d *WinDivertDataReflect) Flags() uint64 {
	return hostByteOrder.Uint64(d[20:27])
}

func (d *WinDivertDataReflect) Priority() int16 {
	return int16(hostByteOrder.Uint16(d[28:29]))
}
