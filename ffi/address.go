package ffi

// contains WINDIVERT_ADDRESS and related data types

import "net/netip"

type addressInternalUnion [64]byte

// WINDIVERT_ADDRESS
// https://reqrypt.org/windivert-doc.html#divert_address
type WinDivertAddress struct {
	// A timestamp indicating when event occurred.
	Timestamp int64

	flags uint64
	//UINT32 Layer:8;                     /* Packet's layer. */
	//UINT32 Event:8;                     /* Packet event. */
	//UINT32 Sniffed:1;                   /* Packet was sniffed? */
	//UINT32 Outbound:1;                  /* Packet is outound? */
	//UINT32 Loopback:1;                  /* Packet is loopback? */
	//UINT32 Impostor:1;                  /* Packet is impostor? */
	//UINT32 IPv6:1;                      /* Packet is IPv6? */
	//UINT32 IPChecksum:1;                /* Packet has valid IPv4 checksum? */
	//UINT32 TCPChecksum:1;               /* Packet has valid TCP checksum? */
	//UINT32 UDPChecksum:1;               /* Packet has valid UDP checksum? */
	//UINT32 Reserved1:8;
	//UINT32 Reserved2;

	data addressInternalUnion
	//union
	//{
	//	WINDIVERT_DATA_NETWORK Network; /* Network layer data. */
	//	WINDIVERT_DATA_FLOW Flow;       /* Flow layer data. */
	//	WINDIVERT_DATA_SOCKET Socket;   /* Socket layer data. */
	//	WINDIVERT_DATA_REFLECT Reflect; /* Reflect layer data. */
	//	UINT8 Reserved3[64];
	//};
}

// The handle's layer (WINDIVERT_LAYER_*).
func (a *WinDivertAddress) Layer() Layer {
	return Layer(a.flags & 0xff)
}

// The captured event (WINDIVERT_EVENT_*).
func (a *WinDivertAddress) Event() Event {
	return Event((a.flags >> 8) & 0xff)
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
	return hostByteOrder.Uint32(d[0:4])
}

// The sub-interface index for IfIdx.
func (d *WinDivertDataNetwork) SubIfIdx() uint32 {
	return hostByteOrder.Uint32(d[4:8])
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
	return hostByteOrder.Uint64(d[0:8])
}

// The parent endpoint ID of the flow.
func (d *WinDivertDataFlow) ParentEndpoint() uint64 {
	return hostByteOrder.Uint64(d[8:16])
}

// The ID of the process associated with the flow.
func (d *WinDivertDataFlow) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[16:20])
}

func (d *WinDivertDataFlow) LocalAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[20:36])
	return ip.Unmap()
}

func (d *WinDivertDataFlow) RemoteAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[36:52])
	return ip.Unmap()
}

func (d *WinDivertDataFlow) LocalPort() uint16 {
	return hostByteOrder.Uint16(d[52:54])
}

func (d *WinDivertDataFlow) RemotePort() uint16 {
	return hostByteOrder.Uint16(d[54:56])
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
	return hostByteOrder.Uint64(d[0:8])
}

// The parent endpoint ID of the socket operation.
func (d *WinDivertDataSocket) ParentEndpoint() uint64 {
	return hostByteOrder.Uint64(d[8:16])
}

// The ID of the process associated with the socket operation.
func (d *WinDivertDataSocket) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[16:20])
}

func (d *WinDivertDataSocket) LocalAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[20:36])
	return ip.Unmap()
}

func (d *WinDivertDataSocket) RemoteAddr() netip.Addr {
	ip, _ := netip.AddrFromSlice(d[36:52])
	return ip.Unmap()
}

func (d *WinDivertDataSocket) LocalPort() uint16 {
	return hostByteOrder.Uint16(d[52:54])
}

func (d *WinDivertDataSocket) RemotePort() uint16 {
	return hostByteOrder.Uint16(d[54:56])
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
	return int64(hostByteOrder.Uint64(d[0:8]))
}

// The ID of the process that opened the handle.
func (d *WinDivertDataReflect) ProcessId() uint32 {
	return hostByteOrder.Uint32(d[8:12])
}

func (d *WinDivertDataReflect) Layer() Layer {
	// Note: Defined as "WINDIVERT_LAYER Layer;" with no explicit byte ordering
	return Layer(hostByteOrder.Uint32(d[12:16]))
}

func (d *WinDivertDataReflect) Flags() Flag {
	return Flag(hostByteOrder.Uint64(d[16:24]))
}

func (d *WinDivertDataReflect) Priority() int16 {
	return int16(hostByteOrder.Uint16(d[24:28]))
}
