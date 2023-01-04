package ffi

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Wrapped packet
type Packet struct {
	Address *WinDivertAddress
	Length  uint
	Content []byte
}

func (p *Packet) IPVersion() uint8 {
	return p.Content[0] >> 4
}

func (p *Packet) Decode(options gopacket.DecodeOptions) gopacket.Packet {
	switch p.IPVersion() {
	case 4:
		return gopacket.NewPacket(p.Content, layers.LayerTypeIPv4, options)
	case 6:
		return gopacket.NewPacket(p.Content, layers.LayerTypeIPv6, options)
	}

	return nil
}
