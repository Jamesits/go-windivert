// Dumps every packet it can receive into a pcap file.
// Usage:
//
//	pktdump <filename.pcap>
package main

import (
	"encoding/binary"
	"github.com/jamesits/go-windivert/diverter"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
)

var d *diverter.Diverter
var cleanupOnce sync.Once

func cleanup() {
	cleanupOnce.Do(func() {
		log.Println("exiting...")
		err := d.Stop()
		if err != nil {
			panic(err)
		}
	})
}

func main() {
	var err error

	// open dump file
	filename := os.Args[1]
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// write pcap header
	// https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html
	_, _ = f.Write([]byte{
		0xD4, 0xC3, 0xB2, 0xA1, // magic
		0x02, 0x00, 0x04, 0x00, // Version: 2.4
		0x00, 0x00, 0x00, 0x00, // Reserved1
		0x00, 0x00, 0x00, 0x00, // Reserved2
		0x00, 0x01, 0x00, 0x00, // SnapLen: 65536
		0x65 /* LINKTYPE_RAW */, 0x00, 0x00, 0x00, // LinkType & FCS https://www.tcpdump.org/linktypes.html
	})

	d, err = diverter.New(diverter.NewDefaultDiverterConfig("WinDivert.dll", "true"))
	if err != nil {
		panic(err)
	}

	err = d.Start()
	if err != nil {
		panic(err)
	}
	defer cleanup()

	c := make(chan os.Signal, 1)
	go func() {
		<-c
		cleanup()
	}()
	signal.Notify(c, os.Interrupt)

	for pkt := range d.RecvChan() {
		_ = binary.Write(f, binary.LittleEndian, time.Now().UnixNano())
		_ = binary.Write(f, binary.LittleEndian, uint32(pkt.Length)) // Captured Packet Length
		_ = binary.Write(f, binary.LittleEndian, uint32(pkt.Length)) // Original Packet Length

		_, err = f.Write(pkt.Content)
		if err != nil {
			panic(err)
		}
	}
}
