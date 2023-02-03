// Dumps every packet it can receive into a pcap file.
// Usage:
//
//	pktdump <filename.pcap>
package main

import (
	"encoding/binary"
	"github.com/jamesits/go-windivert/pkg/diverter"
	"github.com/jamesits/goinvoke/utils"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
		0x4D, 0x3C, 0xB2, 0xA1, // magic
		0x02, 0x00, 0x04, 0x00, // Version: 2.4
		0x00, 0x00, 0x00, 0x00, // Reserved1
		0x00, 0x00, 0x00, 0x00, // Reserved2
		0x00, 0x01, 0x00, 0x00, // SnapLen: 65536
		0x65 /* LINKTYPE_RAW */, 0x00, 0x00, 0x00, // LinkType & FCS https://www.tcpdump.org/linktypes.html
	})

	// configure WinDivert
	ep, err := utils.ExecutableDir()
	if err != nil {
		panic(err)
	}
	d, err = diverter.New(diverter.NewDefaultDiverterConfig(filepath.Join(ep, "WinDivert.dll"), "true"))
	if err != nil {
		panic(err)
	}

	// start packet capturing
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
		// TODO: utilize pkt.Timestamp for more high resolution packet interval recording
		ts := time.Now().UnixNano()

		// write packet header
		_ = binary.Write(f, binary.LittleEndian, uint32(ts/1000000000)) // timestamp (seconds)
		_ = binary.Write(f, binary.LittleEndian, uint32(ts%1000000000)) // timestamp (nanoseconds)
		_ = binary.Write(f, binary.LittleEndian, uint32(pkt.Length))    // Captured Packet Length
		_ = binary.Write(f, binary.LittleEndian, uint32(pkt.Length))    // Original Packet Length

		// write packet content
		_, err = f.Write(pkt.Content)
		if err != nil {
			panic(err)
		}
	}
}
