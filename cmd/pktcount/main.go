// Counts received packets by their layer 4 protocol.
// Usage:
//
//	pktcount
package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jamesits/go-windivert/diverter"
	"github.com/jamesits/go-windivert/ffi"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
)

var d *diverter.Diverter
var cleanupOnce sync.Once
var dataFlushLock sync.Mutex
var total uint
var icmp4, icmp6, udp, tcp, unknown uint

func countPacket(packet *ffi.Packet) {
	dataFlushLock.Lock()
	defer dataFlushLock.Unlock()

	total++
	tp := packet.Decode(gopacket.NoCopy).TransportLayer()
	if tp != nil {
		switch tp.LayerType() {
		case layers.LayerTypeICMPv4:
			icmp4++
		case layers.LayerTypeICMPv6:
			icmp6++
		case layers.LayerTypeTCP:
			tcp++
		case layers.LayerTypeUDP:
			udp++
		default:
			unknown++
		}
	} else {
		unknown++
	}

}

func displayHeader() {
	fmt.Printf("Total\tICMPv4\tICMPv6\tTCP\tUDP\tUnknown\t(pps)\n")
}

func displayAndClear() {
	dataFlushLock.Lock()
	defer dataFlushLock.Unlock()

	fmt.Printf("%d\t%d\t%d\t%d\t%d\t%d\n", total, icmp4, icmp6, tcp, udp, unknown)
	total = 0
	icmp4 = 0
	icmp6 = 0
	tcp = 0
	udp = 0
	unknown = 0
}

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

	d, err = diverter.New(diverter.NewDefaultDiverterConfig("WinDivert.dll", "true"))
	if err != nil {
		panic(err)
	}

	err = d.Start()
	if err != nil {
		panic(err)
	}
	defer cleanup()

	// exit handler
	c := make(chan os.Signal, 1)
	go func() {
		<-c
		cleanup()
	}()
	signal.Notify(c, os.Interrupt)

	// UI thread
	go func() {
		displayHeader()

		for {
			time.Sleep(1 * time.Second)
			displayAndClear()
		}
	}()

	// packet processing loop
	for pkt := range d.RecvChan() {
		countPacket(pkt)
	}
}
