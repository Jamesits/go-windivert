// Drops all the packets matching a filter. If the filter is unset, it defaults to drop all packets.
// Usage:
//
//	pktdrop [filter]
package main

import (
	"github.com/jamesits/go-windivert/diverter"
	"github.com/jamesits/go-windivert/ffi"
	"log"
	"os"
	"os/signal"
)

var d *diverter.Diverter

func main() {
	var err error

	filter := "!loopback"
	if len(os.Args) == 2 {
		filter = os.Args[1]
	}

	log.Printf("packet filter: %s\n", filter)

	config := diverter.Config{
		DLLPath:  "WinDivert.dll",
		Layer:    ffi.Network,
		Priority: ffi.Lowest,
		Flag:     ffi.Drop,
		Filter:   ffi.Filter(filter),
	}

	d, err = diverter.New(&config)
	if err != nil {
		panic(err)
	}

	err = d.Start()
	if err != nil {
		panic(err)
	}
	defer d.Stop()

	log.Println("pktdrop started")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	log.Println("pktdrop stopped")
}
