// Drops all the packets matching a filter. If the filter is unset, it defaults to drop all packets.
// This is a re-implementation of https://github.com/williamfhe/godivert/blob/a48c5b872c736d3f23abaad7732528b17416341a/examples/blockPackets/main.go
// Usage:
//
//	pktdrop [filter]
package main

import (
	"github.com/jamesits/go-windivert/ffi"
	diverter2 "github.com/jamesits/go-windivert/pkg/diverter"
	ffi2 "github.com/jamesits/go-windivert/pkg/ffi"
	"log"
	"os"
	"os/signal"
)

var d *diverter2.Diverter

func main() {
	var err error

	filter := "!loopback"
	if len(os.Args) == 2 {
		filter = os.Args[1]
	}

	log.Printf("packet filter: %s\n", filter)

	config := diverter2.Config{
		DLLPath:  "WinDivert.dll",
		Layer:    ffi2.Network,
		Priority: ffi.Lowest,
		Flag:     ffi2.Drop,
		Filter:   ffi2.Filter(filter),
	}

	d, err = diverter2.New(&config)
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
