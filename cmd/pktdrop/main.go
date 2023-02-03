// Drops all the packets matching a filter. If the filter is unset, it defaults to drop all packets.
// This is a re-implementation of https://github.com/williamfhe/godivert/blob/a48c5b872c736d3f23abaad7732528b17416341a/examples/blockPackets/main.go
// Usage:
//
//	pktdrop [filter]
package main

import (
	"github.com/jamesits/go-windivert/pkg/diverter"
	"github.com/jamesits/go-windivert/pkg/ffi"
	"github.com/jamesits/goinvoke/utils"
	"log"
	"os"
	"os/signal"
	"path/filepath"
)

var d *diverter.Diverter

func main() {
	var err error

	filter := "!loopback"
	if len(os.Args) == 2 {
		filter = os.Args[1]
	}

	log.Printf("packet filter: %s\n", filter)

	ep, err := utils.ExecutableDir()
	if err != nil {
		panic(err)
	}

	config := diverter.Config{
		DLLPath:  filepath.Join(ep, "WinDivert.dll"),
		Layer:    ffi.Network,
		Priority: ffi.WinDivertPriorityLowest,
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
