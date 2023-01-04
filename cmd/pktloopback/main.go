// Prints every ICMP packet. This program works in non-sniff mode, so packets must be re-injected.
// Usage:
//
//	pktloopback
package main

import (
	"fmt"
	"github.com/jamesits/go-windivert/diverter"
	"github.com/jamesits/go-windivert/ffi"
	"os"
	"os/signal"
	"sync"
)

var d *diverter.Diverter
var cleanupOnce sync.Once

func cleanup() {
	cleanupOnce.Do(func() {
		err := d.Stop()
		if err != nil {
			panic(err)
		}
	})
}

func main() {
	var err error

	config := diverter.Config{
		DLLPath: "WinDivert.dll",
		Flag:    ffi.Fragments,
		Filter:  "icmp",
	}

	d, err = diverter.New(&config)
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
		fmt.Println(pkt)
		d.SendChan() <- pkt
	}
}
