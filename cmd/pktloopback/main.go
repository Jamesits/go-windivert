// Prints every ICMP packet. This program works in non-sniff mode, so packets must be re-injected.
// Usage:
//
//	pktloopback
package main

import (
	"fmt"
	diverter2 "github.com/jamesits/go-windivert/pkg/diverter"
	"github.com/jamesits/go-windivert/pkg/ffi"
	"os"
	"os/signal"
	"sync"
)

var d *diverter2.Diverter
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

	config := diverter2.Config{
		DLLPath: "WinDivert.dll",
		Flag:    ffi.Fragments,
		Filter:  "icmp",
	}

	d, err = diverter2.New(&config)
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
