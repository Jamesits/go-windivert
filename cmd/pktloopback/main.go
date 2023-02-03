// Prints every ICMP packet. This program works in non-sniff mode, so packets must be re-injected.
// Usage:
//
//	pktloopback
package main

import (
	"fmt"
	"github.com/jamesits/go-windivert/pkg/diverter"
	"github.com/jamesits/go-windivert/pkg/ffi"
	"github.com/jamesits/goinvoke/utils"
	"os"
	"os/signal"
	"path/filepath"
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

	ep, err := utils.ExecutableDir()
	if err != nil {
		panic(err)
	}

	config := diverter.Config{
		DLLPath: filepath.Join(ep, "WinDivert.dll"),
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
