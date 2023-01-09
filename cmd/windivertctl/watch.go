package main

import (
	"fmt"
	diverter2 "github.com/jamesits/go-windivert/pkg/diverter"
	ffi2 "github.com/jamesits/go-windivert/pkg/ffi"
	"log"
	"strings"
	"time"
)

func watch(mode Mode) {
	var err error

	config := diverter2.Config{
		DLLPath:      "WinDivert.dll",
		Filter:       filter,
		Layer:        ffi2.Reflect,
		Priority:     priority,
		Flag:         ffi2.Sniff | ffi2.ReceiveOnly,
		RecvChanSize: ffi2.WinDivertParamQueueLengthMax,
	}

	if mode == Watch {
		config.Flag |= ffi2.NoInstall
	}

	d, err := diverter2.New(&config)
	if err != nil {
		log.Panic(err)
	}

	err = d.Start()
	if err != nil {
		if mode == Uninstall {
			// if the service is stopped but not deleted, you will not be able to start it
			return
		}
		log.Panic(err)
	}

	err = d.SetParam(ffi2.QueueLength, ffi2.WinDivertParamQueueLengthMax)
	if err != nil {
		log.Panic(err)
	}

	err = d.SetParam(ffi2.QueueSize, ffi2.WinDivertParamQueueSizeMax)
	if err != nil {
		log.Panic(err)
	}

	err = d.SetParam(ffi2.QueueTime, ffi2.WinDivertParamQueueTimeMax)
	if err != nil {
		log.Panic(err)
	}

	if mode != Watch {
		// batch receive current status into the queue, then quit immediately
		_ = d.Stop()
	}

	for packet := range d.RecvChan() {
		ts := time.Now().UnixNano() // TODO: use high precision clock

		var operation string
		switch packet.Address.Event() {
		case ffi2.ReflectOpen:
			if mode == Uninstall || mode == Kill {
				operation = "KILL"
			} else {
				operation = "OPEN"
			}

		case ffi2.ReflectClose:
			if mode == Watch {
				operation = "CLOSE"
			} else {
				continue
			}

		default:
			operation = "???"
		}

		addr := packet.Address.Reflect()

		pid := addr.ProcessId()
		processName, err := GetProcessImageFileName(pid)
		if err != nil {
			processName = "???"
		}

		layer := addr.Layer()
		flags := addr.Flags()
		priority := addr.Priority()
		filter, err := d.LibraryReference().FormatFilter(ffi2.Filter(packet.Content), layer)
		if err != nil {
			filter = ffi2.Filter(packet.Content)
		}

		fmt.Printf(
			"%s ts=%ds pid=%d exe=%s layer=%s flags=%s priority=%d filter=%s\n",
			operation,
			ts,
			pid,
			processName,
			strings.ToUpper(layer.String()),
			flags.String(),
			priority,
			filter.String(),
		)

		if mode == Kill || mode == Uninstall {
			_ = KillProcess(pid)
		}
	}
}
