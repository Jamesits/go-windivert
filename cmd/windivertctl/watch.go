package main

import (
	"fmt"
	"github.com/jamesits/go-windivert/diverter"
	"github.com/jamesits/go-windivert/ffi"
	"log"
	"strings"
	"time"
)

func watch(mode Mode) {
	var err error

	config := diverter.Config{
		DLLPath:      "WinDivert.dll",
		Filter:       filter,
		Layer:        ffi.Reflect,
		Priority:     priority,
		Flag:         ffi.Sniff | ffi.ReceiveOnly,
		RecvChanSize: ffi.WinDivertParamQueueLengthMax,
	}

	if mode == Watch {
		config.Flag |= ffi.NoInstall
	}

	d, err := diverter.New(&config)
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

	err = d.SetParam(ffi.QueueLength, ffi.WinDivertParamQueueLengthMax)
	if err != nil {
		log.Panic(err)
	}

	err = d.SetParam(ffi.QueueSize, ffi.WinDivertParamQueueSizeMax)
	if err != nil {
		log.Panic(err)
	}

	err = d.SetParam(ffi.QueueTime, ffi.WinDivertParamQueueTimeMax)
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
		case ffi.ReflectOpen:
			if mode == Uninstall || mode == Kill {
				operation = "KILL"
			} else {
				operation = "OPEN"
			}

		case ffi.ReflectClose:
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
		filter, err := d.FormatFilter(ffi.Filter(packet.Content), layer)
		if err != nil {
			filter = ffi.Filter(packet.Content)
		}

		fmt.Printf(
			"%s ts=%ds pid=%d exe=%s layer=%s flags=%s priority=%d filter=%s\n",
			operation,
			ts,
			pid,
			processName,
			strings.ToUpper(layer.String()),
			flagsToString(flags),
			priority,
			filter.String(),
		)

		if mode == Kill || mode == Uninstall {
			_ = KillProcess(pid)
		}
	}
}
