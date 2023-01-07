package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
)

func uninstall() {
	var err error

	mutexName, err := windows.UTF16FromString("WinDivertDriverInstallMutex")
	if err != nil {
		log.Panic(err)
	}

	mutexHandle, err := windows.CreateMutex(nil, false, &mutexName[0])
	if err != nil || mutexHandle == windows.InvalidHandle {
		log.Panic(err)
	}
	defer windows.CloseHandle(mutexHandle)
	defer windows.ReleaseMutex(mutexHandle)

	mutexEvent, err := windows.WaitForSingleObject(mutexHandle, windows.INFINITE)
	if err != nil || (mutexEvent != windows.WAIT_OBJECT_0 && mutexEvent != windows.WAIT_ABANDONED) {
		log.Panic(err)
	}

	sc, err := mgr.Connect()
	if err != nil {
		panic(err)
	}
	defer sc.Disconnect()

	service, err := sc.OpenService("WinDivert")
	if err != nil || service == nil {
		panic(err)
	}
	defer service.Close()

	status, err := service.Control(svc.Stop)
	if err != nil {
		log.Println(err)
	}

	if status.State != windows.SERVICE_STOPPED {
		log.Println("error: failed to stop WinDivert service")
	}

	err = service.Delete()
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("UNINSTALL WinDivert")
}
