package main

import (
	"github.com/jamesits/go-windivert/ffi"
	"log"
	"os"
)

func printUsage() {
	log.Printf("usage: %s (list|watch|kill) [filter]\n", os.Args[0])
	log.Printf("       %s uninstall\n", os.Args[0])
}

func main() {
	var mode Mode

	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		mode = List
	case "watch":
		mode = Watch
	case "kill":
		mode = Kill
	case "uninstall":
		mode = Uninstall

	default:
		log.Fatalf("Unknown mode: %s\n", os.Args[1])
	}

	if len(os.Args) == 3 {
		filter = ffi.Filter(os.Args[2])
	}

	watch(mode)
	if mode == Uninstall {
		uninstall()
	}
}
