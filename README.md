# go-windivert

Go bindings for [WinDivert](https://github.com/basil00/Divert). Currently WIP, API might change.

[![Go Reference](https://pkg.go.dev/badge/github.com/Jamesits/go-windivert.svg)](https://pkg.go.dev/github.com/Jamesits/go-windivert)

## Features

- WinDivert 2.2
- Native support for [google/gopacket](https://github.com/google/gopacket) packet parsing library

TODO:
- Test 32-bit platforms

## Usage

```shell
go get github.com/jamesits/go-windivert
```

Examples using the high-level interface (channel based):
- [Sniffing only](cmd/pktdump/main.go)
- [Packet injection](cmd/pktloopback/main.go)
- [Packet content parsing](cmd/pktcount/main.go)

All [Low-level interfaces](pkg/ffi/library.go) and [simple wrappers](pkg/ffi/wrapper.go) are also available for more than average needs.
