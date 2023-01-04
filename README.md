# go-windivert

Go bindings for [WinDivert](https://github.com/basil00/Divert).

[![Go Reference](https://pkg.go.dev/badge/github.com/Jamesits/go-windivert.svg)](https://pkg.go.dev/github.com/Jamesits/go-windivert)

## Features

- WinDivert 2.2
- Native support for [google/gopacket](https://github.com/google/gopacket) packet parsing library

## Usage

```shell
go get github.com/jamesits/go-windivert
```

Examples using the high-level interface (channel based):
- [Sniffing only](cmd/pktdump/main.go)
- [Packet injection](cmd/pktloopback/main.go)
- [Packet content parsing](cmd/pktcount/main.go)

All [Low-level interfaces](ffi/library.go) and [simple wrappers](ffi/wrapper.go) are also available for more than average needs.
