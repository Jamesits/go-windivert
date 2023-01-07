package main

//go:generate stringer -type=Mode -output=enums_string.go -linecomment
type Mode uint8

const (
	List Mode = iota
	Watch
	Kill
	Uninstall
)
