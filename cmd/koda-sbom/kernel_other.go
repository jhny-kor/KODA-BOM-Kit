//go:build !linux

package main

func kernelRelease() string { return "unsupported-build-host" }
