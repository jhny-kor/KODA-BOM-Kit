//go:build linux

package main

import "golang.org/x/sys/unix"

func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return "unknown"
	}
	n := 0
	for n < len(u.Release) && u.Release[n] != 0 {
		n++
	}
	return string(u.Release[:n])
}
