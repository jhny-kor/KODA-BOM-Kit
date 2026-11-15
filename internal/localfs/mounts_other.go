//go:build !linux

package localfs

func RemoteMounts() ([]string, error) { return nil, nil }
