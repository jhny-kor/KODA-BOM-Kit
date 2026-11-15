//go:build !linux

package hostcontext

import "os"

func openNoFollow(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
