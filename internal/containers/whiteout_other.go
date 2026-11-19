//go:build !linux

package containers

import "io/fs"

func whiteout(fs.FileInfo) bool { return false }
func opaque(string) bool        { return false }

func FreeBytes(string) (int64, bool) { return 0, false }
