//go:build !unix

package localfs

import "os"

func openEvidence(root *os.Root, path string) (*os.File, error) {
	return root.Open(path)
}
