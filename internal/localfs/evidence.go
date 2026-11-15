package localfs

import (
	"errors"
	"os"
)

var errEvidenceChanged = errors.New("evidence is no longer a readable regular file")

// OpenRegularEvidence opens a preflight path beneath root and rejects a
// symlink or a file replaced between the metadata check and the open.
func OpenRegularEvidence(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, errEvidenceChanged
	}
	file, err := openEvidence(root, name)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, errEvidenceChanged
	}
	return file, after, nil
}
