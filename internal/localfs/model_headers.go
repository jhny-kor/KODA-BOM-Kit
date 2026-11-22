package localfs

import (
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func modelHeaderCandidate(name, root string) bool {
	base := strings.ToLower(path.Base(name))
	if strings.HasPrefix(base, "._") {
		return false
	}
	if strings.HasSuffix(base, ".safetensors") || strings.HasSuffix(base, ".gguf") || ModelCheckpointFile(name) {
		return true
	}
	if strings.Contains("/"+name, "/models/blobs/sha256-") {
		return true
	}
	// Hugging Face snapshot symlinks point to extensionless LFS objects.
	if len(base) == 64 && path.Base(path.Dir(name)) == "blobs" {
		if _, err := hex.DecodeString(base); err != nil {
			return false
		}
		repository := path.Base(path.Dir(path.Dir(name)))
		if repository == "." {
			repository = filepath.Base(root)
		}
		return strings.HasPrefix(repository, "models--")
	}
	return false
}

// ModelCheckpointFile reports names conventionally used for PyTorch
// checkpoints. Only their pickle opcodes are read, so files beyond the 2 GiB
// package-parsing bound are still admitted for that bounded inspection.
func ModelCheckpointFile(name string) bool {
	base := strings.ToLower(path.Base(name))
	switch path.Ext(base) {
	case ".pt", ".pth", ".ckpt":
		return true
	case ".bin":
		return strings.HasPrefix(base, "pytorch_model") || base == "training_args.bin"
	}
	return false
}

// OpenModelHeader keeps large weight files outside full-file package parsing.
// Their canonical paths were independently admitted during the same preflight.
func (p Plan) OpenModelHeader(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	canonical, known := p.modelHeaders[name]
	if !known {
		return p.OpenIndexedRegular(root, name)
	}
	f, info, err := openIndexedFile(root, canonical)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode().Perm()&0444 == 0 {
		f.Close()
		return nil, nil, fs.ErrPermission
	}
	return f, info, nil
}

// AdmittedFileCount counts physical regular files admitted for package or model
// metadata collection; symbolic link aliases do not consume another file slot.
func (p Plan) AdmittedFileCount() int64 {
	count := int64(len(p.Paths))
	for name, canonical := range p.modelHeaders {
		if name == canonical {
			count++
		}
	}
	return count
}
