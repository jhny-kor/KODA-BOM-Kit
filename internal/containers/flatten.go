package containers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrFlattenBudget reports that a root filesystem exceeded the copy limits;
// the wrapped message says whether files or bytes ran out.
var ErrFlattenBudget = errors.New("root filesystem exceeds the copy limit")

// Budget bounds the bytes and files copied while flattening.
type Budget struct {
	Bytes int64
	Files int64
}

// Flatten copies layers, lowest first, into the empty directory dest and
// applies overlay whiteouts so dest holds the merged root filesystem. Only
// directories, regular files and symlinks are copied; set-ID bits and device
// nodes are dropped. Writes go through os.Root, so a symlink from a lower
// layer can never redirect a copy outside dest. Sources are only read.
func Flatten(ctx context.Context, layers []string, dest string, budget *Budget) error {
	out, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	for _, layer := range layers {
		in, err := os.OpenRoot(layer)
		if err != nil {
			return err
		}
		err = flattenDir(ctx, in, layer, out, ".", budget)
		in.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func flattenDir(ctx context.Context, in *os.Root, layer string, out *os.Root, rel string, budget *Budget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := in.Open(rel)
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == ".wh..wh..opq" { // AUFS-style opaque marker
			if err := clearDir(out, rel); err != nil {
				return err
			}
		}
	}
	for _, e := range entries {
		name := e.Name()
		p := path.Join(rel, name)
		if name == ".wh..wh..opq" {
			continue
		}
		if hidden, ok := strings.CutPrefix(name, ".wh."); ok {
			if err := out.RemoveAll(path.Join(rel, hidden)); err != nil {
				return err
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if budget.Files--; budget.Files < 0 {
			return fmt.Errorf("%w: file count", ErrFlattenBudget)
		}
		switch {
		case whiteout(info):
			if err := out.RemoveAll(p); err != nil {
				return err
			}
		case info.IsDir():
			existing, err := out.Lstat(p)
			if err == nil && (!existing.IsDir() || opaque(filepath.Join(layer, filepath.FromSlash(p)))) {
				if err := out.RemoveAll(p); err != nil {
					return err
				}
				err = fs.ErrNotExist
			}
			if errors.Is(err, fs.ErrNotExist) {
				if err := out.Mkdir(p, 0755); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			if err := flattenDir(ctx, in, layer, out, p, budget); err != nil {
				return err
			}
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := in.Readlink(p)
			if err != nil {
				return err
			}
			if err := out.RemoveAll(p); err != nil {
				return err
			}
			if err := out.Symlink(target, p); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if budget.Bytes -= info.Size(); budget.Bytes < 0 {
				return fmt.Errorf("%w: size", ErrFlattenBudget)
			}
			if err := out.RemoveAll(p); err != nil {
				return err
			}
			if err := copyFile(in, out, p, info.Mode().Perm()); err != nil {
				return err
			}
		}
	}
	return nil
}

func clearDir(out *os.Root, rel string) error {
	dir, err := out.Open(rel)
	if err != nil {
		return nil
	}
	entries, _ := dir.ReadDir(-1)
	dir.Close()
	for _, e := range entries {
		if err := out.RemoveAll(path.Join(rel, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(in, out *os.Root, p string, perm fs.FileMode) error {
	src, err := in.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := out.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm|0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	return err
}

// LayerSize sums regular file sizes over layers: an upper bound of the
// flattened size, used to check free space before copying.
func LayerSize(ctx context.Context, layers []string) int64 {
	var total int64
	for _, layer := range layers {
		filepath.WalkDir(layer, func(_ string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return ctx.Err()
			}
			if d.Type().IsRegular() {
				if info, err := d.Info(); err == nil {
					total += info.Size()
				}
			}
			return nil
		})
	}
	return total
}
