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

// ErrInvalidWhiteout marks a layer deletion whose target is not one sibling.
var ErrInvalidWhiteout = errors.New("invalid stored-layer whiteout target")

const (
	layerDirectoryBatch = 256
	opaqueLayerMarker   = ".wh..wh..opq"
	// Keep AUFS markers outside the existing file limit, with a separate
	// ceiling for metadata work even when the caller requests a tiny scan.
	minLayerMarkerBudget = 10_000_000
)

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
	markers := max(int64(minLayerMarkerBudget), budget.Files)
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		in, err := os.OpenRoot(layer)
		if err != nil {
			return err
		}
		err = flattenDir(ctx, in, layer, out, ".", budget, &markers)
		in.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func flattenDir(ctx context.Context, in *os.Root, layer string, out *os.Root, rel string, budget *Budget, markers *int64) error {
	// Clear lower entries before visiting upper entries, regardless of where
	// the opaque marker appears in filesystem enumeration order.
	if _, err := in.Lstat(path.Join(rel, opaqueLayerMarker)); err == nil {
		if err := ClearLayerDirectory(ctx, out, rel); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return visitLayerDirectory(ctx, in, rel, func(e fs.DirEntry) error {
		name := e.Name()
		p := path.Join(rel, name)
		if err := chargeLayerEntry(name, budget, markers); err != nil {
			return err
		}
		if name == opaqueLayerMarker {
			return nil
		}
		if hidden, ok := strings.CutPrefix(name, ".wh."); ok {
			target := path.Join(rel, hidden)
			if hidden == "." || !filepath.IsLocal(hidden) || filepath.Base(hidden) != hidden || path.Dir(target) != rel {
				return ErrInvalidWhiteout
			}
			return out.RemoveAll(target)
		}
		info, err := in.Lstat(p)
		if err != nil {
			return err
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
			return flattenDir(ctx, in, layer, out, p, budget, markers)
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
			if err := chargeLayerBytes(budget, info.Size()); err != nil {
				return err
			}
			if err := out.RemoveAll(p); err != nil {
				return err
			}
			if err := copyFile(in, out, p, info.Mode().Perm()); err != nil {
				return err
			}
		}
		return nil
	})
}

func chargeLayerEntry(name string, budget *Budget, markers *int64) error {
	if strings.HasPrefix(name, ".wh.") {
		if *markers <= 0 {
			return fmt.Errorf("%w: whiteout count", ErrFlattenBudget)
		}
		*markers--
		return nil
	}
	if budget.Files <= 0 {
		return fmt.Errorf("%w: file count", ErrFlattenBudget)
	}
	budget.Files--
	return nil
}

func chargeLayerBytes(budget *Budget, size int64) error {
	if size < 0 || size > budget.Bytes {
		return fmt.Errorf("%w: size", ErrFlattenBudget)
	}
	budget.Bytes -= size
	return nil
}

func visitLayerDirectory(ctx context.Context, root *os.Root, rel string, visit func(fs.DirEntry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(layerDirectoryBatch)
		for readErr == nil && len(entries) < layerDirectoryBatch {
			more, err := dir.ReadDir(layerDirectoryBatch - len(entries))
			entries = append(entries, more...)
			readErr = err
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return readErr
			}
			// Release the final batch's handle before descending. Ordinary
			// small directories then use one descriptor at a time.
			dir.Close()
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := visit(entry); err != nil {
				return err
			}
		}
		if readErr != nil {
			return nil
		}
	}
}

// ClearLayerDirectory removes lower entries for an opaque directory in
// bounded batches. Reopening after each batch avoids skipping entries on
// filesystems that reorder a directory while entries are being removed.
func ClearLayerDirectory(ctx context.Context, root *os.Root, rel string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := root.Open(rel)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		names, readErr := dir.Readdirnames(layerDirectoryBatch)
		dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(names) == 0 {
			return nil
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := root.RemoveAll(path.Join(rel, name)); err != nil {
				return err
			}
		}
	}
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
func LayerSize(ctx context.Context, layers []string, budget Budget) (int64, error) {
	bytes := budget.Bytes
	markers := max(int64(minLayerMarkerBudget), budget.Files)
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		root, err := os.OpenRoot(layer)
		if err != nil {
			return 0, err
		}
		err = layerSizeDir(ctx, root, ".", &budget, &markers)
		root.Close()
		if err != nil {
			return 0, err
		}
	}
	return bytes - budget.Bytes, nil
}

func layerSizeDir(ctx context.Context, root *os.Root, rel string, budget *Budget, markers *int64) error {
	return visitLayerDirectory(ctx, root, rel, func(entry fs.DirEntry) error {
		name := entry.Name()
		if err := chargeLayerEntry(name, budget, markers); err != nil {
			return err
		}
		if strings.HasPrefix(name, ".wh.") {
			return nil
		}
		child := path.Join(rel, name)
		if entry.IsDir() {
			return layerSizeDir(ctx, root, child, budget, markers)
		}
		if entry.Type().IsRegular() {
			info, err := root.Lstat(child)
			if err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				return chargeLayerBytes(budget, info.Size())
			}
		}
		return nil
	})
}
