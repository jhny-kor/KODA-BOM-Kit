package zipguard

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	// The Java cataloger can recurse internally before returning control to
	// the source resolver. Bound that preflight at the same depth as Syft's
	// generic archive traversal and its existing per-member read limit.
	maxJavaDepth         = 16
	maxJavaMemberBytes   = 2 << 30
	maxJavaTreeBytes     = 16 << 30
	maxJavaTreeDirectory = 128 << 20
	maxJavaTreeMembers   = 500_000
)

// IsJavaArchive matches ZIP-based formats used by Syft's Java cataloger.
func IsJavaArchive(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	return ext == ".zip" || isJavaMember(ext)
}

func isJavaMember(ext string) bool {
	switch ext {
	case ".jar", ".war", ".ear", ".par", ".sar", ".nar", ".jpi", ".hpi", ".kar", ".far", ".lpkg", ".rar", ".zap":
		return true
	}
	return false
}

func javaChildren(z *zip.Reader) []*zip.File {
	var entries []*zip.File
	for _, entry := range z.File {
		// Syft matches nested Java filename patterns case-sensitively.
		if !entry.FileInfo().IsDir() && isJavaMember(path.Ext(entry.Name)) {
			entries = append(entries, entry)
		}
	}
	return entries
}

// JavaReader protects Syft's direct Java ZIP reads and its internal recursion.
// It does not close r. Archives without Java children share the underlying
// payload; otherwise a private copy carries the exact checked nested bytes.
func JavaReader(ctx context.Context, r io.ReaderAt, size int64) (io.ReadCloser, error) {
	i, err := readIndex(ctx, r, size, Limits{})
	if err != nil {
		return nil, err
	}
	z, err := i.open(r, size)
	if err != nil {
		return nil, err
	}
	if len(javaChildren(z)) == 0 {
		return io.NopCloser(cancelReader{ctx, i.stream(r)}), nil
	}
	snapshot, err := copyArchive(ctx, i.stream(r), size)
	if err != nil {
		return nil, err
	}
	b := javaBudget{bytes: maxJavaTreeBytes, indexBytes: maxJavaTreeDirectory, members: maxJavaTreeMembers}
	if err := b.check(ctx, snapshot, size, 1); err != nil {
		snapshot.Close()
		return nil, err
	}
	return snapshot, nil
}

type javaBudget struct {
	bytes, indexBytes int64
	members           int
}

func (b *javaBudget) check(ctx context.Context, r io.ReaderAt, size int64, depth int) error {
	if depth > maxJavaDepth || b.members <= 0 {
		return ErrLimit
	}
	i, err := readIndex(ctx, r, size, Limits{Members: b.members})
	if err != nil {
		return err
	}
	b.indexBytes -= int64(len(i.data))
	if b.indexBytes < 0 {
		return ErrLimit
	}
	z, err := i.open(r, size)
	if err != nil {
		return err
	}
	b.members -= len(z.File)
	for _, entry := range javaChildren(z) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.UncompressedSize64 >= maxJavaMemberBytes || entry.UncompressedSize64 > uint64(b.bytes) {
			return ErrLimit
		}
		length := int64(entry.UncompressedSize64)
		b.bytes -= length
		if err := b.checkMember(ctx, r, size, entry, length, depth+1); err != nil {
			return fmt.Errorf("nested Java ZIP directory unreadable: %w", err)
		}
	}
	return nil
}

func (b *javaBudget) checkMember(ctx context.Context, r io.ReaderAt, size int64, entry *zip.File, length int64, depth int) error {
	if entry.Method == zip.Store {
		off, err := entry.DataOffset()
		if err != nil || off < 0 || off > size || length > size-off || entry.CompressedSize64 != entry.UncompressedSize64 {
			return zip.ErrFormat
		}
		return b.check(ctx, io.NewSectionReader(r, off, length), length, depth)
	}
	f, err := entry.Open()
	if err != nil {
		return err
	}
	defer f.Close()
	snapshot, err := copyArchive(ctx, f, length)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	return b.check(ctx, snapshot, length, depth)
}

type scratchArchive struct {
	*os.File
}

func (a *scratchArchive) Close() error {
	return errors.Join(a.File.Close(), os.Remove(a.Name()))
}

func copyArchive(ctx context.Context, r io.Reader, size int64) (*scratchArchive, error) {
	f, err := os.CreateTemp("", "koda-java-archive-*")
	if err != nil {
		return nil, err
	}
	snapshot := &scratchArchive{f}
	n, err := io.Copy(f, io.LimitReader(cancelReader{ctx, r}, size+1))
	if err == nil && n != size {
		err = zip.ErrFormat
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		snapshot.Close()
		return nil, err
	}
	return snapshot, nil
}

type cancelReader struct {
	ctx context.Context
	r   io.Reader
}

func (r cancelReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
