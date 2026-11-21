// Package zipguard bounds ZIP indexes before archive/zip allocates per-entry metadata.
package zipguard

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
)

const (
	maxIndexBytes = 32 << 20
	maxMembers    = 100_000
	tailBytes     = 65 * 1024
	indexOverhead = 256 << 10
)

var ErrLimit = errors.New("ZIP directory exceeds collection limits")

type index struct {
	offset          int64
	data            []byte
	alternateOffset int64
	alternatePrefix []byte
}

// Limits bounds the entries and bytes in a central directory. Zero values use
// the default limits. RequireExactEnd disallows extra bytes after the ZIP footer.
type Limits struct {
	Members         int
	DirectoryBytes  int64
	RequireExactEnd bool
}

func (i index) stream(r io.ReaderAt) io.Reader {
	if len(i.alternatePrefix) == 0 {
		return io.MultiReader(io.NewSectionReader(r, 0, i.offset), bytes.NewReader(i.data))
	}
	end := i.alternateOffset + int64(len(i.alternatePrefix))
	return io.MultiReader(io.NewSectionReader(r, 0, i.alternateOffset), bytes.NewReader(i.alternatePrefix),
		io.NewSectionReader(r, end, i.offset-end), bytes.NewReader(i.data))
}

// NewReader opens a ZIP using a checked directory. File data remains backed
// by r, and consumers are responsible for limiting member decompression.
func NewReader(ctx context.Context, r io.ReaderAt, size int64, limits Limits) (*zip.Reader, error) {
	i, err := readIndex(ctx, r, size, limits)
	if err != nil {
		return nil, err
	}
	return i.open(r, size)
}

func (i *index) open(r io.ReaderAt, size int64) (*zip.Reader, error) {
	input := &indexedReader{ReaderAt: r, index: i}
	z, err := zip.NewReader(input, size)
	input.index = nil
	return z, err
}

// While archive/zip parses, it can read only the checked metadata. Its probes
// of bytes earlier in the file see zeros and cannot choose an alternate index.
// After parsing, member streams read the original input.
type indexedReader struct {
	io.ReaderAt
	index *index
}

func (r *indexedReader) ReadAt(p []byte, off int64) (int, error) {
	i := r.index
	if i == nil {
		return r.ReaderAt.ReadAt(p, off)
	}
	if off < 0 || off > i.offset+int64(len(i.data)) {
		return 0, io.EOF
	}
	n := 0
	if off < i.offset {
		n = int(min(int64(len(p)), i.offset-off))
		clear(p[:n])
		off += int64(n)
	}
	if n < len(p) {
		n += copy(p[n:], i.data[off-i.offset:])
	}
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func readIndex(ctx context.Context, r io.ReaderAt, size int64, limits Limits) (index, error) {
	if err := ctx.Err(); err != nil {
		return index{}, err
	}
	memberLimit := maxMembers
	if limits.Members > 0 {
		memberLimit = min(limits.Members, maxMembers)
	}
	byteLimit := int64(maxIndexBytes)
	if limits.DirectoryBytes > 0 {
		byteLimit = min(limits.DirectoryBytes, maxIndexBytes)
	}
	const endSize = 22
	if size < endSize {
		return index{}, zip.ErrFormat
	}
	tail := make([]byte, min(size, tailBytes))
	if _, err := r.ReadAt(tail, size-int64(len(tail))); err != nil {
		return index{}, err
	}
	var end []byte
	for p := len(tail) - endSize; p >= 0; p-- {
		if string(tail[p:p+4]) == "PK\x05\x06" {
			end = tail[p:]
			break
		}
	}
	u16, u32, u64 := binary.LittleEndian.Uint16, binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	if end == nil || endSize+int(u16(end[20:22])) > len(end) || u16(end[4:6]) != 0 || u16(end[6:8]) != 0 {
		return index{}, zip.ErrFormat
	}
	if limits.RequireExactEnd && endSize+int(u16(end[20:22])) != len(end) {
		return index{}, zip.ErrFormat
	}
	endOffset := size - int64(len(end))
	dirEnd := endOffset
	records, length, offset := uint64(u16(end[10:12])), uint64(u32(end[12:16])), uint64(u32(end[16:20]))
	var locator, zip64 []byte
	if (records == 0xffff || length == 0xffff || offset == 0xffffffff) && endOffset >= 20 {
		locator = make([]byte, 20)
		if _, err := r.ReadAt(locator, endOffset-20); err != nil {
			return index{}, err
		}
		if string(locator[:4]) == "PK\x06\x07" {
			pos := u64(locator[8:16])
			if endOffset < 76 || pos > uint64(endOffset-76) || u32(locator[4:8]) != 0 || u32(locator[16:20]) != 1 {
				return index{}, zip.ErrFormat
			}
			dirEnd = int64(pos)
			zip64 = make([]byte, 56)
			if _, err := r.ReadAt(zip64, dirEnd); err != nil {
				return index{}, err
			}
			if string(zip64[:4]) != "PK\x06\x06" || u32(zip64[16:20]) != 0 || u32(zip64[20:24]) != 0 {
				return index{}, zip.ErrFormat
			}
			records, length, offset = u64(zip64[32:40]), u64(zip64[40:48]), u64(zip64[48:56])
		}
	}
	if length > uint64(dirEnd) || offset > uint64(size) {
		return index{}, zip.ErrFormat
	}
	start := dirEnd - int64(length)
	dataStart := start
	if locator != nil {
		dataStart = min(dataStart, endOffset-int64(len(locator)))
	}
	if length > uint64(byteLimit) || size-dataStart > byteLimit+indexOverhead || records > uint64(memberLimit) {
		return index{}, ErrLimit
	}
	data := make([]byte, size-dataStart)
	if _, err := r.ReadAt(data, dataStart); err != nil {
		return index{}, err
	}
	n := min(len(tail), len(data))
	if !bytes.Equal(tail[len(tail)-n:], data[len(data)-n:]) ||
		(locator != nil && !bytes.Equal(locator, data[endOffset-20-dataStart:endOffset-dataStart])) ||
		(zip64 != nil && !bytes.Equal(zip64, data[dirEnd-dataStart:dirEnd-dataStart+int64(len(zip64))])) {
		return index{}, zip.ErrFormat
	}
	directory := data[start-dataStart : dirEnd-dataStart]
	count := 0
	const fileHeaderSize = 46
	for p := 0; p < len(directory); {
		if err := ctx.Err(); err != nil {
			return index{}, err
		}
		entry := directory[p:]
		if len(entry) < 4 || string(entry[:4]) != "PK\x01\x02" {
			break // archive/zip also stops at a non-file header, e.g. a signature.
		}
		if len(entry) < fileHeaderSize {
			return index{}, zip.ErrFormat
		}
		step := fileHeaderSize + int(u16(entry[28:30])) + int(u16(entry[30:32])) + int(u16(entry[32:34]))
		if step > len(entry) {
			return index{}, zip.ErrFormat
		}
		count++
		if count > memberLimit {
			return index{}, ErrLimit
		}
		p += step
	}
	if uint16(count) != uint16(records) || zip64 != nil && uint64(count) != records {
		return index{}, zip.ErrFormat
	}
	i := index{offset: dataStart, data: data}
	// Self-extracting ZIPs often place shell/launcher bytes before the archive.
	// Go tests the unadjusted directory offset for a second possible header.
	// Check and pin its signature too, without copying the launcher or payload.
	if int64(offset) < start {
		var signature [4]byte
		prefix := 0
		if int64(offset) < dataStart {
			prefix = int(min(dataStart-int64(offset), int64(len(signature))))
			if _, err := r.ReadAt(signature[:prefix], int64(offset)); err != nil {
				return index{}, err
			}
		}
		if prefix < len(signature) {
			copy(signature[prefix:], data[int64(offset)+int64(prefix)-dataStart:])
		}
		if string(signature[:]) == "PK\x01\x02" {
			return index{}, zip.ErrFormat
		}
		i.alternateOffset = int64(offset)
		i.alternatePrefix = signature[:prefix]
	}
	return i, nil
}
