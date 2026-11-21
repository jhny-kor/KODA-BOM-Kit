package staticjs

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"

	"koda.local/security-sbom-linux/internal/zipguard"
)

const (
	MaxArchiveBytes   = 512 << 20
	maxDirectoryBytes = 8 << 20
	totalIndexBytes   = 128 << 20
	totalArchiveReads = 512 << 20
	maxNestedBytes    = 64 << 20
	totalNestedBytes  = 128 << 20
	maxArchiveDepth   = 3
	maxArchiveEntries = 50_000
	maxVirtualPath    = 4096
)

// archiveCandidate selects direct scripts and child archives in deployment
// layouts. Ordinary JAR entries (classes, test resources, and arbitrary data)
// don't need script probes.
func archiveCandidate(container, name string) (script bool, child string) {
	if isScript(name) {
		if container != ".jar" {
			return true, ""
		}
		for _, prefix := range []string{"", "BOOT-INF/classes/"} {
			path, present := strings.CutPrefix(name, prefix)
			if !present {
				continue
			}
			for _, directory := range []string{"META-INF/resources/", "static/", "public/", "resources/"} {
				if strings.HasPrefix(path, directory) {
					return true, ""
				}
			}
		}
		return false, ""
	}

	child = archiveKind(name)
	switch container {
	case ".ear", ".zip":
		return false, child
	case ".war":
		if child == ".jar" && (strings.HasPrefix(name, "WEB-INF/lib/") ||
			strings.HasPrefix(name, "WEB-INF/lib-provided/")) {
			return false, child
		}
	case ".jar":
		if child == ".jar" && strings.HasPrefix(name, "BOOT-INF/lib/") {
			return false, child
		}
	}
	return false, ""
}

type archiveEntry struct {
	file *zip.File
	kind string // empty for a script
}

// ValidateDeploymentArchive checks the bounded ZIP directory before a supplied
// deployment reaches the catalogers. It does not decompress any entries.
func ValidateDeploymentArchive(ctx context.Context, r io.ReaderAt, size int64) error {
	z, err := ReadDeploymentZIP(ctx, r, size)
	if err != nil {
		return err
	}
	names := make(map[string]bool, len(z.File))
	for _, entry := range z.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if !safePath(name) || names[name] {
			return zip.ErrInsecurePath
		}
		names[name] = true
	}
	return ctx.Err()
}

// ReadDeploymentZIP limits ZIP directory size and entry count before allocation.
func ReadDeploymentZIP(ctx context.Context, r io.ReaderAt, size int64) (*zip.Reader, error) {
	if size <= 0 || size > MaxArchiveBytes {
		return nil, errArchiveReadLimit
	}
	return zipguard.NewReader(ctx, r, size, zipguard.Limits{
		Members: maxArchiveEntries, DirectoryBytes: maxDirectoryBytes, RequireExactEnd: true,
	})
}

func (c *collector) scanArchive(r io.ReaderAt, size int64, rel, kind string, depth int) {
	if size > MaxArchiveBytes {
		c.issue(rel, "static_js_archive_limit", "archive exceeds the size limit for JavaScript inspection")
		return
	}
	if c.archiveReadBudget <= 0 {
		c.issue(rel, "static_js_archive_read_limit", "total compressed archive read budget was exhausted")
		return
	}
	remaining := totalIndexBytes - c.indexBytes
	if remaining <= 0 {
		c.issue(rel, "static_js_archive_index_limit", "total archive directory inspection budget was exhausted")
		return
	}
	budget := min(remaining, maxDirectoryBytes+(256<<10))
	indexRemaining := budget
	index := &boundedArchiveReader{ReaderAt: r, remaining: &indexRemaining, ctx: c.ctx}
	indexErr := checkDirectory(index, size)
	var z *zip.Reader
	if indexErr == nil {
		// The standard reader stays bounded even if the archive declared a
		// smaller directory than it actually contains.
		z, indexErr = zip.NewReader(index, size)
	}
	// Charge this directory before any child is scanned.
	c.indexBytes += budget - indexRemaining
	index.remaining = &c.archiveReadBudget
	if indexErr != nil && !errors.Is(indexErr, zip.ErrInsecurePath) {
		code := "static_js_archive_invalid"
		if errors.Is(indexErr, errArchiveReadLimit) {
			code = "static_js_archive_limit"
		}
		c.issue(rel, code, "archive directory could not be read within JavaScript collection limits")
		return
	}
	if len(z.File) > maxArchiveEntries {
		c.issue(rel, "static_js_archive_limit", "archive exceeds the entry limit for JavaScript inspection")
		return
	}
	entries := make(map[string]archiveEntry)
	for _, entry := range z.File {
		script, child := archiveCandidate(kind, entry.Name)
		if !script && child == "" {
			continue
		}
		if !safePath(entry.Name) {
			c.issue(rel, "static_js_archive_invalid_entry", "archive contains a script or child archive entry with an unsafe name")
			continue
		}
		if previous, found := entries[entry.Name]; found {
			previous.file = nil
			entries[entry.Name] = previous
			continue
		}
		entries[entry.Name] = archiveEntry{file: entry, kind: child}
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		// Record direct scripts before descending, and prefer web deployment
		// archives to library JARs when they share an EAR/ZIP.
		left, right := entryPriority(entries[names[i]]), entryPriority(entries[names[j]])
		if left != right {
			return left < right
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		if c.stopped() {
			return
		}
		if c.archiveReadBudget <= 0 {
			c.issue(rel, "static_js_archive_read_limit", "remaining archive entries could not be inspected within the compressed read budget")
			return
		}
		c.probes++
		if len(rel)+2+len(name) > maxVirtualPath {
			c.issue(rel, "static_js_archive_path_limit", "archive entry evidence path exceeds the virtual path limit")
			continue
		}
		entry := entries[name]
		location := rel + "!/" + name
		if entry.file == nil || !entry.file.Mode().IsRegular() {
			c.issue(location, "static_js_archive_invalid_entry", "script or child archive entry is duplicated or is not a regular file")
			continue
		}
		if entry.kind != "" {
			c.scanChildArchive(r, size, entry, location, depth)
			continue
		}
		f, err := entry.file.Open()
		if err != nil {
			c.issueArchiveRead(location, err)
			continue
		}
		c.probe(f, location)
		f.Close()
	}
}

func entryPriority(entry archiveEntry) int {
	switch entry.kind {
	case "":
		return 0
	case ".jar":
		return 2
	default:
		return 1
	}
}

func (c *collector) scanChildArchive(parent io.ReaderAt, parentSize int64, entry archiveEntry, rel string, depth int) {
	if depth >= maxArchiveDepth {
		c.issue(rel, "static_js_archive_depth_limit", "child archive is beyond the JavaScript archive nesting limit")
		return
	}
	size := entry.file.UncompressedSize64
	if size > maxNestedBytes {
		c.issue(rel, "static_js_nested_archive_limit", "child archive exceeds the size limit for JavaScript inspection")
		return
	}
	if entry.file.Method == zip.Store {
		// Executable Spring Boot archives normally store library JARs without
		// compression. Read their directory and selected entries in place.
		offset, err := entry.file.DataOffset()
		if err != nil {
			c.issueArchiveRead(rel, err)
			return
		}
		if offset < 0 || offset > parentSize || int64(size) > parentSize-offset || entry.file.CompressedSize64 != size {
			c.issue(rel, "static_js_archive_invalid_entry", "stored child archive has inconsistent boundaries")
			return
		}
		c.scanArchive(io.NewSectionReader(parent, offset, int64(size)), int64(size), rel, entry.kind, depth+1)
		return
	}

	remaining := totalNestedBytes - c.nestedBytes
	if remaining <= 0 || size > uint64(remaining) {
		c.issue(rel, "static_js_nested_archive_limit", "child archive exceeds the remaining total decompression budget")
		return
	}
	f, err := entry.file.Open()
	if err != nil {
		c.issueArchiveRead(rel, err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(size)+1))
	f.Close()
	c.nestedBytes += int64(len(data))
	if err != nil {
		c.issueArchiveRead(rel, err)
		return
	}
	if uint64(len(data)) != size {
		c.issue(rel, "static_js_archive_invalid_entry", "inflated child archive does not match its declared size")
		return
	}
	c.scanArchive(bytes.NewReader(data), int64(len(data)), rel, entry.kind, depth+1)
}

func (c *collector) issueArchiveRead(rel string, err error) {
	if errors.Is(err, errArchiveReadLimit) {
		c.issue(rel, "static_js_archive_read_limit", "total compressed archive read budget was exhausted")
	} else {
		c.issue(rel, "static_js_read_failed", "script or child archive entry could not be read")
	}
}

var errArchiveReadLimit = errors.New("ZIP evidence exceeds scan limits")

// checkDirectory caps the declared directory size and record count before
// archive/zip allocates a slice for the central directory. Support single-disk
// ZIP64 as well as ordinary ZIP so small forced-ZIP64 WARs are still readable.
func checkDirectory(r io.ReaderAt, size int64) error {
	const endSize = 22
	// Match archive/zip's search window and final-marker precedence. Do not
	// fall back to earlier markers when the final one looks invalid.
	tail := make([]byte, min(size, 65*1024))
	if _, err := r.ReadAt(tail, size-int64(len(tail))); err != nil {
		return err
	}
	for i := len(tail) - endSize; i >= 0; i-- {
		end := tail[i:]
		if string(end[:4]) != "PK\x05\x06" {
			continue
		}
		if i+endSize+int(binary.LittleEndian.Uint16(end[20:22])) != len(tail) {
			return zip.ErrFormat
		}
		records := uint64(binary.LittleEndian.Uint16(end[10:12]))
		length := uint64(binary.LittleEndian.Uint32(end[12:16]))
		offset := binary.LittleEndian.Uint32(end[16:20])
		if binary.LittleEndian.Uint16(end[4:6]) != 0 || binary.LittleEndian.Uint16(end[6:8]) != 0 {
			return zip.ErrFormat
		}
		if records == 0xffff || length == 0xffff || offset == 0xffffffff {
			// archive/zip accepts 0xffff in the length field as a ZIP64
			// indicator too. A classic archive with exactly that length is valid.
			endOffset := size - int64(len(tail)-i)
			locator := make([]byte, 20)
			if endOffset >= int64(len(locator)) {
				if _, err := r.ReadAt(locator, endOffset-int64(len(locator))); err != nil {
					return err
				}
			}
			if string(locator[:4]) == "PK\x06\x07" {
				zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
				record := make([]byte, 56)
				if zip64Offset > uint64(endOffset-int64(len(locator))) || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
					return zip.ErrFormat
				}
				if _, err := r.ReadAt(record, int64(zip64Offset)); err != nil || string(record[:4]) != "PK\x06\x06" {
					return zip.ErrFormat
				}
				records = binary.LittleEndian.Uint64(record[32:40])
				length = binary.LittleEndian.Uint64(record[40:48])
			}
		}
		if records > maxArchiveEntries || length > maxDirectoryBytes {
			return errArchiveReadLimit
		}
		return nil
	}
	return zip.ErrFormat
}

type boundedArchiveReader struct {
	io.ReaderAt
	remaining *int64
	ctx       context.Context
}

func (r *boundedArchiveReader) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining == nil {
		return r.ReaderAt.ReadAt(p, off)
	}
	if int64(len(p)) > *r.remaining {
		*r.remaining = 0
		return 0, errArchiveReadLimit
	}
	n, err := r.ReaderAt.ReadAt(p, off)
	*r.remaining -= int64(n)
	return n, err
}
