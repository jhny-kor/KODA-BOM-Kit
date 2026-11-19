package containers

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"os"
)

// A minimal read-only reader for the bbolt files containerd keeps its image,
// container and snapshot metadata in. It follows the documented on-disk
// layout (two meta pages, branch/leaf pages, inline buckets) and never
// writes or locks the file. Every offset is bounds-checked: a corrupt or
// concurrently rewritten page yields errBolt, not a panic.

var errBolt = errors.New("unreadable bolt database")

const (
	boltBranch     = 0x01
	boltLeaf       = 0x02
	boltMeta       = 0x04
	boltBucketFlag = 0x01
	boltMagic      = 0xED0CDAED
	boltMaxPages   = 1 << 20 // pages visited per bucket walk
)

type boltDB struct {
	f        *os.File
	size     int64
	pageSize int64
	root     uint64
}

func openBolt(path string) (*boltDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errBolt
	}
	db := &boltDB{f: f, size: st.Size()}
	header := make([]byte, 16+64)
	var best uint64
	found := false
	// Meta pages are page 0 and page 1; the page size is stored in each.
	for _, offset := range []int64{0, -1} {
		if offset < 0 {
			offset = db.pageSize
			if offset == 0 {
				offset = 4096 // page 0 unreadable: the common page size
			}
		}
		if _, err := f.ReadAt(header, offset); err != nil {
			continue
		}
		meta := header[16:]
		if binary.LittleEndian.Uint16(header[8:]) != boltMeta || binary.LittleEndian.Uint32(meta) != boltMagic || binary.LittleEndian.Uint32(meta[4:]) != 2 {
			continue
		}
		h := fnv.New64a()
		h.Write(meta[:56])
		if h.Sum64() != binary.LittleEndian.Uint64(meta[56:]) {
			continue
		}
		pageSize := int64(binary.LittleEndian.Uint32(meta[8:]))
		if pageSize < 512 || pageSize > 1<<16 {
			continue
		}
		if txid := binary.LittleEndian.Uint64(meta[48:]); !found || txid > best {
			best, found = txid, true
			db.root, db.pageSize = binary.LittleEndian.Uint64(meta[16:]), pageSize
		}
	}
	if !found {
		f.Close()
		return nil, errBolt
	}
	return db, nil
}

func (db *boltDB) Close() error { return db.f.Close() }

func (db *boltDB) page(id uint64) ([]byte, error) {
	offset := int64(id) * db.pageSize
	if id < 2 || offset < 0 || offset+16 > db.size {
		return nil, errBolt
	}
	header := make([]byte, 16)
	if _, err := db.f.ReadAt(header, offset); err != nil {
		return nil, errBolt
	}
	length := (int64(binary.LittleEndian.Uint32(header[12:])) + 1) * db.pageSize
	if length > 64<<20 || offset+length > db.size {
		return nil, errBolt
	}
	buf := make([]byte, length)
	if _, err := db.f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, errBolt
	}
	return buf, nil
}

// boltBucket is a bucket rooted at a page, or inline in its parent's value.
type boltBucket struct {
	db     *boltDB
	root   uint64
	inline []byte
}

func (db *boltDB) Root() boltBucket { return boltBucket{db: db, root: db.root} }

// each calls fn for every key in key order; bucket is true for sub-buckets.
func (b boltBucket) each(fn func(key, value []byte, bucket bool) bool) error {
	visited := 0
	var walk func(page []byte) error
	walk = func(page []byte) error {
		if visited++; visited > boltMaxPages || len(page) < 16 {
			return errBolt
		}
		flags, count := binary.LittleEndian.Uint16(page[8:]), int(binary.LittleEndian.Uint16(page[10:]))
		if 16+count*16 > len(page) {
			return errBolt
		}
		for i := 0; i < count; i++ {
			element := page[16+i*16:]
			switch flags {
			case boltBranch:
				child, err := b.db.page(binary.LittleEndian.Uint64(element[8:]))
				if err != nil {
					return err
				}
				if err := walk(child); err != nil {
					return err
				}
			case boltLeaf:
				elementFlags := binary.LittleEndian.Uint32(element)
				pos, ksize, vsize := int(binary.LittleEndian.Uint32(element[4:])), int(binary.LittleEndian.Uint32(element[8:])), int(binary.LittleEndian.Uint32(element[12:]))
				start := 16 + i*16 + pos
				if pos < 0 || ksize < 0 || vsize < 0 || start+ksize+vsize > len(page) {
					return errBolt
				}
				if !fn(page[start:start+ksize], page[start+ksize:start+ksize+vsize], elementFlags&boltBucketFlag != 0) {
					return nil
				}
			default:
				return errBolt
			}
		}
		return nil
	}
	if b.root == 0 {
		return walk(b.inline)
	}
	page, err := b.db.page(b.root)
	if err != nil {
		return err
	}
	return walk(page)
}

// Bucket returns the named sub-bucket.
func (b boltBucket) Bucket(name string) (boltBucket, bool) {
	var out boltBucket
	found := false
	b.each(func(key, value []byte, bucket bool) bool {
		if bucket && string(key) == name && len(value) >= 16 {
			out = boltBucket{db: b.db, root: binary.LittleEndian.Uint64(value)}
			if out.root == 0 {
				out.inline = value[16:]
			}
			found = true
			return false
		}
		return true
	})
	return out, found
}

// Path follows nested buckets.
func (b boltBucket) Path(names ...string) (boltBucket, bool) {
	for _, name := range names {
		var ok bool
		if b, ok = b.Bucket(name); !ok {
			return b, false
		}
	}
	return b, true
}

// Get returns a key's value, or nil.
func (b boltBucket) Get(name string) []byte {
	var out []byte
	b.each(func(key, value []byte, bucket bool) bool {
		if !bucket && string(key) == name {
			out = append([]byte{}, value...)
			return false
		}
		return true
	})
	return out
}

// Keys lists sub-bucket names.
func (b boltBucket) Keys() []string {
	var out []string
	b.each(func(key, _ []byte, bucket bool) bool {
		if bucket {
			out = append(out, string(key))
		}
		return len(out) < 100000
	})
	return out
}
