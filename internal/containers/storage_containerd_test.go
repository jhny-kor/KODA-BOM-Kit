package containers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// A tiny bbolt writer for tests: every bucket is inline except the root,
// which may be split over a branch page to exercise both page kinds.

const testPageSize = 4096

func boltBucketValue(t *testing.T, entries map[string]any) []byte {
	page := boltLeafPage(t, entries, false)
	return append(make([]byte, 16), page...) // root 0: inline page follows
}

func boltLeafPage(t *testing.T, entries map[string]any, pad bool) []byte {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	header := make([]byte, 16+16*len(keys))
	binary.LittleEndian.PutUint16(header[8:], boltLeaf)
	binary.LittleEndian.PutUint16(header[10:], uint16(len(keys)))
	var data []byte
	for i, k := range keys {
		var value []byte
		flags := uint32(0)
		switch v := entries[k].(type) {
		case string:
			value = []byte(v)
		case []byte:
			value = v
		case map[string]any:
			value, flags = boltBucketValue(t, v), boltBucketFlag
		}
		element := header[16+16*i:]
		binary.LittleEndian.PutUint32(element, flags)
		binary.LittleEndian.PutUint32(element[4:], uint32(len(header)-16-16*i+len(data)))
		binary.LittleEndian.PutUint32(element[8:], uint32(len(k)))
		binary.LittleEndian.PutUint32(element[12:], uint32(len(value)))
		data = append(append(data, k...), value...)
	}
	page := append(header, data...)
	if pad {
		if len(page) > testPageSize {
			t.Fatal("test page too large")
		}
		page = append(page, make([]byte, testPageSize-len(page))...)
	}
	return page
}

// writeBolt stores root entries split into two leaf pages under a branch.
func writeBolt(t *testing.T, path string, root map[string]any) {
	t.Helper()
	keys := make([]string, 0, len(root))
	for k := range root {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	left, right := map[string]any{}, map[string]any{}
	for i, k := range keys {
		if i < (len(keys)+1)/2 {
			left[k] = root[k]
		} else {
			right[k] = root[k]
		}
	}
	pages := make([]byte, 5*testPageSize)
	branch := pages[3*testPageSize:]
	binary.LittleEndian.PutUint16(branch[8:], boltBranch)
	children := []map[string]any{left}
	if len(right) > 0 {
		children = append(children, right)
	}
	binary.LittleEndian.PutUint16(branch[10:], uint16(len(children)))
	for i := range children {
		binary.LittleEndian.PutUint64(branch[16+16*i+8:], uint64(4+i))
	}
	for i, child := range children {
		if i == 1 {
			pages = append(pages, make([]byte, testPageSize)...)
		}
		copy(pages[(4+i)*testPageSize:], boltLeafPage(t, child, true))
	}
	for i := 0; i < 2; i++ {
		page := pages[i*testPageSize:]
		binary.LittleEndian.PutUint16(page[8:], boltMeta)
		meta := page[16:]
		binary.LittleEndian.PutUint32(meta, boltMagic)
		binary.LittleEndian.PutUint32(meta[4:], 2)
		binary.LittleEndian.PutUint32(meta[8:], testPageSize)
		binary.LittleEndian.PutUint64(meta[16:], 3) // root bucket page
		binary.LittleEndian.PutUint64(meta[48:], uint64(i))
		h := fnv.New64a()
		h.Write(meta[:56])
		binary.LittleEndian.PutUint64(meta[56:], h.Sum64())
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pages, 0600); err != nil {
		t.Fatal(err)
	}
}

func uvarint(n uint64) []byte { return binary.AppendUvarint(nil, n) }

func TestBoltReaderAndContainerdStore(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "var/lib/containerd")
	blob := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		digest := hex.EncodeToString(sum[:])
		put(t, base, "io.containerd.content.v1.content/blobs/sha256/"+digest, content)
		return "sha256:" + digest
	}
	d1, d2 := "sha256:"+h("l1"), "sha256:"+h("l2")
	chain2 := "sha256:" + h(d1+" "+d2)
	config := blob(`{"rootfs":{"diff_ids":["` + d1 + `","` + d2 + `"]}}`)
	manifest := blob(`{"config":{"digest":"` + config + `"}}`)
	other := blob(`{"config":{"digest":"` + blob(`{"rootfs":{"diff_ids":["`+d1+`"]}}`) + `"}}`)
	index := blob(`{"manifests":[{"digest":"sha256:` + h("absent") + `","platform":{"os":"linux","architecture":"riscv64"}},{"digest":"` + other + `","platform":{"os":"linux","architecture":"s390x"}}]}`)
	writeBolt(t, filepath.Join(base, "io.containerd.metadata.v1.bolt/meta.db"), map[string]any{
		"v1": map[string]any{"default": map[string]any{
			"images": map[string]any{
				"docker.io/library/app:1":   map[string]any{"target": map[string]any{"digest": manifest}},
				"docker.io/library/app:one": map[string]any{"target": map[string]any{"digest": manifest}},
				"docker.io/library/tool:1":  map[string]any{"target": map[string]any{"digest": index}},
			},
			"snapshots": map[string]any{"overlayfs": map[string]any{
				d1:       map[string]any{"name": "default/1/" + d1},
				chain2:   map[string]any{"name": "default/2/" + chain2},
				"ctr-rw": map[string]any{"name": "default/3/ctr-rw"},
			}},
			"containers": map[string]any{
				"web": map[string]any{"image": "docker.io/library/app:1", "snapshotter": "overlayfs", "snapshotKey": "ctr-rw",
					"labels": map[string]any{"nerdctl/name": "web-1"}},
			},
		}},
	})
	writeBolt(t, filepath.Join(base, "io.containerd.snapshotter.v1.overlayfs/metadata.db"), map[string]any{
		"v1": map[string]any{"snapshots": map[string]any{
			"default/1/" + d1:     map[string]any{"id": uvarint(1)},
			"default/2/" + chain2: map[string]any{"id": uvarint(2), "parent": "default/1/" + d1},
			"default/3/ctr-rw":    map[string]any{"id": uvarint(300)},
		}},
	})
	images, stopped, issues := Storage(context.Background(), root, nil)
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	dir := func(id int) string {
		return filepath.Join(base, "io.containerd.snapshotter.v1.overlayfs/snapshots", strconv.Itoa(id), "fs")
	}
	if len(stopped) != 1 || stopped[0].ID != "web" || stopped[0].Names[0] != "web-1" || stopped[0].Image != "docker.io/library/app:1" ||
		!reflect.DeepEqual(stopped[0].Layers, []string{dir(1), dir(2), dir(300)}) {
		t.Fatalf("stopped %+v", stopped)
	}
	// app is used by the container; tool resolves through the one platform
	// manifest that is present locally.
	if len(images) != 1 || images[0].Names[0] != "docker.io/library/tool:1" || !reflect.DeepEqual(images[0].Layers, []string{dir(1)}) {
		t.Fatalf("images %+v", images)
	}

	db, err := openBolt(filepath.Join(base, "io.containerd.metadata.v1.bolt/meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ns, ok := db.Root().Path("v1", "default", "images")
	if !ok || !reflect.DeepEqual(ns.Keys(), []string{"docker.io/library/app:1", "docker.io/library/app:one", "docker.io/library/tool:1"}) {
		t.Fatalf("keys %v", ns.Keys())
	}
	corrupt := filepath.Join(root, "corrupt.db")
	os.WriteFile(corrupt, make([]byte, 3*testPageSize), 0600)
	if _, err := openBolt(corrupt); err == nil {
		t.Fatal("a file without valid meta pages must be rejected")
	}
}
