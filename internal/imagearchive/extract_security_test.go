package imagearchive

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type securityEntry struct {
	name, data, link string
	kind             byte
}

func securityTar(t *testing.T, entries []securityEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0600, Typeflag: kind, Linkname: e.link}
		if kind == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func securityArchive(t *testing.T, entries []securityEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.tar")
	if err := os.WriteFile(p, securityTar(t, entries), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func securityDocker(t *testing.T, layers ...[]byte) string {
	t.Helper()
	names := make([]string, 0, len(layers))
	entries := []securityEntry{{name: "config.json", data: `{"os":"linux","architecture":"amd64"}`}}
	for i, data := range layers {
		name := strings.Repeat("x", i+1) + "/layer.tar"
		names = append(names, name)
		entries = append(entries, securityEntry{name: name, data: string(data)})
	}
	manifest, _ := json.Marshal([]map[string]any{{"Config": "config.json", "Layers": names}})
	entries = append(entries, securityEntry{name: "manifest.json", data: string(manifest)})
	return securityArchive(t, entries)
}
func TestRejectsOuterArchiveTraversalAndLinks(t *testing.T) {
	for _, entry := range []securityEntry{{name: "../outside", data: "secret"}, {name: "/absolute", data: "secret"}, {name: `x\outside`, data: "secret"}, {name: "link", link: "../outside", kind: tar.TypeSymlink}, {name: "hard", link: "safe", kind: tar.TypeLink}} {
		t.Run(entry.name, func(t *testing.T) {
			if _, err := Extract(context.Background(), securityArchive(t, []securityEntry{entry}), t.TempDir()); err == nil {
				t.Fatal("unsafe outer archive accepted")
			}
		})
	}
}
func TestRejectsLayerEscapingSymlinkAndHardlink(t *testing.T) {
	for _, entry := range []securityEntry{{name: "link", link: "../../escape", kind: tar.TypeSymlink}, {name: "hard", link: "../outside", kind: tar.TypeLink}} {
		t.Run(entry.name, func(t *testing.T) {
			layer := securityTar(t, []securityEntry{entry})
			if _, err := Extract(context.Background(), securityDocker(t, layer), t.TempDir()); err == nil {
				t.Fatal("unsafe layer accepted")
			}
		})
	}
}
func TestLayerWhiteoutsPreserveUpperFiles(t *testing.T) {
	lower := securityTar(t, []securityEntry{{name: "app/remove.txt", data: "lower"}, {name: "app/keep.txt", data: "keep"}, {name: "opaque/old.txt", data: "old"}})
	upper := securityTar(t, []securityEntry{{name: "app/.wh.remove.txt"}, {name: "opaque/new.txt", data: "new"}, {name: "opaque/.wh..wh..opq"}})
	root, err := Extract(context.Background(), securityDocker(t, lower, upper), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"app/remove.txt", "opaque/old.txt"} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Fatalf("whiteout did not remove %s: %v", p, err)
		}
	}
	for p, want := range map[string]string{"app/keep.txt": "keep", "opaque/new.txt": "new"} {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil || string(b) != want {
			t.Fatalf("bad upper file %s: %q %v", p, b, err)
		}
	}
}
func TestCumulativeExtractionBudgetAcrossPasses(t *testing.T) {
	archive := securityArchive(t, []securityEntry{{name: "one", data: strings.Repeat("x", 64)}})
	limits := &budget{remaining: 100}
	if err := unpack(context.Background(), archive, t.TempDir(), true, false, limits); err != nil {
		t.Fatal(err)
	}
	if err := unpack(context.Background(), archive, t.TempDir(), true, false, limits); err == nil {
		t.Fatal("per-layer reset bypassed cumulative budget")
	}
}
func TestCancelledExtractionDoesNotWriteLayer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dest := t.TempDir()
	archive := securityArchive(t, []securityEntry{{name: "must-not-write", data: "x"}})
	if err := unpack(ctx, archive, dest, true, false, &budget{remaining: 1024}); err == nil {
		t.Fatal("cancelled extraction succeeded")
	}
	if _, err := os.Stat(filepath.Join(dest, "must-not-write")); !os.IsNotExist(err) {
		t.Fatal("file written after cancellation")
	}
}
func TestRejectsUnsupportedImageArchitecture(t *testing.T) {
	manifest := `[{"Config":"config.json","Layers":["layer.tar"]}]`
	entries := []securityEntry{{name: "manifest.json", data: manifest}, {name: "config.json", data: `{"os":"linux","architecture":"arm64"}`}, {name: "layer.tar", data: string(securityTar(t, []securityEntry{{name: "foo", data: "bar"}}))}}
	if _, err := Extract(context.Background(), securityArchive(t, entries), t.TempDir()); err == nil {
		t.Fatal("unsupported CPU accepted")
	}
}

func TestRejectsMalformedWhiteoutNames(t *testing.T) {
	for _, name := range []string{"app/.wh.", "app/.wh..", "app/.wh..."} {
		t.Run(name, func(t *testing.T) {
			lower := securityTar(t, []securityEntry{{name: "app/keep", data: "lower"}})
			upper := securityTar(t, []securityEntry{{name: name}})
			if _, err := Extract(context.Background(), securityDocker(t, lower, upper), t.TempDir()); err == nil {
				t.Fatalf("invalid whiteout %s accepted", name)
			}
		})
	}
}
