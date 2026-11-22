package bomset

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRelationshipArchiveIntegrityAndOrdering(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sp, err := newSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.close()
	a, err := sp.put([]byte(`{"ref":"a","dependsOn":["b"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sp.put([]byte(`{"ref":"b","dependsOn":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	v := version{SpecVersion: "1.6", Sources: []source{{Dependencies: []relationship{{Ref: "a", SHA256: a}, {Ref: "b", SHA256: b}}}}}
	output, err := newOutput(dir)
	if err != nil {
		t.Fatal(err)
	}
	v.Relationships, err = writeRelationshipSidecar(ctx, output, sp, v)
	output.close(err == nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sums := map[string]string{v.Relationships.Filename: v.Relationships.SHA256}
	restored, err := newSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if err = readRelationshipSidecar(ctx, root, restored, v, sums); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.get(a); err != nil {
		t.Fatal(err)
	}
	swap := v
	swap.Sources = []source{{Dependencies: []relationship{{Ref: "b", SHA256: b}, {Ref: "a", SHA256: a}}}}
	if err = readRelationshipSidecar(ctx, root, restored, swap, sums); err == nil {
		t.Fatal("swapped records accepted")
	}
	short := v
	short.Sources = []source{{Dependencies: []relationship{{Ref: "a", SHA256: a}}}}
	if err = readRelationshipSidecar(ctx, root, restored, short, sums); err == nil {
		t.Fatal("extra record accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = readRelationshipSidecar(cancelled, root, restored, v, sums); err == nil {
		t.Fatal("cancelled read succeeded")
	}
	path := filepath.Join(dir, v.Relationships.Filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	v.Relationships.SHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	sums[v.Relationships.Filename] = v.Relationships.SHA256
	if err = readRelationshipSidecar(ctx, root, restored, v, sums); err == nil {
		t.Fatal("trailing data accepted")
	}
}
