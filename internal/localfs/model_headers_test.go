package localfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLargeModelAdmissionKeepsFullReadBoundAndFileBudget(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"model.safetensors", "excluded.gguf", "other.bin"} {
		f, err := os.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		err = f.Truncate(3 << 30)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("model.safetensors", filepath.Join(root, "alias.safetensors")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("excluded.gguf", filepath.Join(root, "excluded-alias.gguf")); err != nil {
		t.Fatal(err)
	}
	p, err := BuildWithOptions(context.Background(), root, []string{"/excluded.gguf"}, Options{MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	if p.AdmittedFileCount() != 1 || len(p.Paths) != 0 || len(p.ModelHeaderPaths) != 2 {
		t.Fatalf("unexpected admission: %+v", p)
	}
	r, err := p.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, name := range []string{"model.safetensors", "alias.safetensors"} {
		if f, _, err := p.OpenIndexedRegular(r, name); err == nil {
			f.Close()
			t.Fatal("full read admitted", name)
		}
		f, info, err := p.OpenModelHeader(r, name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if info.Size() != 3<<30 {
			t.Fatal(info.Size())
		}
	}
	for _, name := range []string{"excluded.gguf", "excluded-alias.gguf", "other.bin"} {
		if f, _, err := p.OpenModelHeader(r, name); err == nil {
			f.Close()
			t.Fatal("excluded path admitted", name)
		}
	}
	_, err = BuildWithOptions(context.Background(), root, []string{"/excluded.gguf"}, Options{MaxFiles: 1, FilesAlreadyCounted: 1})
	var limit *FileLimitError
	if !errors.As(err, &limit) || limit.Observed != 2 {
		t.Fatalf("file budget: %v", err)
	}
	// Replacing an admitted canonical file with an escaping symlink must fail.
	if err = os.Remove(filepath.Join(root, "model.safetensors")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(root, "model.safetensors")); err != nil {
		t.Fatal(err)
	}
	if f, _, err := p.OpenModelHeader(r, "alias.safetensors"); err == nil {
		f.Close()
		t.Fatal("replacement symlink admitted")
	}
}
