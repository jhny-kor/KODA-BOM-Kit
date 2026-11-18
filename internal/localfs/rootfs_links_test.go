package localfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRootFilesystemResolvesAbsoluteLinksInsideTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/busybox"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/busybox", filepath.Join(root, "bin/sh")); err != nil {
		t.Fatal(err)
	}
	directory, err := BuildWithOptions(context.Background(), root, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Issues) != 1 || directory.Issues[0].Path != "bin/sh" {
		t.Fatalf("an application directory must not follow an absolute link out of the target: %+v", directory.Issues)
	}
	rootfs, err := BuildWithOptions(context.Background(), root, nil, Options{RootFilesystem: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rootfs.Issues) != 0 {
		t.Fatalf("container root links resolve inside the target: %+v", rootfs.Issues)
	}
	if got, _, err := rootfs.ResolveIndexedPath("bin/sh"); err != nil || got != "bin/busybox" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, _, err := rootfs.ResolveIndexedPath("../etc"); err == nil {
		t.Fatal("relative escape must still be rejected")
	}
}
