//go:build linux

package containers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Overlay whiteouts are 0/0 character devices; creating one needs root.
func TestFlattenCharacterDeviceWhiteout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating a whiteout device requires root; run in the Linux test container")
	}
	base := t.TempDir()
	lower, upper, dest := filepath.Join(base, "l"), filepath.Join(base, "u"), filepath.Join(base, "d")
	put(t, lower, "etc/secret", "x")
	if err := os.MkdirAll(filepath.Join(upper, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(filepath.Join(upper, "etc/secret"), unix.S_IFCHR|0600, 0); err == unix.EPERM {
		t.Skip("device nodes are not permitted here; run privileged with TMPDIR on tmpfs (overlayfs refuses 0/0 devices)")
	} else if err != nil {
		t.Fatal(err)
	}
	os.Mkdir(dest, 0755)
	if err := Flatten(context.Background(), []string{lower, upper}, dest, &Budget{Bytes: 1 << 20, Files: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "etc/secret")); !os.IsNotExist(err) {
		t.Fatalf("whiteout not applied: %v", err)
	}
}
