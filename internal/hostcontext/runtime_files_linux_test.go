//go:build linux

package hostcontext

import (
	"os"
	"testing"
)

func TestRuntimeFilesPreserveDeletedIdentityAndVersions(t *testing.T) {
	files := parseRuntimeFiles("1-2 r-xp 0 08:01 42 /usr/lib/libssl.so (deleted)\n2-3 r--p 0 08:01 42 /usr/lib/libssl.so (deleted)\n3-4 r-xp 0 08:01 43 /usr/lib/libssl.so\n4-5 r-xp 0 08:01 44 /proc/secret\n", []string{"proc"})
	if len(files) != 2 || !files[0].Deleted || files[0].Inode != 42 || files[1].Deleted || files[1].Inode != 43 {
		t.Fatalf("identity lost: %+v", files)
	}
}

func TestRuntimeFileMissingNamespaceCannotClaimDiskMatch(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files := runtimeFiles(root, "1-2 r-xp 0 08:01 42 /lib/x.so\n2-3 r-xp 0 08:01 43 /lib/y.so (deleted)\n", nil, false)
	if files[0].State != "namespace_unknown" || files[1].State != "restart_review" {
		t.Fatalf("unexpected states: %+v", files)
	}
}

func TestRuntimeFilesRejectInvalidIdentity(t *testing.T) {
	for _, input := range []string{"1-2 r-xp 0 invalid 42 /lib/x.so", "1-2 r-xp 0 08:zz 42 /lib/x.so", "1-2 r-xp 0 08:01 0 /lib/x.so", "1-2 r-xp 0 08:01 42 [heap]"} {
		if len(parseRuntimeFiles(input, nil)) != 0 {
			t.Fatal(input)
		}
	}
}
