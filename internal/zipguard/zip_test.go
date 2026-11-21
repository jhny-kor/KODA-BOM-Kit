package zipguard

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"
)

func archive(t *testing.T, prefix string, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(prefix)
	w := zip.NewWriter(&b)
	for i := range n {
		entry, err := w.CreateRaw(&zip.FileHeader{Name: strconv.Itoa(i), Method: zip.Store, CompressedSize64: 0})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestNewReaderChecksConfiguredMemberCount(t *testing.T) {
	data := archive(t, "", 2)
	if _, err := NewReader(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{Members: 1}); !errors.Is(err, ErrLimit) {
		t.Fatalf("expected entry limit error, got %v", err)
	}
	z, err := NewReader(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{Members: 2})
	if err != nil || len(z.File) != 2 {
		t.Fatalf("could not read both entries at the limit: %v", err)
	}
}

func TestStableReaderKeepsPrefixAndIndex(t *testing.T) {
	data := archive(t, "#!/usr/bin/env python3\n", 1)
	stable, err := JavaReader(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer stable.Close()
	got, err := io.ReadAll(stable)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stable reader changed the archive: %v", err)
	}
	z, err := NewReader(context.Background(), bytes.NewReader(got), int64(len(got)), Limits{Members: 1})
	if err != nil || len(z.File) != 1 || z.File[0].Name != "0" {
		t.Fatalf("could not read prefixed ZIP: %v", err)
	}
	f, err := z.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestNewReaderAcceptsZIP64Directory(t *testing.T) {
	const members = 1 << 16
	data := archive(t, "", members)
	z, err := NewReader(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{Members: members})
	if err != nil || len(z.File) != members {
		t.Fatalf("could not read ZIP64 directory: %v", err)
	}
}

func TestJavaReaderPreservesNestedJar(t *testing.T) {
	nested := archive(t, "", 2)
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		t.Run(strconv.Itoa(int(method)), func(t *testing.T) {
			var b bytes.Buffer
			w := zip.NewWriter(&b)
			f, err := w.CreateHeader(&zip.FileHeader{Name: "BOOT-INF/lib/library.jar", Method: method})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(nested); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := JavaReader(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()))
			if err != nil {
				t.Fatal(err)
			}
			scratch := r.(*scratchArchive).Name()
			result, err := io.ReadAll(r)
			if closeErr := r.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil || !bytes.Equal(result, b.Bytes()) {
				t.Fatalf("changed valid nested archive: %v", err)
			}
			if _, err := os.Stat(scratch); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary archive remained after close: %v", err)
			}
		})
	}
}
