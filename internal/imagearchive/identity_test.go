package imagearchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerIdentityDoesNotInventRegistryManifest(t *testing.T) {
	archive := securityDocker(t, securityTar(t, []securityEntry{{name: "app", data: "installed"}}))
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := ExtractWithIdentity(context.Background(), archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	config := sha256.Sum256([]byte(`{"os":"linux","architecture":"amd64"}`))
	if identity.ArchiveSHA256 != hex.EncodeToString(sum[:]) || identity.ConfigDigest != "sha256:"+hex.EncodeToString(config[:]) || identity.ManifestDigest != "" || identity.Format != "docker-save" {
		t.Fatalf("incorrect identity %+v", identity)
	}
}

func TestArchiveIdentityHonorsCancellation(t *testing.T) {
	archive := securityDocker(t, securityTar(t, []securityEntry{{name: "app", data: "installed"}}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ExtractWithIdentity(ctx, archive, t.TempDir()); err == nil {
		t.Fatal("cancelled hash accepted")
	}
}

func TestCompressedArchiveIdentityIncludesAllInputBytes(t *testing.T) {
	input := securityDocker(t, securityTar(t, []securityEntry{{name: "app", data: "installed"}}))
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	if _, err := g.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	// Gzip padding remains part of the checksum even after tar reaches EOF.
	b.Write(make([]byte, 8192))
	gzipPath := filepath.Join(t.TempDir(), "image.tar.gz")
	if err := os.WriteFile(gzipPath, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	root, identity, err := ExtractWithIdentity(context.Background(), gzipPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.Bytes())
	app, err := os.ReadFile(filepath.Join(root, "app"))
	if err != nil || string(app) != "installed" || identity.ArchiveSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("incorrect content or identity %+v: %v", identity, err)
	}
}

func TestOCIIdentityPreservesRepeatedLayers(t *testing.T) {
	var entries []securityEntry
	addBlob := func(data []byte) descriptor {
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		entries = append(entries, securityEntry{name: "blobs/sha256/" + digest, data: string(data)})
		return descriptor{Digest: "sha256:" + digest, Size: int64(len(data))}
	}
	config := addBlob([]byte(`{"os":"linux","architecture":"amd64"}`))
	layer := addBlob(securityTar(t, []securityEntry{{name: "app", data: "installed"}}))
	manifestJSON, err := json.Marshal(map[string]any{"config": config, "layers": []descriptor{layer, layer}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := addBlob(manifestJSON)
	index, err := json.Marshal(map[string]any{"manifests": []descriptor{manifest}})
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, securityEntry{name: "index.json", data: string(index)})
	root, identity, err := ExtractWithIdentity(context.Background(), securityArchive(t, entries), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app, err := os.ReadFile(filepath.Join(root, "app"))
	if err != nil || string(app) != "installed" || identity.ManifestDigest != manifest.Digest || identity.ConfigDigest != config.Digest {
		t.Fatalf("incorrect OCI content or identity %+v: %v", identity, err)
	}
}
