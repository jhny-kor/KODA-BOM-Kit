package imagearchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
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
