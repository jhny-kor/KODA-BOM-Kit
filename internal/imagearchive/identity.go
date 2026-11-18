package imagearchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"os"
	"path/filepath"
)

type Identity struct {
	Format         string `json:"format"`
	ArchiveSHA256  string `json:"archiveSha256"`
	ConfigDigest   string `json:"configDigest"`
	ManifestDigest string `json:"manifestDigest,omitempty"`
	Architecture   string `json:"architecture"`
	OS             string `json:"os"`
}

func boundedDigest(ctx context.Context, f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
		return "", fmt.Errorf("image identity requires bounded regular input")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, r: f}, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes || n != st.Size() {
		return "", fmt.Errorf("image identity input size changed")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func archiveDigest(ctx context.Context, archive string) (string, error) {
	f, err := evidencefile.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return boundedDigest(ctx, f)
}

// ExtractWithIdentity binds a successful extraction to the supplied archive bytes.
// Docker save metadata does not establish a registry manifest digest.
func ExtractWithIdentity(ctx context.Context, archive, work string) (string, Identity, error) {
	result := Identity{Architecture: "amd64", OS: "linux"}
	before, err := archiveDigest(ctx, archive)
	if err != nil {
		return "", result, err
	}
	fsroot, err := Extract(ctx, archive, work)
	if err != nil {
		return "", result, err
	}
	after, err := archiveDigest(ctx, archive)
	if err != nil || before != after {
		return "", result, fmt.Errorf("archive changed during collection")
	}
	result.ArchiveSHA256 = before
	root, err := os.OpenRoot(filepath.Join(work, "image"))
	if err != nil {
		return "", result, err
	}
	defer root.Close()
	var config string
	if _, err := root.Stat("manifest.json"); err == nil {
		result.Format = "docker-save"
		var manifests []struct{ Config string }
		if err := jsonFile(root, "manifest.json", &manifests); err != nil {
			return "", result, err
		}
		if len(manifests) != 1 {
			return "", result, fmt.Errorf("ambiguous Docker identity")
		}
		config = manifests[0].Config
	} else {
		result.Format = "oci"
		var index struct {
			Manifests []descriptor `json:"manifests"`
		}
		if err := jsonFile(root, "index.json", &index); err != nil {
			return "", result, err
		}
		for _, d := range index.Manifests {
			if d.Platform != nil && (d.Platform.OS != "linux" || d.Platform.Architecture != "amd64") {
				continue
			}
			manifest, err := blob(ctx, root, d)
			if err != nil {
				return "", result, err
			}
			var m struct {
				Config descriptor `json:"config"`
			}
			if err := jsonFile(root, manifest, &m); err != nil {
				return "", result, err
			}
			config, err = blob(ctx, root, m.Config)
			if err != nil {
				return "", result, err
			}
			result.ManifestDigest = d.Digest
		}
	}
	config, err = clean(config)
	if err != nil {
		return "", result, err
	}
	f, err := root.Open(config)
	if err != nil {
		return "", result, err
	}
	defer f.Close()
	digest, err := boundedDigest(ctx, f)
	if err != nil {
		return "", result, err
	}
	result.ConfigDigest = "sha256:" + digest
	return fsroot, result, nil
}
