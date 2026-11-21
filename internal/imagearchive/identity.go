package imagearchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/localfs"
)

type Identity struct {
	Format         string `json:"format"`
	ArchiveSHA256  string `json:"archiveSha256"`
	ConfigDigest   string `json:"configDigest"`
	ManifestDigest string `json:"manifestDigest,omitempty"`
	Architecture   string `json:"architecture"`
	OS             string `json:"os"`
}

// extractOuter uses one file descriptor and hashes the very bytes delivered to
// the decoder. No pathname reopen or second read can change what the digest covers.
func extractOuter(ctx context.Context, archive, dest string, limits *budget) (string, error) {
	safe, err := localfs.ResolveLocal(archive)
	if err != nil {
		return "", err
	}
	f, err := evidencefile.Open(safe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxBytes {
		return "", fmt.Errorf("image identity requires bounded regular input")
	}
	limit := &io.LimitedReader{R: contextReader{ctx: ctx, r: f}, N: maxBytes + 1}
	hash := sha256.New()
	raw := io.TeeReader(limit, hash)
	if err := unpackStream(ctx, raw, dest, true, false, limits); err != nil {
		return "", err
	}
	// A tar reader can stop at its end marker. Include any trailing encoded
	// bytes in the digest, as expected for a checksum of the original file.
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return "", err
	}
	after, err := f.Stat()
	if err != nil || maxBytes+1-limit.N != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", fmt.Errorf("archive changed during collection")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ExtractWithIdentity binds a successful extraction to the supplied archive bytes.
// Docker save metadata does not establish a registry manifest digest.
func ExtractWithIdentity(ctx context.Context, archive, work string) (string, Identity, error) {
	var identity Identity
	root, err := extract(ctx, archive, work, &identity)
	if err != nil {
		return "", Identity{}, err
	}
	return root, identity, nil
}

func dockerConfigDigest(ctx context.Context, root *os.Root, config string) (string, error) {
	name, err := clean(config)
	if err != nil {
		return "", err
	}
	f, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
		return "", fmt.Errorf("image config requires bounded regular input")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, r: f}, st.Size()+1))
	if err != nil {
		return "", err
	}
	if n != st.Size() {
		return "", fmt.Errorf("image config size changed")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
