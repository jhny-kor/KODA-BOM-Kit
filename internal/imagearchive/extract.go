// Package imagearchive flattens an explicitly supplied local Docker/OCI archive.
// It never contacts a registry or daemon, and never uses external decompressors.
package imagearchive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"koda.local/security-sbom-linux/internal/containers"
	"koda.local/security-sbom-linux/internal/evidencefile"
)

const maxBytes int64 = 16 << 30
const maxEntries = 500000
const maxLayers = 256

func decoder(r io.Reader) (io.ReadCloser, error) {
	buffered := bufio.NewReader(r)
	magic, _ := buffered.Peek(4)
	if len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		g, e := gzip.NewReader(buffered)
		if e != nil {
			return nil, e
		}
		return g, nil
	}
	if string(magic) == "\x28\xb5\x2f\xfd" {
		z, e := zstd.NewReader(buffered, zstd.WithDecoderMaxMemory(128<<20))
		if e != nil {
			return nil, e
		}
		return z.IOReadCloser(), nil
	}
	return io.NopCloser(buffered), nil
}

func clean(name string) (string, error) {
	if strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("archive parent traversal rejected")
		}
	}
	n := path.Clean(name)
	if n == ".." || strings.HasPrefix(n, "../") {
		return "", fmt.Errorf("unsafe archive path")
	}
	return n, nil
}
func jsonFile(root *os.Root, name string, v any) error {
	n, e := clean(name)
	if e != nil {
		return e
	}
	f, e := root.Open(n)
	if e != nil {
		return e
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(v)
}

type budget struct {
	remaining int64
	entries   int
}
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func unpack(ctx context.Context, archive, dest string, outer, whiteoutPass bool, limits *budget) error {
	f, e := evidencefile.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("archive must remain a regular file")
	}
	return unpackStream(ctx, f, dest, outer, whiteoutPass, limits)
}

func unpackStream(ctx context.Context, raw io.Reader, dest string, outer, whiteoutPass bool, limits *budget) error {
	r, e := decoder(contextReader{ctx: ctx, r: raw})
	if e != nil {
		return e
	}
	defer r.Close()
	t := tar.NewReader(contextReader{ctx: ctx, r: r})
	root, e := os.OpenRoot(dest)
	if e != nil {
		return e
	}
	defer root.Close()
	var total int64
	count := 0
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		h, e := t.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		count++
		limits.entries++
		if count > maxEntries || limits.entries > maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		n, e := clean(h.Name)
		if e != nil {
			return e
		}
		if n == "." {
			continue
		}
		if h.Size < 0 || h.Size > maxBytes-total {
			return fmt.Errorf("archive extraction size limit exceeded")
		}
		total += h.Size
		if h.Size > limits.remaining {
			return fmt.Errorf("cumulative archive extraction budget exceeded")
		}
		limits.remaining -= h.Size
		base := path.Base(n)
		isWhite := strings.HasPrefix(base, ".wh.")
		if !outer && isWhite {
			if !whiteoutPass {
				continue
			}
			parent := path.Dir(n)
			victim := strings.TrimPrefix(base, ".wh.")
			if base != ".wh..wh..opq" && (victim == "" || victim == "." || victim == "..") {
				return fmt.Errorf("invalid whiteout target")
			}
			if base == ".wh..wh..opq" {
				if e := containers.ClearLayerDirectory(ctx, root, parent); e != nil {
					return e
				}
			} else {
				if e = root.RemoveAll(path.Join(parent, strings.TrimPrefix(base, ".wh."))); e != nil && !os.IsNotExist(e) {
					return e
				}
			}
			continue
		}
		if whiteoutPass {
			continue
		}
		if e = root.MkdirAll(path.Dir(n), 0700); e != nil {
			return e
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if st, err := root.Lstat(n); err == nil && !st.IsDir() {
				if e = root.RemoveAll(n); e != nil {
					return e
				}
			}
			e = root.MkdirAll(n, 0700)
		case tar.TypeReg, tar.TypeRegA:
			if st, err := root.Lstat(n); err == nil && (st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
				if e = root.RemoveAll(n); e != nil {
					return e
				}
			}
			f, err := root.OpenFile(n, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = io.CopyN(f, t, h.Size)
			ce := f.Close()
			if err != nil {
				return err
			}
			e = ce
		case tar.TypeSymlink:
			if outer {
				return fmt.Errorf("outer image archive links are not permitted")
			}
			target := h.Linkname
			if strings.HasPrefix(target, "/") {
				target = strings.TrimLeft(target, "/")
			} else {
				target = path.Join(path.Dir(n), target)
			}
			target, e = clean(target)
			if e != nil {
				return e
			}
			relative, err := filepath.Rel(filepath.FromSlash(path.Dir(n)), filepath.FromSlash(target))
			if err != nil {
				return err
			}
			if e = root.RemoveAll(n); e != nil && !os.IsNotExist(e) {
				return e
			}
			e = root.Symlink(filepath.ToSlash(relative), n)
		case tar.TypeLink:
			if outer {
				return fmt.Errorf("outer image archive links are not permitted")
			}
			target, err := clean(h.Linkname)
			if err != nil {
				return err
			}
			if e = root.RemoveAll(n); e != nil && !os.IsNotExist(e) {
				return e
			}
			e = root.Link(target, n)
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return fmt.Errorf("unsupported archive entry type")
		}
		if e != nil {
			return e
		}
	}
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

type blobVerifier struct {
	root      *os.Root
	remaining int64
	sizes     map[string]int64
}

func (v *blobVerifier) verify(ctx context.Context, d descriptor) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	parts := strings.Split(d.Digest, ":")
	if len(parts) != 2 || parts[0] != "sha256" || len(parts[1]) != 64 {
		return "", fmt.Errorf("only sha256 OCI blobs supported")
	}
	if _, e := hex.DecodeString(parts[1]); e != nil {
		return "", e
	}
	n := "blobs/sha256/" + parts[1]
	if size, ok := v.sizes[d.Digest]; ok {
		if size != d.Size {
			return "", fmt.Errorf("OCI blob size mismatch")
		}
		return n, nil
	}
	if d.Size < 0 || d.Size > v.remaining {
		return "", fmt.Errorf("OCI blob verification budget exceeded")
	}
	f, e := v.root.Open(n)
	if e != nil {
		return "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != d.Size {
		return "", fmt.Errorf("OCI blob size mismatch")
	}
	hash := sha256.New()
	size, e := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, r: f}, d.Size+1))
	if e != nil {
		return "", e
	}
	if d.Size != size || hex.EncodeToString(hash.Sum(nil)) != parts[1] {
		return "", fmt.Errorf("OCI blob size/digest mismatch")
	}
	v.remaining -= size
	v.sizes[d.Digest] = size
	return n, nil
}

func Extract(ctx context.Context, archive, work string) (string, error) {
	fsroot, _, err := ExtractWithIdentity(ctx, archive, work)
	return fsroot, err
}

func extract(ctx context.Context, archive, work string, identity *Identity) (string, error) {
	limits := &budget{remaining: maxBytes * 3} // bounded outer + prepass + materialized layer bytes

	outer := filepath.Join(work, "image")
	fsroot := filepath.Join(work, "rootfs")
	if e := os.MkdirAll(outer, 0700); e != nil {
		return "", e
	}
	if e := os.MkdirAll(fsroot, 0700); e != nil {
		return "", e
	}
	digest, e := extractOuter(ctx, archive, outer, limits)
	if e != nil {
		return "", e
	}
	identity.ArchiveSHA256 = digest
	r, e := os.OpenRoot(outer)
	if e != nil {
		return "", e
	}
	defer r.Close()
	var layers []string
	var config string
	if _, e = r.Stat("manifest.json"); e == nil {
		identity.Format = "docker-save"
		var m []struct {
			Config string
			Layers []string
		}
		if e = jsonFile(r, "manifest.json", &m); e != nil {
			return "", e
		}
		if len(m) != 1 {
			return "", fmt.Errorf("Docker archive must contain exactly one image")
		}
		config = m[0].Config
		layers = m[0].Layers
	} else {
		identity.Format = "oci"
		var index struct {
			Manifests []descriptor `json:"manifests"`
		}
		if e = jsonFile(r, "index.json", &index); e != nil {
			return "", fmt.Errorf("expected Docker/OCI image archive")
		}
		var matches []descriptor
		for _, d := range index.Manifests {
			if d.Platform == nil || (d.Platform.OS == "linux" && d.Platform.Architecture == "amd64") {
				matches = append(matches, d)
			}
		}
		if len(matches) != 1 {
			return "", fmt.Errorf("OCI archive must identify exactly one linux/amd64 manifest")
		}
		// The outer extraction already limits the sum of all file bytes to
		// maxBytes. Count each verified blob only once against the same budget.
		verifier := blobVerifier{root: r, remaining: maxBytes, sizes: make(map[string]int64)}
		manifest, e := verifier.verify(ctx, matches[0])
		if e != nil {
			return "", e
		}
		var m struct {
			Config descriptor   `json:"config"`
			Layers []descriptor `json:"layers"`
		}
		if e = jsonFile(r, manifest, &m); e != nil {
			return "", e
		}
		if len(m.Layers) == 0 || len(m.Layers) > maxLayers {
			return "", fmt.Errorf("invalid image layer count")
		}
		layerBytes := int64(0)
		for _, d := range m.Layers {
			if d.Size < 0 || d.Size > maxBytes-layerBytes {
				return "", fmt.Errorf("image layer total size limit exceeded")
			}
			layerBytes += d.Size
		}
		config, e = verifier.verify(ctx, m.Config)
		if e != nil {
			return "", e
		}
		identity.ManifestDigest = matches[0].Digest
		identity.ConfigDigest = m.Config.Digest
		for _, d := range m.Layers {
			n, e := verifier.verify(ctx, d)
			if e != nil {
				return "", e
			}
			layers = append(layers, n)
		}
	}
	var cfg struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if e = jsonFile(r, config, &cfg); e != nil {
		return "", e
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		return "", fmt.Errorf("only linux/amd64 image archives are supported")
	}
	identity.OS, identity.Architecture = cfg.OS, cfg.Architecture
	if len(layers) == 0 || len(layers) > maxLayers {
		return "", fmt.Errorf("invalid image layer count")
	}
	if identity.Format == "docker-save" {
		identity.ConfigDigest, e = dockerConfigDigest(ctx, r, config)
		if e != nil {
			return "", e
		}
	}
	var expanded int64
	for _, n := range layers {
		safe, e := clean(n)
		if e != nil {
			return "", e
		}
		st, e := r.Stat(safe)
		if e != nil || !st.Mode().IsRegular() {
			return "", fmt.Errorf("missing regular image layer")
		}
		expanded += st.Size()
		if expanded > maxBytes {
			return "", fmt.Errorf("image layer total size limit exceeded")
		}
		file := filepath.Join(outer, filepath.FromSlash(safe))
		if e = unpack(ctx, file, fsroot, false, true, limits); e != nil {
			return "", e
		}
		if e = unpack(ctx, file, fsroot, false, false, limits); e != nil {
			return "", e
		}
	}
	return fsroot, nil
}
