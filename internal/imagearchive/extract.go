// Package imagearchive flattens an explicitly supplied local Docker/OCI archive.
// It never contacts a registry or daemon, and never uses external decompressors.
package imagearchive

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"io"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/localfs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxBytes int64 = 16 << 30
const maxEntries = 500000

func reader(file string) (io.ReadCloser, error) {
	f, e := evidencefile.Open(file)
	if e != nil {
		return nil, e
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("archive must remain a regular file")
	}
	buf := make([]byte, 4)
	n, _ := f.Read(buf)
	f.Seek(0, 0)
	if n >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		g, e := gzip.NewReader(f)
		if e != nil {
			f.Close()
			return nil, e
		}
		return &closer{Reader: g, close: func() error { g.Close(); return f.Close() }}, nil
	}
	if n == 4 && buf[0] == 0x28 && buf[1] == 0xb5 && buf[2] == 0x2f && buf[3] == 0xfd {
		z, e := zstd.NewReader(f, zstd.WithDecoderMaxMemory(128<<20))
		if e != nil {
			f.Close()
			return nil, e
		}
		return &closer{Reader: z, close: func() error { z.Close(); return f.Close() }}, nil
	}
	return f, nil
}

type closer struct {
	io.Reader
	close func() error
}

func (c *closer) Close() error { return c.close() }
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
	r, e := reader(archive)
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
				d, e := root.Open(parent)
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				names, e := d.Readdirnames(-1)
				d.Close()
				if e != nil {
					return e
				}
				for _, v := range names {
					if e = root.RemoveAll(path.Join(parent, v)); e != nil {
						return e
					}
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

func blob(ctx context.Context, root *os.Root, d descriptor) (string, error) {
	parts := strings.Split(d.Digest, ":")
	if len(parts) != 2 || parts[0] != "sha256" || len(parts[1]) != 64 {
		return "", fmt.Errorf("only sha256 OCI blobs supported")
	}
	if _, e := hex.DecodeString(parts[1]); e != nil {
		return "", e
	}
	n := "blobs/sha256/" + parts[1]
	f, e := root.Open(n)
	if e != nil {
		return "", e
	}
	defer f.Close()
	hash := sha256.New()
	size, e := io.Copy(hash, io.LimitReader(contextReader{ctx: ctx, r: f}, maxBytes+1))
	if e != nil {
		return "", e
	}
	if size > maxBytes || d.Size != size || hex.EncodeToString(hash.Sum(nil)) != parts[1] {
		return "", fmt.Errorf("OCI blob size/digest mismatch")
	}
	return n, nil
}
func Extract(ctx context.Context, archive, work string) (string, error) {
	safeArchive, e := localfs.ResolveLocal(archive)
	if e != nil {
		return "", e
	}
	info, e := os.Stat(safeArchive)
	if e != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("image input must be a local regular file")
	}
	archive = safeArchive
	limits := &budget{remaining: maxBytes * 3} // bounded outer + prepass + materialized layer bytes

	outer := filepath.Join(work, "image")
	fsroot := filepath.Join(work, "rootfs")
	if e := os.MkdirAll(outer, 0700); e != nil {
		return "", e
	}
	if e := os.MkdirAll(fsroot, 0700); e != nil {
		return "", e
	}
	if e := unpack(ctx, archive, outer, true, false, limits); e != nil {
		return "", e
	}
	r, e := os.OpenRoot(outer)
	if e != nil {
		return "", e
	}
	defer r.Close()
	var layers []string
	var config string
	if _, e = r.Stat("manifest.json"); e == nil {
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
		manifest, e := blob(ctx, r, matches[0])
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
		config, e = blob(ctx, r, m.Config)
		if e != nil {
			return "", e
		}
		for _, d := range m.Layers {
			n, e := blob(ctx, r, d)
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
	if len(layers) == 0 || len(layers) > 256 {
		return "", fmt.Errorf("invalid image layer count")
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
