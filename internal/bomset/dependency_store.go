package bomset

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"koda.local/security-sbom-linux/internal/evidencefile"
)

func relationshipFilename(spec string) string {
	if spec == "1.7" {
		return "relationships.cdx-1.7.jsonl.gz"
	}
	return "relationships.cdx.jsonl.gz"
}

// Store the original relationship rows in source order, including edges that
// span two profiles. Only the identity and checksum of each row go into the
// manifest, even on hosts with millions of dependency edges.
func writeRelationshipSidecar(ctx context.Context, out *output, data *spool, v version) (profile, error) {
	name := relationshipFilename(v.SpecVersion)
	digest, err := out.write(name, func(dst io.Writer) error {
		archive, err := gzip.NewWriterLevel(dst, gzip.BestSpeed)
		if err != nil {
			return err
		}
		for _, source := range v.Sources {
			for _, row := range source.Dependencies {
				if err = ctx.Err(); err != nil {
					return err
				}
				raw, err := data.get(row.SHA256)
				if err != nil {
					return err
				}
				if _, err = archive.Write(raw); err != nil {
					return err
				}
				if _, err = archive.Write([]byte{'\n'}); err != nil {
					return err
				}
			}
		}
		return archive.Close()
	})
	return profile{Kind: "relationships", Filename: name, SHA256: digest}, err
}

// Verify both the compressed bytes and the individual records consumed by
// Merge. A changed, missing, reordered, extra or oversized row is an error.
func readRelationshipSidecar(ctx context.Context, root *os.Root, data *spool, v version, sums map[string]string) error {
	entry := v.Relationships
	name := relationshipFilename(v.SpecVersion)
	if entry.Kind != "relationships" || entry.Filename != name || len(entry.SHA256) != 64 || sums[name] != entry.SHA256 {
		return errors.New("relationship archive does not match set checksums")
	}
	f, err := evidencefile.OpenRoot(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return errors.New("relationship archive must be a regular file")
	}
	h := sha256.New()
	compressed := bufio.NewReader(io.TeeReader(&limitedRecordReader{ctx: ctx, r: f, remaining: stat.Size() + 1}, h))
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	defer gz.Close()
	gz.Multistream(false)
	lines := bufio.NewScanner(gz)
	lines.Buffer(make([]byte, 64<<10), maxRecordBytes+1)
	for _, s := range v.Sources {
		for _, record := range s.Dependencies {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !lines.Scan() {
				if err := lines.Err(); err != nil {
					return err
				}
				return errors.New("missing row in relationship archive")
			}
			raw := lines.Bytes()
			hash := sha256.Sum256(raw)
			if hex.EncodeToString(hash[:]) != record.SHA256 {
				return errors.New("relationship record checksum mismatch")
			}
			var header struct {
				Ref string `json:"ref"`
			}
			if err := json.Unmarshal(raw, &header); err != nil || header.Ref == "" || header.Ref != record.Ref {
				return errors.New("relationship source reference mismatch")
			}
			if err := data.cacheRecord(record.SHA256, raw); err != nil {
				return err
			}
		}
	}
	if lines.Scan() {
		return errors.New("extra row in relationship archive")
	}
	if err = lines.Err(); err != nil {
		return err
	}
	if _, err = compressed.ReadByte(); err != io.EOF {
		return errors.New("trailing relationship archive data")
	}
	if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return ctx.Err()
}

// cacheRecord indexes canonical JSON by its previously computed digest.
func (s *spool) cacheRecord(digest string, raw []byte) error {
	if s.ctx != nil {
		if err := s.ctx.Err(); err != nil {
			return err
		}
	}
	if _, known := s.rows[digest]; known {
		return nil
	}
	offset, err := s.file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	n, err := s.file.Write(raw)
	if err != nil {
		return err
	}
	if n != len(raw) {
		return io.ErrShortWrite
	}
	s.rows[digest] = position{offset, int64(n)}
	return nil
}
