package bomset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"koda.local/security-sbom-linux/internal/evidencefile"
)

// A regenerated operations document must identify the collection it describes.
// Digests prove each input's integrity; this also checks their snapshot binding.
func bindOperations(ctx context.Context, root *os.Root, expected string, operation source) error {
	f, err := evidencefile.OpenRoot(root, "collection.json")
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxRecordBytes {
		return fmt.Errorf("invalid collection metadata for regenerated operations")
	}
	r := &limitedRecordReader{ctx: ctx, r: f, remaining: maxRecordBytes + 1}
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if expected == "" || hex.EncodeToString(sum[:]) != expected {
		return fmt.Errorf("collection metadata checksum mismatch")
	}
	var collection struct {
		Schema    string
		StartedAt string
		Host      map[string]any
	}
	if err = json.Unmarshal(raw, &collection); err != nil {
		return err
	}
	var metadata struct {
		Timestamp string
		Component struct {
			Properties []struct {
				Name, Value string
			}
		}
	}
	if err = json.Unmarshal(operation.Header["metadata"], &metadata); err != nil {
		return err
	}
	if collection.Schema != "koda-sbom-collection-v1" || collection.StartedAt == "" || metadata.Timestamp != collection.StartedAt {
		return fmt.Errorf("regenerated operations BOM belongs to another collection time")
	}
	if len(collection.Host) == 0 {
		return nil
	}
	var host map[string]any
	for _, p := range metadata.Component.Properties {
		if p.Name == "koda:obom:host-identity" {
			if err = json.Unmarshal([]byte(p.Value), &host); err != nil {
				return err
			}
		}
	}
	for key, value := range collection.Host {
		if !sameJSON(value, host[key]) {
			return fmt.Errorf("regenerated operations BOM belongs to another host")
		}
	}
	return nil
}
