package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"io"
	"koda.local/security-sbom-linux/internal/model"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Generated from tests/schemas/spdx.schema.json (CycloneDX 1.6, SPDX list 3.23).
// Source: https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/spdx.schema.json
// Schema SHA-256: baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e
// The synchronization test prevents this runtime list from drifting from validation.
//
//go:embed cyclonedx16-license-ids.txt
var cyclonedx16LicenseList string

// IDs added by the SPDX enum in tests/schemas/cyclonedx-1.7/spdx.schema.json.
//
//go:embed cyclonedx17-license-additions.txt
var cyclonedx17LicenseAdditions string

var cyclonedx16LicenseIDs = licenseIDSet(cyclonedx16LicenseList)
var cyclonedx17LicenseIDs = licenseIDSet(cyclonedx16LicenseList + "\n" + cyclonedx17LicenseAdditions)

func licenseIDSet(list string) map[string]bool {
	ids := map[string]bool{}
	for _, id := range strings.Fields(list) {
		ids[id] = true
	}
	return ids
}

func WriteJSON(dir, name string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return write(dir, name, append(b, '\n'))
}
func write(dir, name string, data []byte) error {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func WriteSBOMs(dir, selected string, s *sbom.SBOM) error {
	return WriteSBOMsContext(context.Background(), dir, selected, s, false, nil)
}
func WriteSBOMsContext(ctx context.Context, dir, selected string, s *sbom.SBOM, incomplete bool, coverage *CollectionCoverage) error {
	return WriteSBOMsWithAssets(ctx, dir, selected, s, incomplete, coverage, nil, false)
}

const CycloneDX17Filename = "sbom.cdx-1.7.json"

func WriteSBOMsWithAssets(ctx context.Context, dir, selected string, s *sbom.SBOM, incomplete bool, coverage *CollectionCoverage, assets []model.Asset, cyclonedx17 bool) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if cyclonedx17 && selected == "spdx" {
		return fmt.Errorf("CycloneDX 1.7 requires a CycloneDX output format")
	}
	var coverageJSON []byte
	allOccurrences := coverage != nil && coverage.IncludeAllOccurrences
	if coverage != nil {
		var err error
		coverageJSON, err = json.Marshal(coverage)
		if err != nil {
			return fmt.Errorf("encode collection coverage: %w", err)
		}
	}
	encs := map[string]sbom.FormatEncoder{"inventory.syft.json": syftjson.NewFormatEncoder()}
	if selected == "both" || selected == "cyclonedx" {
		enc, e := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: "1.6", Pretty: true})
		if e != nil {
			return e
		}
		encs["sbom.cdx.json"] = enc
		if cyclonedx17 {
			additional, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: "1.7", Pretty: true})
			if err != nil {
				return err
			}
			encs[CycloneDX17Filename] = additional
		}
	}
	if selected == "both" || selected == "spdx" {
		enc, e := spdxjson.NewFormatEncoderWithConfig(spdxjson.EncoderConfig{Version: "2.3", DefaultVersion: "2.3", Pretty: true})
		if e != nil {
			return e
		}
		encs["sbom.spdx.json"] = enc
	}
	keys := []string{}
	for key := range encs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		type encoded struct {
			data []byte
			err  error
		}
		ch := make(chan encoded, 1)
		enc := encs[name]
		go func() { b, e := format.Encode(*s, enc); ch <- encoded{b, e} }()
		var b []byte
		var e error
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-ch:
			b, e = result.data, result.err
		}
		if e != nil {
			return fmt.Errorf("encode %s: %w", name, e)
		}
		if name == "sbom.cdx.json" || name == CycloneDX17Filename {
			licenseIDs := cyclonedx16LicenseIDs
			if name == CycloneDX17Filename {
				licenseIDs = cyclonedx17LicenseIDs
			}
			b, _, e = normalizeCycloneDXLicenseIDs(b, licenseIDs)
			if e != nil {
				return fmt.Errorf("encode CycloneDX license identifiers: %w", e)
			}
			b, e = addCycloneDXEvidence(b, incomplete, coverageJSON, allOccurrences)
			if e != nil {
				return fmt.Errorf("encode CycloneDX collection evidence: %w", e)
			}
		} else if name == "sbom.spdx.json" {
			b, e = addSPDXEvidence(b, s.Artifacts.Packages, coverageJSON, allOccurrences)
			if e != nil {
				return fmt.Errorf("encode SPDX collection evidence: %w", e)
			}
		}
		if name != "inventory.syft.json" {
			b, e = addAssetComponents(b, name, assets)
			if e != nil {
				return fmt.Errorf("encode %s asset evidence: %w", name, e)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if e = write(dir, name, append(b, '\n')); e != nil {
			return e
		}
	}
	return nil
}

// Only licenseChoice arrays named "licenses" are changed. In particular, SPDX
// expressions, component IDs, PURLs, relationships and source inventories remain
// untouched. RawMessage keeps numeric values and fields outside these objects.
func normalizeCycloneDXLicenseIDs(raw json.RawMessage, licenseIDs map[string]bool) (json.RawMessage, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, fmt.Errorf("empty JSON value")
	}
	changed := false
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, false, err
		}
		for key, value := range object {
			var next json.RawMessage
			var updated bool
			var err error
			if key == "licenses" {
				next, updated, err = normalizeCycloneDXLicenseChoices(value, licenseIDs)
			} else {
				next, updated, err = normalizeCycloneDXLicenseIDs(value, licenseIDs)
			}
			if err != nil {
				return nil, false, err
			}
			if updated {
				object[key], changed = next, true
			}
		}
		if changed {
			data, err := json.MarshalIndent(object, "", "  ")
			return data, true, err
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, false, err
		}
		for i, item := range items {
			next, updated, err := normalizeCycloneDXLicenseIDs(item, licenseIDs)
			if err != nil {
				return nil, false, err
			}
			if updated {
				items[i], changed = next, true
			}
		}
		if changed {
			data, err := json.Marshal(items)
			return data, true, err
		}
	}
	return raw, false, nil
}

func normalizeCycloneDXLicenseChoices(raw json.RawMessage, licenseIDs map[string]bool) (json.RawMessage, bool, error) {
	var choices []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &choices); err != nil {
		return nil, false, err
	}
	changed := false
	for _, choice := range choices {
		value, exists := choice["license"]
		if !exists {
			continue // An expression is a different licenseChoice; preserve it verbatim.
		}
		var license map[string]json.RawMessage
		if err := json.Unmarshal(value, &license); err != nil {
			return nil, false, err
		}
		idValue, exists := license["id"]
		if !exists {
			continue
		}
		var id string
		if err := json.Unmarshal(idValue, &id); err != nil {
			return nil, false, err
		}
		if licenseIDs[id] {
			continue
		}
		if _, exists := license["name"]; exists {
			return nil, false, fmt.Errorf("license contains both id and name")
		}
		license["name"] = idValue
		delete(license, "id")
		encoded, err := json.Marshal(license)
		if err != nil {
			return nil, false, err
		}
		choice["license"], changed = encoded, true
	}
	if changed {
		data, err := json.Marshal(choices)
		return data, true, err
	}
	return raw, false, nil
}

func Checksums(dir string) error {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	var lines []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "SHA256SUMS" {
			continue
		}
		f, e := os.Open(filepath.Join(dir, entry.Name()))
		if e != nil {
			return e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		lines = append(lines, hex.EncodeToString(h.Sum(nil))+"  "+entry.Name())
	}
	sort.Strings(lines)
	return write(dir, "SHA256SUMS", []byte(strings.Join(lines, "\n")+"\n"))
}
func Scrub(s *sbom.SBOM) { ScrubMetadata(s) }
