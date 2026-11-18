package assessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/anchore/packageurl-go"
)

type osvDocument struct {
	ID         string                       `json:"id"`
	Modified   string                       `json:"modified"`
	Withdrawn  string                       `json:"withdrawn"`
	Aliases    []string                     `json:"aliases"`
	References []struct{ Type, URL string } `json:"references"`
	Affected   []struct {
		Package struct {
			PURL string `json:"purl"`
		} `json:"package"`
		Versions []string          `json:"versions"`
		Ranges   []json.RawMessage `json:"ranges"`
	} `json:"affected"`
}

// parseOSV accepts fully enumerated exact versions. Range-only or partially
// enumerated advisories require ecosystem-specific range evaluation and fail
// explicitly so a partial conversion cannot hide affected releases.
func parseOSV(raw []byte) (Rules, error) {
	out := Rules{Schema: "koda-advisory-rules-v1"}
	if len(raw) > maxInput {
		return out, errors.New("OSV input exceeds size limit")
	}
	raw = bytes.TrimSpace(raw)
	var docs []osvDocument
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &docs); err != nil {
			return out, err
		}
	} else {
		var doc osvDocument
		if err := json.Unmarshal(raw, &doc); err != nil {
			return out, err
		}
		docs = []osvDocument{doc}
	}
	if len(docs) == 0 || len(docs) > 4096 {
		return out, errors.New("OSV requires 1 to 4096 advisories")
	}
	var latest time.Time
	for _, doc := range docs {
		if doc.ID == "" || doc.Withdrawn != "" || len(doc.Affected) == 0 {
			return out, errors.New("OSV advisory requires an ID and affected packages and must not be withdrawn")
		}
		modified, err := time.Parse(time.RFC3339, doc.Modified)
		if err != nil {
			return out, fmt.Errorf("OSV %s has invalid modified time", doc.ID)
		}
		if modified.After(latest) {
			latest = modified
		}
		source := ""
		for _, ref := range doc.References {
			u, err := url.Parse(ref.URL)
			if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
				source = ref.URL
				if ref.Type == "ADVISORY" {
					break
				}
			}
		}
		if source == "" {
			return out, fmt.Errorf("OSV %s requires an HTTPS reference", doc.ID)
		}
		for _, affected := range doc.Affected {
			if len(affected.Ranges) > 0 {
				return out, fmt.Errorf("OSV %s contains ranges; this adapter requires exhaustive affected.versions without ranges", doc.ID)
			}
			if len(affected.Versions) == 0 {
				return out, fmt.Errorf("OSV %s has no exact affected versions", doc.ID)
			}
			p, err := packageurl.FromString(affected.Package.PURL)
			if err != nil || p.Type == "" || p.Name == "" || p.Version != "" || p.Subpath != "" {
				return out, fmt.Errorf("OSV %s requires an explicit versionless package PURL", doc.ID)
			}
			versions := slices.Clone(affected.Versions)
			for _, v := range versions {
				if v == "" {
					return out, fmt.Errorf("OSV %s has an empty version", doc.ID)
				}
			}
			slices.Sort(versions)
			versions = slices.Compact(versions)
			out.Rules = append(out.Rules, Rule{ID: doc.ID, Aliases: slices.Clone(doc.Aliases), Source: source, Component: &Selector{PURL: p.ToString()}, AffectedVersions: versions})
			if len(out.Rules) > 4096 {
				return out, errors.New("OSV conversion exceeds 4096 rules")
			}
		}
	}
	out.PublishedAt = latest.UTC().Format(time.RFC3339)
	return out, nil
}
