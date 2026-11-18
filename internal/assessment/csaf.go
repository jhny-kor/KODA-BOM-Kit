package assessment

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
)

type csafProduct struct {
	ID     string `json:"product_id"`
	Helper struct {
		PURL string `json:"purl"`
		CPE  string `json:"cpe"`
	} `json:"product_identification_helper"`
}
type csafBranch struct {
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}
type csafDocument struct {
	Document struct {
		Version  string `json:"csaf_version"`
		Tracking struct {
			ID     string `json:"id"`
			Date   string `json:"current_release_date"`
			Status string `json:"status"`
		} `json:"tracking"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"document"`
	Tree struct {
		Products      []csafProduct     `json:"full_product_names"`
		Branches      []csafBranch      `json:"branches"`
		Relationships []json.RawMessage `json:"relationships"`
		Groups        []json.RawMessage `json:"product_groups"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE string `json:"cve"`
		IDs []struct {
			Text string `json:"text"`
		} `json:"ids"`
		Status       map[string][]string `json:"product_status"`
		Flags        []json.RawMessage   `json:"flags"`
		Threats      []json.RawMessage   `json:"threats"`
		Remediations []json.RawMessage   `json:"remediations"`
		Notes        []json.RawMessage   `json:"notes"`
	} `json:"vulnerabilities"`
}

// parseCSAF converts unconditional exact product assertions. Product groups,
// relationships and contextual assertions need richer applicability evaluation.
func parseCSAF(raw []byte) (Rules, error) {
	out := Rules{Schema: "koda-advisory-rules-v1"}
	if len(raw) > maxInput {
		return out, errors.New("CSAF input exceeds size limit")
	}
	var doc csafDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out, err
	}
	if doc.Document.Version != "2.0" || doc.Document.Tracking.ID == "" || doc.Document.Tracking.Status != "final" {
		return out, errors.New("CSAF requires version 2.0, tracking ID and final status")
	}
	if _, err := time.Parse(time.RFC3339, doc.Document.Tracking.Date); err != nil {
		return out, errors.New("invalid CSAF release date")
	}
	out.PublishedAt = doc.Document.Tracking.Date
	source := ""
	for _, ref := range doc.Document.References {
		u, err := url.Parse(ref.URL)
		if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
			source = ref.URL
			break
		}
	}
	if source == "" {
		return out, errors.New("CSAF requires an HTTPS document reference")
	}
	if len(doc.Tree.Relationships) > 0 || len(doc.Tree.Groups) > 0 {
		return out, errors.New("CSAF product relationships and groups require applicability evaluation")
	}
	products := map[string]csafProduct{}
	add := func(p csafProduct) error {
		if p.ID == "" {
			return errors.New("CSAF missing product ID")
		}
		if _, ok := products[p.ID]; ok {
			return errors.New("CSAF duplicate product ID")
		}
		products[p.ID] = p
		return nil
	}
	for _, p := range doc.Tree.Products {
		if err := add(p); err != nil {
			return out, err
		}
	}
	var walk func([]csafBranch, int) error
	walk = func(branches []csafBranch, depth int) error {
		if depth > 32 {
			return errors.New("CSAF product depth limit")
		}
		for _, b := range branches {
			if b.Product != nil {
				if err := add(*b.Product); err != nil {
					return err
				}
			}
			if err := walk(b.Branches, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc.Tree.Branches, 0); err != nil {
		return out, err
	}
	if len(products) > 4096 || len(doc.Vulnerabilities) == 0 {
		return out, errors.New("CSAF requires vulnerabilities and at most 4096 products")
	}
	for _, v := range doc.Vulnerabilities {
		if len(v.Flags)+len(v.Threats)+len(v.Remediations)+len(v.Notes) > 0 {
			return out, errors.New("CSAF contextual assertions require review and cannot be converted into unconditional rules")
		}
		id := v.CVE
		aliases := []string{doc.Document.Tracking.ID}
		for _, entry := range v.IDs {
			if id == "" {
				id = entry.Text
			} else if entry.Text != "" {
				aliases = append(aliases, entry.Text)
			}
		}
		if id == "" {
			return out, errors.New("CSAF vulnerability needs CVE or vendor ID")
		}
		seen := map[string]bool{}
		selectorRules := map[string]int{}
		keys := make([]string, 0, len(v.Status))
		for status := range v.Status {
			keys = append(keys, status)
		}
		slices.Sort(keys)
		for _, status := range keys {
			ids := v.Status[status]
			if status != "known_affected" && status != "fixed" {
				return out, fmt.Errorf("unsupported CSAF product status %s", status)
			}
			for _, pid := range ids {
				if seen[pid] {
					return out, errors.New("CSAF product has conflicting or duplicate status")
				}
				seen[pid] = true
				p, ok := products[pid]
				if !ok {
					return out, errors.New("CSAF references unknown product")
				}
				selector, version, err := csafIdentity(p)
				if err != nil {
					return out, err
				}
				key := selector.PURL + "\x00" + selector.CPE
				index, exists := selectorRules[key]
				if !exists {
					index = len(out.Rules)
					selectorRules[key] = index
					out.Rules = append(out.Rules, Rule{ID: id, Aliases: slices.Clone(aliases), Source: source, Component: &selector})
				}
				rule := &out.Rules[index]
				if status == "fixed" {
					rule.FixedVersions = append(rule.FixedVersions, version)
				} else {
					rule.AffectedVersions = append(rule.AffectedVersions, version)
				}
				if len(out.Rules) > 4096 {
					return out, errors.New("CSAF rule limit")
				}
			}
		}
	}
	if len(out.Rules) == 0 {
		return out, errors.New("CSAF has no supported product assertions")
	}
	return out, nil
}
func csafIdentity(p csafProduct) (Selector, string, error) {
	if p.Helper.PURL != "" && p.Helper.CPE != "" {
		return Selector{}, "", errors.New("CSAF dual identifiers require consistency review")
	}
	if p.Helper.PURL != "" {
		parsed, err := packageurl.FromString(p.Helper.PURL)
		if err != nil || parsed.Version == "" || parsed.Name == "" || parsed.Subpath != "" {
			return Selector{}, "", errors.New("CSAF requires versioned product PURL")
		}
		version := parsed.Version
		parsed.Version = ""
		return Selector{PURL: parsed.ToString()}, version, nil
	}
	parts := strings.Split(p.Helper.CPE, ":")
	if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" || strings.ContainsAny(p.Helper.CPE, "*?\\") || parts[5] == "" || parts[5] == "-" {
		return Selector{}, "", errors.New("CSAF requires exact full CPE or versioned PURL")
	}
	return Selector{CPE: p.Helper.CPE}, parts[5], nil
}
