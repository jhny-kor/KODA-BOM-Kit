package assessment

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// applyKEV adds prioritization evidence without changing the observed version
// or the result of a rule evaluation.
func applyKEV(report *Report, path string) error {
	data, digest, err := readInput(path)
	if err != nil {
		return fmt.Errorf("KEV catalog: %w", err)
	}
	var catalog struct {
		DateReleased    string `json:"dateReleased"`
		Count           int
		Vulnerabilities []struct {
			ID string `json:"cveID"`
		}
	}
	if err := json.Unmarshal(data, &catalog); err != nil || catalog.Count <= 0 || catalog.Count != len(catalog.Vulnerabilities) {
		return errors.New("invalid CISA KEV catalog or inconsistent count")
	}
	if _, err := time.Parse(time.RFC3339, catalog.DateReleased); err != nil {
		return errors.New("invalid CISA KEV release date")
	}
	ids := map[string]bool{}
	for _, entry := range catalog.Vulnerabilities {
		if !cveID.MatchString(entry.ID) || ids[entry.ID] {
			return errors.New("invalid or duplicate CISA KEV CVE identifier")
		}
		ids[entry.ID] = true
	}
	report.KEVSHA256, report.KEVDate = digest, catalog.DateReleased
	for i := range report.Findings {
		f := &report.Findings[i]
		f.KnownExploited = ids[f.ID]
		for _, alias := range f.Aliases {
			f.KnownExploited = f.KnownExploited || ids[alias]
		}
	}
	return nil
}
