// Package assessment correlates observations with an explicitly supplied offline rule set.
package assessment

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/packageurl-go"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/model"
)

type Rule struct {
	ID               string           `json:"id"`
	Aliases          []string         `json:"aliases,omitempty"`
	Source           string           `json:"source"`
	Component        *Selector        `json:"component,omitempty"`
	Setting          *SettingSelector `json:"setting,omitempty"`
	AffectedVersions []string         `json:"affectedVersions,omitempty"`
	FixedVersions    []string         `json:"fixedVersions,omitempty"`
	AffectedSemver   string           `json:"affectedSemver,omitempty"`
	SupportEndsAt    string           `json:"supportEndsAt,omitempty"`
	Remediation      string           `json:"remediation,omitempty"`
}

type Selector struct {
	PURL       string            `json:"purl,omitempty"`
	CPE        string            `json:"cpe,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Name       string            `json:"name,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	Model      string            `json:"model,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type SettingSelector struct {
	Product string `json:"product"`
	Name    string `json:"name"`
	Equals  string `json:"equals"`
}

type Rules struct {
	Schema      string `json:"schema"`
	PublishedAt string `json:"publishedAt"`
	Rules       []Rule `json:"rules"`
}

type Finding struct {
	ID              string   `json:"id"`
	Aliases         []string `json:"aliases,omitempty"`
	Source          string   `json:"source"`
	ComponentRef    string   `json:"componentRef,omitempty"`
	ComponentName   string   `json:"componentName,omitempty"`
	ObservedVersion string   `json:"observedVersion,omitempty"`
	Status          string   `json:"status"`
	Evidence        string   `json:"evidence"`
	FixedVersions   []string `json:"fixedVersions,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
	SupportEndsAt   string   `json:"supportEndsAt,omitempty"`
	KnownExploited  bool     `json:"knownExploited,omitempty"`
}

type Report struct {
	Schema           string    `json:"schema"`
	AdvisoriesAt     string    `json:"advisoriesAt"`
	AnalyzedAt       string    `json:"analyzedAt"`
	SBOMSHA256       string    `json:"sbomSha256"`
	AdvisoriesSHA256 string    `json:"advisoriesSha256"`
	ContextSHA256    string    `json:"contextSha256,omitempty"`
	KEVSHA256        string    `json:"kevSha256,omitempty"`
	KEVDate          string    `json:"kevDate,omitempty"`
	ComponentCount   int       `json:"componentCount"`
	RulesEvaluated   int       `json:"rulesEvaluated"`
	UnmatchedRules   int       `json:"unmatchedRules"`
	Findings         []Finding `json:"findings"`
}

type component struct {
	model.Asset
	parentRef string
}

type cdxComponent struct {
	Ref          string                         `json:"bom-ref"`
	Type         string                         `json:"type"`
	Name         string                         `json:"name"`
	Version      string                         `json:"version"`
	CPE          string                         `json:"cpe"`
	PURL         string                         `json:"purl"`
	Manufacturer struct{ Name string }          `json:"manufacturer"`
	Components   []cdxComponent                 `json:"components"`
	Properties   []struct{ Name, Value string } `json:"properties"`
}

func parseComponents(raw []byte) ([]component, error) {
	var doc struct {
		BOMFormat   string         `json:"bomFormat"`
		SPDXVersion string         `json:"spdxVersion"`
		Components  []cdxComponent `json:"components"`
		Packages    []struct {
			Ref     string `json:"SPDXID"`
			Name    string
			Version string `json:"versionInfo"`
			Purpose string `json:"primaryPackagePurpose"`
			Comment string
			Refs    []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("read SBOM structure: %w", err)
	}
	var out []component
	switch {
	case doc.BOMFormat == "CycloneDX":
		pending := doc.Components
		for len(pending) > 0 {
			row := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			pending = append(pending, row.Components...)
			a := model.Asset{ID: row.Ref, Kind: row.Type, Name: row.Name, Version: row.Version, CPE: row.CPE,
				PURL: row.PURL, Vendor: row.Manufacturer.Name, Properties: map[string]string{}}
			for _, p := range row.Properties {
				switch p.Name {
				case "koda:asset:model":
					a.Model = p.Value
				case "koda:asset:revision":
					a.Revision = p.Value
				case "koda:asset:parent-id":
					a.ParentID = p.Value
				case "koda:asset:observed-at":
					a.ObservedAt = p.Value
				default:
					if key, ok := strings.CutPrefix(p.Name, "koda:asset:evidence:"); ok {
						a.Properties[key] = p.Value
					}
				}
			}
			out = append(out, component{Asset: a, parentRef: a.ParentID})
		}
	case doc.SPDXVersion == "SPDX-2.3":
		for _, row := range doc.Packages {
			if strings.HasPrefix(row.Ref, "SPDXRef-DocumentRoot-") {
				continue
			}
			a := model.Asset{ID: row.Ref, Kind: strings.ReplaceAll(strings.ToLower(row.Purpose), "_", "-"), Name: row.Name, Version: row.Version}
			if evidence, ok := strings.CutPrefix(row.Comment, "koda:asset:"); ok {
				if err := json.Unmarshal([]byte(evidence), &a); err != nil || a.Name != row.Name || a.Version != row.Version || a.ID == "" {
					return nil, errors.New("invalid SPDX asset evidence")
				}
			}
			refConflict := false
			for _, ref := range row.Refs {
				switch ref.Type {
				case "purl":
					refConflict = refConflict || (a.PURL != "" && a.PURL != ref.Locator)
					a.PURL = ref.Locator
				case "cpe23Type", "cpe22Type":
					refConflict = refConflict || (a.CPE != "" && a.CPE != ref.Locator)
					a.CPE = ref.Locator
				}
			}
			if refConflict {
				return nil, errors.New("conflicting SPDX component identity")
			}
			out = append(out, component{Asset: a, parentRef: a.ParentID})
		}
	default:
		return nil, errors.New("expected CycloneDX or SPDX 2.3 SBOM JSON")
	}
	return out, nil
}

const maxInput = 64 << 20
const maxExactVersions = 1_000_000

func readInput(path string) ([]byte, string, error) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxInput {
		return nil, "", errors.New("expected a readable local regular file of at most 64 MiB")
	}
	f, err := evidencefile.Open(path)
	if err != nil {
		return nil, "", errors.New("cannot open input")
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(st, current) {
		return nil, "", errors.New("input changed before read")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxInput+1))
	if err != nil || len(b) > maxInput {
		return nil, "", errors.New("input read failed or exceeded 64 MiB")
	}
	sum := sha256.Sum256(b)
	return b, fmt.Sprintf("%x", sum), nil
}

// EvaluateFiles binds the result to the bytes actually read. The caller decides
// whether imported rule and context provenance are appropriate for its assets.
func EvaluateFiles(ctx context.Context, sbom, advisories, contextFile, kevFile string) (Report, error) {
	raw, digest, err := readInput(sbom)
	if err != nil {
		return Report{}, fmt.Errorf("SBOM: %w", err)
	}
	rulesRaw, rulesDigest, err := readInput(advisories)
	if err != nil {
		return Report{}, fmt.Errorf("advisories: %w", err)
	}
	var contextData model.Context
	var contextDigest string
	if contextFile != "" {
		data, checksum, err := readInput(contextFile)
		if err != nil {
			return Report{}, fmt.Errorf("context: %w", err)
		}
		if err := json.Unmarshal(data, &contextData); err != nil || contextData.Mode == "" {
			return Report{}, errors.New("invalid KODA context JSON")
		}
		if err := boundContext(sbom, digest, contextFile, checksum); err != nil {
			return Report{}, err
		}
		contextDigest = checksum
	}
	report, err := evaluate(ctx, raw, rulesRaw, contextData)
	if err == nil && kevFile != "" {
		err = applyKEV(&report, kevFile)
	}
	report.SBOMSHA256, report.AdvisoriesSHA256, report.ContextSHA256 = digest, rulesDigest, contextDigest
	return report, err
}

func boundContext(sbom, digest, contextFile, contextDigest string) error {
	sbomPath, sbomErr := filepath.EvalSymlinks(sbom)
	contextPath, contextErr := filepath.EvalSymlinks(contextFile)
	if sbomErr != nil || contextErr != nil || filepath.Dir(sbomPath) != filepath.Dir(contextPath) || filepath.Base(contextPath) != "context.json" {
		return errors.New("context must be context.json in the same collection result as the SBOM")
	}
	manifest, _, err := readInput(filepath.Join(filepath.Dir(sbomPath), "SHA256SUMS"))
	if err != nil || len(manifest) > 32<<10 {
		return errors.New("collection SHA256SUMS required to bind context to SBOM")
	}
	var bomCount, contextCount int
	for _, line := range strings.Split(string(manifest), "\n") {
		hash, name, ok := strings.Cut(line, "  ")
		if !ok {
			continue
		}
		switch name {
		case filepath.Base(sbomPath):
			if hash != digest {
				return errors.New("collection SBOM hash mismatch")
			}
			bomCount++
		case "context.json":
			if hash != contextDigest {
				return errors.New("collection context hash mismatch")
			}
			contextCount++
		}
	}
	if bomCount != 1 || contextCount != 1 {
		return errors.New("collection SHA256SUMS must identify the SBOM and context exactly once")
	}
	return nil
}

func evaluate(ctx context.Context, raw, rulesRaw []byte, contextData model.Context) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	components, err := parseComponents(raw)
	if err != nil {
		return Report{}, err
	}
	var rules Rules
	var envelope struct {
		Schema   string `json:"schema"`
		Document struct {
			Version string `json:"csaf_version"`
		} `json:"document"`
	}
	_ = json.Unmarshal(rulesRaw, &envelope)
	switch {
	case envelope.Schema == "koda-advisory-rules-v1":
		err = json.Unmarshal(rulesRaw, &rules)
	case envelope.Document.Version != "":
		rules, err = parseCSAF(ctx, rulesRaw)
	default:
		rules, err = parseOSV(ctx, rulesRaw)
	}
	if err != nil {
		return Report{}, fmt.Errorf("invalid advisory input: %w", err)
	}
	if len(rules.Rules) == 0 || len(rules.Rules) > 4096 {
		return Report{}, errors.New("expected koda-advisory-rules-v1 with 1–4096 rules")
	}
	if _, err := time.Parse(time.RFC3339, rules.PublishedAt); err != nil {
		return Report{}, errors.New("advisory publishedAt must use RFC3339")
	}
	now := time.Now().UTC()
	report := Report{Schema: "koda-assessment-v1", AdvisoriesAt: rules.PublishedAt, AnalyzedAt: now.Format(time.RFC3339),
		ComponentCount: len(components), Findings: []Finding{}}
	if len(components) > 10_000_000/len(rules.Rules) {
		return Report{}, errors.New("assessment exceeds 10 million rule comparisons")
	}
	remainingVersions := maxExactVersions
	remainingVersionOutput := maxInput
	byRef := map[string]model.Asset{}
	for _, c := range components {
		if c.ID != "" {
			if _, found := byRef[c.ID]; found {
				return Report{}, errors.New("duplicate SBOM component reference")
			}
			byRef[c.ID] = c.Asset
		}
	}
	restart := map[string]bool{}
	for _, proc := range contextData.ProcessLinks {
		for _, file := range proc.RuntimeFiles {
			if file.State == "restart_review" && file.PURL != "" {
				restart[file.PURL] = true
			}
		}
	}
	for i, rule := range rules.Rules {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		remainingVersions -= len(rule.AffectedVersions) + len(rule.FixedVersions)
		if remainingVersions < 0 {
			return Report{}, errors.New("assessment exceeds 1 million exact advisory versions")
		}
		constraint, err := validateRule(rule)
		if err != nil {
			return Report{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		versions, err := indexVersions(ctx, rule)
		if err != nil {
			return Report{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		report.RulesEvaluated++
		start := len(report.Findings)
		if rule.Setting != nil {
			report.Findings = append(report.Findings, settingFinding(rule, contextData))
		} else {
			for _, c := range components {
				if err := ctx.Err(); err != nil {
					return Report{}, err
				}
				if matches(*rule.Component, c.Asset, byRef[c.parentRef]) {
					// Each finding repeats the rule's fixed versions in the output.
					remainingVersionOutput -= versions.fixedBytes
					if remainingVersionOutput < 0 {
						return Report{}, errors.New("assessment exceeds fixed-version result size limit")
					}
					if len(report.Findings) == 100_000 {
						return Report{}, errors.New("assessment exceeds 100000 findings")
					}
					report.Findings = append(report.Findings, versionFinding(rule, c.Asset, constraint, versions, restart[c.PURL], now))
				}
			}
		}
		if len(report.Findings) > 100_000 {
			return Report{}, errors.New("assessment exceeds 100000 findings")
		}
		if start == len(report.Findings) {
			report.UnmatchedRules++
		}
	}
	slices.SortStableFunc(report.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.ComponentRef, b.ComponentRef), cmp.Compare(a.ComponentName, b.ComponentName), cmp.Compare(a.ObservedVersion, b.ObservedVersion))
	})
	return report, nil
}

func validateRule(rule Rule) (*semver.Constraints, error) {
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Source) == "" || (rule.Component == nil) == (rule.Setting == nil) {
		return nil, errors.New("require ID, source and exactly one selector")
	}
	if rule.Setting != nil {
		if len(rule.AffectedVersions)+len(rule.FixedVersions) > 0 || rule.AffectedSemver != "" || rule.SupportEndsAt != "" {
			return nil, errors.New("settings rules cannot contain version or support fields")
		}
		if rule.Setting.Product == "" || rule.Setting.Name == "" || rule.Setting.Equals == "" {
			return nil, errors.New("require product, name and expected setting")
		}
		return nil, nil
	}
	s := rule.Component
	if s.PURL == "" && s.CPE == "" && (s.Kind == "" || s.Name == "" || (s.Vendor == "" && s.Model == "" && len(s.Properties) == 0)) {
		return nil, errors.New("require PURL, CPE or kind/name and device identity fields")
	}
	if s.PURL != "" {
		p, err := packageurl.FromString(s.PURL)
		if err != nil || p.Version != "" {
			return nil, errors.New("rule PURL must be a valid versionless package URL")
		}
		switch p.Type {
		case "rpm", "deb", "apk":
			if rule.AffectedSemver != "" || len(p.Qualifiers) == 0 {
				return nil, errors.New("distribution packages require exact versions and ecosystem qualifiers")
			}
			qualifiers := p.Qualifiers.Map()
			if qualifiers["distro"] == "" && qualifiers["distro_id"] == "" {
				return nil, errors.New("distribution package selector requires a distro qualifier")
			}
		}
	}
	if len(rule.AffectedVersions)+len(rule.FixedVersions) == 0 && rule.AffectedSemver == "" {
		return nil, errors.New("supply exact versions or an affected SemVer constraint")
	}
	if rule.SupportEndsAt != "" {
		if _, err := time.Parse(time.DateOnly, rule.SupportEndsAt); err != nil || len(rule.FixedVersions) > 0 {
			return nil, errors.New("support rules require a YYYY-MM-DD end date and affected versions without fixed versions")
		}
	}
	if rule.AffectedSemver != "" {
		if s.PURL == "" || s.Kind == "firmware" || s.Kind == "device" || s.Kind == "operating-system" {
			return nil, errors.New("SemVer constraints are limited to package ecosystem selectors")
		}
		return semver.NewConstraint(rule.AffectedSemver)
	}
	return nil, nil
}

type exactVersions struct {
	affected   map[string]bool
	fixed      map[string]bool
	fixedBytes int
}

func indexVersions(ctx context.Context, rule Rule) (exactVersions, error) {
	v := exactVersions{affected: make(map[string]bool), fixed: make(map[string]bool)}
	for _, version := range rule.FixedVersions {
		if err := ctx.Err(); err != nil {
			return v, err
		}
		if version == "" {
			return v, errors.New("empty fixed version")
		}
		v.fixed[version] = true
		encoded, _ := json.Marshal(version)
		v.fixedBytes += len(encoded) + 1
	}
	for _, version := range rule.AffectedVersions {
		if err := ctx.Err(); err != nil {
			return v, err
		}
		if version == "" || v.fixed[version] {
			return v, errors.New("empty or overlapping version rules")
		}
		v.affected[version] = true
	}
	return v, nil
}

// RPM package versions may include an epoch prefix that their PURL stores in
// a qualifier. An absent epoch is equivalent to zero, as for Debian.
func splitEpoch(version string) (uint64, string, bool) {
	epoch, rest, found := strings.Cut(version, ":")
	if !found {
		return 0, version, version != ""
	}
	number, err := strconv.ParseUint(epoch, 10, 64)
	return number, rest, err == nil && rest != ""
}

func versionIdentityConsistent(a model.Asset) bool {
	if a.PURL == "" {
		return true
	}
	p, err := packageurl.FromString(a.PURL)
	if err != nil {
		return false
	}
	if p.Version == "" {
		return true
	}
	switch p.Type {
	case "rpm", "deb":
		observedEpoch, observed, validObserved := splitEpoch(a.Version)
		purlEpoch, purlVersion, validPURL := splitEpoch(p.Version)
		if p.Type == "rpm" {
			if qualifier := p.Qualifiers.Map()["epoch"]; qualifier != "" {
				n, err := strconv.ParseUint(qualifier, 10, 64)
				if err != nil || (strings.Contains(p.Version, ":") && n != purlEpoch) {
					return false
				}
				purlEpoch = n
			}
		}
		return validObserved && validPURL && observed == purlVersion && observedEpoch == purlEpoch
	default:
		return a.Version == p.Version
	}
}

func matches(s Selector, a, parent model.Asset) bool {
	if s.PURL != "" {
		want, _ := packageurl.FromString(s.PURL)
		actual, err := packageurl.FromString(a.PURL)
		if err != nil {
			return false
		}
		if actual.Type != want.Type || actual.Namespace != want.Namespace || actual.Name != want.Name {
			return false
		}
		have := actual.Qualifiers.Map()
		for k, v := range want.Qualifiers.Map() {
			if have[k] != v {
				return false
			}
		}
	}
	if (s.CPE != "" && a.CPE != s.CPE) || (s.Kind != "" && a.Kind != s.Kind) || (s.Name != "" && a.Name != s.Name) ||
		(s.Vendor != "" && a.Vendor != s.Vendor && parent.Vendor != s.Vendor) ||
		(s.Model != "" && a.Model != s.Model && parent.Model != s.Model) ||
		(s.Revision != "" && a.Revision != s.Revision && parent.Revision != s.Revision) {
		return false
	}
	for key, value := range s.Properties {
		if strings.HasPrefix(key, "parent.") {
			if parent.Properties[strings.TrimPrefix(key, "parent.")] != value || value == "" {
				return false
			}
		} else if a.Properties[key] != value || value == "" {
			return false
		}
	}
	return true
}

func finding(rule Rule) Finding {
	return Finding{ID: rule.ID, Aliases: rule.Aliases, Source: rule.Source, FixedVersions: rule.FixedVersions, Remediation: rule.Remediation}
}

func versionFinding(rule Rule, a model.Asset, constraint *semver.Constraints, versions exactVersions, restart bool, now time.Time) Finding {
	f := finding(rule)
	f.ComponentRef, f.ComponentName, f.ObservedVersion = a.ID, a.Name, a.Version
	f.Status, f.Evidence = "review_required", "observed version not covered by the supplied rule"
	if a.Version == "" {
		f.Evidence = "component version unavailable"
		return f
	}
	if !versionIdentityConsistent(a) {
		f.Evidence = "component version conflicts with its package URL"
		return f
	}
	affected := versions.affected[a.Version]
	if constraint != nil {
		if v, err := semver.StrictNewVersion(a.Version); err == nil {
			affected = affected || constraint.Check(v)
		}
	}
	if affected {
		f.Status, f.Evidence = "affected_version_observed", "component version matches supplied advisory rule"
		if rule.SupportEndsAt != "" {
			f.SupportEndsAt = rule.SupportEndsAt
			end, _ := time.Parse(time.DateOnly, rule.SupportEndsAt)
			f.Status, f.Evidence = "support_end_scheduled", "observed version has a supplied support end date"
			if !now.Before(end.AddDate(0, 0, 1)) {
				f.Status, f.Evidence = "support_expired", "observed version is past the supplied support end date"
			}
		} else if a.Kind == "firmware" && (versions.fixed[a.Properties["stored.fw"]] || versions.fixed[a.Properties["storedVersion"]]) {
			f.Evidence = "affected firmware version observed; a fixed firmware version is stored and activation requires review"
		}
		return f
	}
	if versions.fixed[a.Version] {
		f.Status, f.Evidence = "fixed_version_observed", "component version matches an explicit fixed version"
		if restart {
			f.Status, f.Evidence = "activation_review", "fixed package version observed; process still references a replaced file"
		}
		if a.Kind == "firmware" && !firmwareActive(a) {
			f.Status, f.Evidence = "activation_review", "fixed firmware version observed; activation is not established"
		}
	}
	return f
}

func settingFinding(rule Rule, contextData model.Context) Finding {
	f := finding(rule)
	f.ComponentName = rule.Setting.Product + "/" + rule.Setting.Name
	f.Status, f.Evidence = "review_required", "effective setting unavailable"
	for _, setting := range contextData.Settings {
		if setting.Product != rule.Setting.Product || setting.Name != rule.Setting.Name || setting.State != "observed" {
			continue
		}
		if f.Status != "review_required" && f.ObservedVersion != setting.Value {
			f.Status, f.Evidence, f.ObservedVersion = "review_required", "conflicting effective settings observed", ""
			return f
		}
		f.ObservedVersion = setting.Value
		f.Status, f.Evidence = "setting_matches", "effective setting matches supplied rule"
		if setting.Value != rule.Setting.Equals {
			f.Status, f.Evidence = "setting_mismatch", "effective setting differs from supplied rule"
		}
	}
	return f
}

func firmwareActive(a model.Asset) bool {
	state := strings.ToLower(a.Properties["applicationState"])
	if state != "" && state != "unknown" {
		return state == "active" || state == "running"
	}
	return a.Version == a.Properties["running.fw"] || a.Version == a.Properties["runningVersion"] ||
		a.Properties["state"] == "running" || a.Properties["state"] == "active"
}
