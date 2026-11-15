package reconcile

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	packageurl "github.com/anchore/packageurl-go"
)

// Comparison groups only identical versioned package coordinates together.
// Counts represent source entries, not unique deployment locations.
type Comparison struct {
	Common       []IdentityCount   `json:"common"`
	ObservedOnly []IdentityCount   `json:"observedOnly"`
	SupplierOnly []IdentityCount   `json:"supplierOnly"`
	Unresolved   []UnresolvedCount `json:"unresolved"`
}

type IdentityCount struct {
	PURL          string `json:"purl"`
	ObservedCount int    `json:"observedCount"`
	SupplierCount int    `json:"supplierCount"`
}

type UnresolvedCount struct {
	Reason        string `json:"reason"`
	ObservedCount int    `json:"observedCount"`
	SupplierCount int    `json:"supplierCount"`
}

func Compare(observed, supplier []Component) Comparison {
	identities := map[string]IdentityCount{}
	unresolved := map[string]UnresolvedCount{}
	for _, side := range []struct {
		rows     []Component
		observed bool
	}{{observed, true}, {supplier, false}} {
		for _, component := range side.rows {
			key, reason := comparableIdentity(component)
			if reason != "" {
				item := unresolved[reason]
				item.Reason = reason
				if side.observed {
					item.ObservedCount++
				} else {
					item.SupplierCount++
				}
				unresolved[reason] = item
				continue
			}
			item := identities[key]
			item.PURL = key
			if side.observed {
				item.ObservedCount++
			} else {
				item.SupplierCount++
			}
			identities[key] = item
		}
	}

	result := Comparison{
		Common: []IdentityCount{}, ObservedOnly: []IdentityCount{},
		SupplierOnly: []IdentityCount{}, Unresolved: []UnresolvedCount{},
	}
	for _, item := range identities {
		switch {
		case item.ObservedCount == 0:
			result.SupplierOnly = append(result.SupplierOnly, item)
		case item.SupplierCount == 0:
			result.ObservedOnly = append(result.ObservedOnly, item)
		default:
			result.Common = append(result.Common, item)
		}
	}
	for _, group := range [][]IdentityCount{result.Common, result.ObservedOnly, result.SupplierOnly} {
		sort.Slice(group, func(i, j int) bool { return group[i].PURL < group[j].PURL })
	}
	for _, item := range unresolved {
		result.Unresolved = append(result.Unresolved, item)
	}
	sort.Slice(result.Unresolved, func(i, j int) bool {
		return result.Unresolved[i].Reason < result.Unresolved[j].Reason
	})
	return result
}

const maxComparablePURL = 2048

var (
	coordinatePart = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$`)
	versionToken   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:!~-]{0,127}$`)
	qualifierToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~@-]{0,127}$`)
	digit          = regexp.MustCompile(`[0-9]`)
	pythonNameSep  = regexp.MustCompile(`[-_.]+`)
)

func comparableIdentity(component Component) (string, string) {
	if component.IdentityIssue != "" {
		switch component.IdentityIssue {
		case "invalid_purl", "conflicting_purl", "version_conflict", "identity_field_invalid":
			return "", component.IdentityIssue
		default:
			return "", "identity_field_invalid"
		}
	}
	raw := strings.TrimSpace(component.PURL)
	if raw == "" {
		return "", "missing_purl"
	}
	if len(raw) > maxComparablePURL {
		return "", "invalid_purl"
	}
	purl, err := packageurl.FromString(raw)
	if err != nil {
		return "", "invalid_purl"
	}
	if strings.Contains(raw, "#") || !comparableQualifiers(raw, purl.Qualifiers) {
		return "", "unsupported_purl_detail"
	}
	if !concreteVersion(purl.Type, purl.Version) {
		return "", "nonconcrete_version"
	}
	if version := strings.TrimSpace(component.Version); version != "" && version != purl.Version {
		return "", "version_conflict"
	}

	namespace, name, ok := rawCoordinates(raw)
	if !ok || !coordinatePart.MatchString(name) || !validNamespace(purl.Type, namespace) {
		return "", "invalid_purl"
	}
	switch purl.Type {
	case packageurl.TypeNPM:
		// This packageurl-go version lowercases historical case-sensitive npm
		// names and scopes. Retain their source case for exact comparison.
		purl.Namespace, purl.Name = namespace, name
	case packageurl.TypePyPi:
		purl.Name = pythonNameSep.ReplaceAllString(strings.ToLower(name), "-")
	}
	return purl.ToString(), ""
}

func rawCoordinates(raw string) (namespace, name string, valid bool) {
	path, _, _ := strings.Cut(raw, "?")
	path = strings.TrimLeft(path[len("pkg:"):], "/")
	_, path, ok := strings.Cut(path, "/")
	if !ok {
		return "", "", false
	}
	segments := strings.Split(path, "/")
	last := len(segments) - 1
	if at := strings.LastIndexByte(segments[last], '@'); at >= 0 {
		segments[last] = segments[last][:at]
	}
	for i, segment := range segments {
		value, err := url.PathUnescape(segment)
		if err != nil || value == "" || strings.ContainsAny(value, "/\\") {
			return "", "", false
		}
		segments[i] = value
	}
	return strings.Join(segments[:last], "/"), segments[last], true
}

func validNamespace(ecosystem, namespace string) bool {
	switch ecosystem {
	case packageurl.TypeMaven:
		return coordinatePart.MatchString(namespace)
	case packageurl.TypeNPM:
		return namespace == "" || (strings.HasPrefix(namespace, "@") && coordinatePart.MatchString(namespace[1:]))
	case packageurl.TypePyPi:
		return namespace == ""
	}
	if namespace == "" {
		return true
	}
	for _, segment := range strings.Split(namespace, "/") {
		if !coordinatePart.MatchString(segment) {
			return false
		}
	}
	return true
}

func concreteVersion(ecosystem, version string) bool {
	if !versionToken.MatchString(version) || !digit.MatchString(version) {
		return false
	}
	if ecosystem == packageurl.TypeNPM {
		_, err := semver.StrictNewVersion(version)
		return err == nil
	}
	switch value := strings.ToLower(version); {
	case strings.HasSuffix(value, "-snapshot"):
		return false
	case strings.HasSuffix(value, ".js"), strings.HasSuffix(value, ".jar"), strings.HasSuffix(value, ".war"),
		strings.HasSuffix(value, ".ear"), strings.HasSuffix(value, ".zip"), strings.HasSuffix(value, ".tgz"),
		strings.HasSuffix(value, ".tar.gz"):
		return false
	}
	return true
}

func comparableQualifiers(raw string, qualifiers packageurl.Qualifiers) bool {
	_, query, exists := strings.Cut(raw, "?")
	if !exists {
		return len(qualifiers) == 0
	}
	// The parser can drop empty values. Require a one-to-one mapping so
	// malformed or extra qualifiers cannot collapse to an unqualified match.
	if len(qualifiers) != strings.Count(query, "&")+1 {
		return false
	}
	for _, qualifier := range qualifiers {
		switch qualifier.Key {
		case "arch", "classifier", "distro", "distro_id", "distro_version_id", "epoch",
			"extension", "libc", "os", "packaging", "platform", "type", "upstream":
			if !qualifierToken.MatchString(qualifier.Value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
