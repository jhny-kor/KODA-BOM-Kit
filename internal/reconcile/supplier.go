package reconcile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	packageurl "github.com/anchore/packageurl-go"
)

const (
	MaxSupplierBytes    = 32 << 20
	maxComponents       = 50_000
	maxComponentDepth   = 32
	maxJSONDepth        = 128
	maxIdentityTextSize = 1024
	maxPURLSize         = 4096
)

var (
	ErrSupplierRead      = errors.New("supplier SBOM could not be read")
	ErrSupplierSize      = errors.New("supplier SBOM exceeds its byte limit")
	ErrSupplierJSON      = errors.New("supplier SBOM is invalid JSON, contains ambiguous fields, or exceeds its structure limit")
	ErrSupplierFormat    = errors.New("supplier SBOM must be CycloneDX 1.4–1.7 JSON or SPDX 2.3 JSON")
	ErrSupplierSubject   = errors.New("supplier SBOM must declare one unambiguous subject SHA-256")
	ErrSupplierInventory = errors.New("supplier SBOM inventory has invalid identifiers or exceeds its component limits")
)

// Component is an internal inventory input. Raw PURLs may carry private data;
// callers must apply reconciliation's output policy before publishing.
type Component struct {
	Name, Version, PURL string
	IdentityIssue       string
}

type Supplier struct {
	Format, SHA256 string
	Components     []Component
}

// ReadSupplier consumes one bounded JSON BOM and extracts its declared subject
// hash. The caller must compare it with the SHA-256 of the deployed artifact.
func ReadSupplier(r io.Reader) (Supplier, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxSupplierBytes+1))
	if err != nil {
		return Supplier{}, ErrSupplierRead
	}
	if len(raw) > MaxSupplierBytes {
		return Supplier{}, ErrSupplierSize
	}
	if err := validateSupplierJSON(raw); err != nil {
		return Supplier{}, err
	}
	var header struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		SPDXVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return Supplier{}, ErrSupplierJSON
	}
	switch {
	case header.BOMFormat == "CycloneDX" && header.SPDXVersion == "":
		switch header.SpecVersion {
		case "1.4", "1.5", "1.6", "1.7":
			return readCycloneDXSupplier(raw)
		}
	case header.BOMFormat == "" && header.SPDXVersion == "SPDX-2.3":
		return readSPDXSupplier(raw)
	}
	return Supplier{}, ErrSupplierFormat
}

type cyclonedxComponent struct {
	Ref        string                `json:"bom-ref"`
	Name       string                `json:"name"`
	Version    string                `json:"version"`
	PURL       string                `json:"purl"`
	Components []*cyclonedxComponent `json:"components"`
	Hashes     []struct {
		Algorithm string `json:"alg"`
		Content   string `json:"content"`
	} `json:"hashes"`
}

func readCycloneDXSupplier(raw []byte) (Supplier, error) {
	var bom struct {
		Metadata struct {
			Component *cyclonedxComponent `json:"component"`
		} `json:"metadata"`
		Components []*cyclonedxComponent `json:"components"`
	}
	if json.Unmarshal(raw, &bom) != nil {
		return Supplier{}, ErrSupplierJSON
	}
	subject := bom.Metadata.Component
	if subject == nil || safeIdentityText(subject.Name) == "" {
		return Supplier{}, ErrSupplierSubject
	}
	var digests []string
	for _, hash := range subject.Hashes {
		if hash.Algorithm == "SHA-256" {
			digests = append(digests, hash.Content)
		}
	}
	digest, err := subjectSHA256(digests)
	if err != nil {
		return Supplier{}, err
	}
	out := Supplier{Format: "cyclonedx-json", SHA256: digest, Components: []Component{}}
	refs := map[string]bool{}
	if subject.Ref != "" {
		refs[subject.Ref] = true
	}
	var appendComponents func([]*cyclonedxComponent, int) error
	appendComponents = func(items []*cyclonedxComponent, depth int) error {
		if len(items) > 0 && depth > maxComponentDepth {
			return ErrSupplierInventory
		}
		for _, item := range items {
			if item == nil || len(out.Components) >= maxComponents || item.Ref != "" && refs[item.Ref] {
				return ErrSupplierInventory
			}
			if item.Ref != "" {
				refs[item.Ref] = true
			}
			out.Components = append(out.Components, supplierComponent(item.Name, item.Version, item.PURL, ""))
			if err := appendComponents(item.Components, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := appendComponents(subject.Components, 1); err != nil {
		return Supplier{}, err
	}
	if err := appendComponents(bom.Components, 1); err != nil {
		return Supplier{}, err
	}
	return out, nil
}

type spdxSupplierPackage struct {
	LicenseDeclared  string `json:"licenseDeclared"`
	LicenseConcluded string `json:"licenseConcluded"`
	ID               string `json:"SPDXID"`
	Name             string `json:"name"`
	Version          string `json:"versionInfo"`
	Checksum         []struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"checksumValue"`
	} `json:"checksums"`
	References []struct {
		Category string `json:"referenceCategory"`
		Type     string `json:"referenceType"`
		Locator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

const spdxDocumentID = "SPDXRef-DOCUMENT"

var spdxPackageID = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)

func validSPDXPackageID(id string) bool {
	return len(id) <= maxIdentityTextSize && spdxPackageID.MatchString(id)
}

func readSPDXSupplier(raw []byte) (Supplier, error) {
	var bom struct {
		ID            string                 `json:"SPDXID"`
		Describes     []string               `json:"documentDescribes"`
		Packages      []*spdxSupplierPackage `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			Type string `json:"relationshipType"`
			To   string `json:"relatedSpdxElement"`
		} `json:"relationships"`
	}
	if json.Unmarshal(raw, &bom) != nil {
		return Supplier{}, ErrSupplierJSON
	}
	if bom.ID != spdxDocumentID {
		return Supplier{}, ErrSupplierSubject
	}
	subjectID := ""
	describe := func(id string) error {
		if !validSPDXPackageID(id) || id == spdxDocumentID || subjectID != "" && subjectID != id {
			return ErrSupplierSubject
		}
		subjectID = id
		return nil
	}
	for _, id := range bom.Describes {
		if err := describe(id); err != nil {
			return Supplier{}, err
		}
	}
	for _, relationship := range bom.Relationships {
		var id string
		switch {
		case relationship.Type == "DESCRIBES" && relationship.From == spdxDocumentID:
			id = relationship.To
		case relationship.Type == "DESCRIBED_BY" && relationship.To == spdxDocumentID:
			id = relationship.From
		default:
			continue
		}
		if err := describe(id); err != nil {
			return Supplier{}, err
		}
	}
	if subjectID == "" {
		return Supplier{}, ErrSupplierSubject
	}
	if len(bom.Packages) > maxComponents+1 {
		return Supplier{}, ErrSupplierInventory
	}
	out := Supplier{Format: "spdx-json", Components: []Component{}}
	refs := map[string]bool{}
	for _, item := range bom.Packages {
		if item == nil || item.ID == spdxDocumentID || !validSPDXPackageID(item.ID) || refs[item.ID] {
			return Supplier{}, ErrSupplierInventory
		}
		refs[item.ID] = true
		if item.ID == subjectID {
			if safeIdentityText(item.Name) == "" {
				return Supplier{}, ErrSupplierSubject
			}
			var digests []string
			for _, hash := range item.Checksum {
				if hash.Algorithm == "SHA256" {
					digests = append(digests, hash.Value)
				}
			}
			digest, err := subjectSHA256(digests)
			if err != nil {
				return Supplier{}, err
			}
			out.SHA256 = digest
			continue
		}
		out.Components = append(out.Components, item.component())
	}
	if out.SHA256 == "" {
		return Supplier{}, ErrSupplierSubject
	}
	return out, nil
}

func (item spdxSupplierPackage) component() Component {
	var purl, issue string
	for _, ref := range item.References {
		if !strings.EqualFold(ref.Type, "purl") {
			continue
		}
		value := strings.TrimSpace(ref.Locator)
		if ref.Category != "PACKAGE-MANAGER" || ref.Type != "purl" || value == "" {
			issue = "invalid_purl"
			continue
		}
		if purl != "" && value != purl {
			issue = "conflicting_purl"
			break
		}
		purl = value
	}
	return supplierComponent(item.Name, item.Version, purl, issue)
}

func supplierComponent(name, version, purl, issue string) Component {
	component := Component{Name: safeIdentityText(name), Version: safeIdentityText(version), IdentityIssue: issue}
	if component.Name == "" || version != "" && component.Version == "" {
		component.IdentityIssue = "identity_field_invalid"
	}
	if component.IdentityIssue != "" || purl == "" {
		return component
	}
	purl = strings.TrimSpace(purl)
	if len(purl) > maxPURLSize || strings.IndexFunc(purl, unicode.IsSpace) >= 0 {
		component.IdentityIssue = "invalid_purl"
		return component
	}
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		component.IdentityIssue = "invalid_purl"
		return component
	}
	if component.Version != "" && parsed.Version != "" && component.Version != parsed.Version {
		component.IdentityIssue = "version_conflict"
		return component
	}
	if component.Version == "" && parsed.Version != "" {
		component.Version = safeIdentityText(parsed.Version)
		if component.Version == "" {
			component.IdentityIssue = "identity_field_invalid"
			return component
		}
	}
	component.PURL = purl
	return component
}

func safeIdentityText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxIdentityTextSize || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) >= 0 {
		return ""
	}
	return value
}

func subjectSHA256(values []string) (string, error) {
	var digest string
	for _, value := range values {
		if len(value) != 64 {
			return "", ErrSupplierSubject
		}
		if _, err := hex.DecodeString(value); err != nil {
			return "", ErrSupplierSubject
		}
		value = strings.ToLower(value)
		if digest != "" && value != digest {
			return "", ErrSupplierSubject
		}
		digest = value
	}
	if digest == "" {
		return "", ErrSupplierSubject
	}
	return digest, nil
}

// encoding/json accepts duplicate keys and matches struct names ignoring case.
// Check the whole object before unmarshalling any field used as evidence.
func validateSupplierJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrSupplierJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrSupplierJSON
	}
	if err := validateJSONContainer(decoder, '{', 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrSupplierJSON
	}
	return nil
}

func validateJSONContainer(decoder *json.Decoder, opening json.Delim, depth int) error {
	if depth > maxJSONDepth {
		return ErrSupplierJSON
	}
	var keys map[string]bool
	if opening == '{' {
		keys = make(map[string]bool)
	}
	for decoder.More() {
		if keys != nil {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return ErrSupplierJSON
			}
			key = strings.Map(foldJSONRune, key)
			if keys[key] {
				return ErrSupplierJSON
			}
			keys[key] = true
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrSupplierJSON
		}
		if delim, ok := token.(json.Delim); ok {
			if delim != '{' && delim != '[' {
				return ErrSupplierJSON
			}
			if err := validateJSONContainer(decoder, delim, depth+1); err != nil {
				return err
			}
		}
	}
	closing := json.Delim(']')
	if opening == '{' {
		closing = '}'
	}
	token, err := decoder.Token()
	if err != nil || token != closing {
		return ErrSupplierJSON
	}
	return nil
}

func foldJSONRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}
		r = next
	}
}
