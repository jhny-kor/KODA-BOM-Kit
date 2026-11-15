package staticjs

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

const fancytreeName = "jquery.fancytree"

//go:embed fancytree_fingerprints.tsv
var fancytreeFingerprintData string

var fancytreeFingerprintIndex = sync.OnceValue(func() fingerprintIndex {
	index, err := parseFingerprintIndex(fancytreeFingerprintData)
	if err != nil {
		panic(err) // The index ships with the binary and is checked by tests.
	}
	return index
})

type fingerprintIndex map[[sha256.Size]byte][]string

// Fingerprint links a versioned package to the exact deployment file that
// matched a release. The location is also emitted in the standard SBOMs.
type Fingerprint struct {
	Path   string `json:"path"`
	PURL   string `json:"purl"`
	SHA256 string `json:"sha256"`
}

func FingerprintCatalogSHA256() string {
	digest := sha256.Sum256([]byte(fancytreeFingerprintData))
	return hex.EncodeToString(digest[:])
}

var fingerprintVersion = regexp.MustCompile("^" + versionPattern + "$")

func parseFingerprintIndex(data string) (fingerprintIndex, error) {
	index := fingerprintIndex{}
	previous := ""
	for line := range strings.SplitSeq(data, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		digest, version, ok := strings.Cut(line, "\t")
		if !ok || line <= previous || len(digest) != sha256.Size*2 || len(version) > 80 || !fingerprintVersion.MatchString(version) {
			return nil, fmt.Errorf("invalid or unsorted Fancytree fingerprint row")
		}
		var key [sha256.Size]byte
		if _, err := hex.Decode(key[:], []byte(digest)); err != nil || strings.ToLower(digest) != digest {
			return nil, fmt.Errorf("invalid Fancytree fingerprint digest")
		}
		index[key] = append(index[key], version)
		previous = line
	}
	if len(index) == 0 {
		return nil, fmt.Errorf("empty Fancytree fingerprint index")
	}
	return index, nil
}

// An exact file with multiple published versions is ambiguous. A banner in
// the same bytes cannot distinguish those versions.
func (c *collector) applyFingerprint(buf []byte, rel string, identities []identity) ([]identity, string, bool) {
	digest := sha256.Sum256(buf)
	versions := c.fingerprints[digest]
	if len(versions) == 0 {
		return identities, "", false
	}
	if len(versions) > 1 {
		candidates := strings.Join(versions[:min(8, len(versions))], ", ")
		if len(versions) > 8 {
			candidates += fmt.Sprintf(" and %d more", len(versions)-8)
		}
		c.issue(rel, "static_js_fingerprint_ambiguous", "the exact JavaScript file occurs in multiple Fancytree releases: "+candidates)
		return removeFancytreeIdentities(identities), "", true
	}
	expected := identity{name: fancytreeName, version: versions[0]}
	for _, candidate := range identities {
		if candidate.name == fancytreeName && candidate != expected {
			c.issue(rel, "static_js_fingerprint_conflict", "Fancytree file hash and content identify different versions")
			return removeFancytreeIdentities(identities), "", true
		}
	}
	if !slices.Contains(identities, expected) {
		identities = append([]identity{expected}, identities...)
	}
	return identities, hex.EncodeToString(digest[:]), true
}

func removeFancytreeIdentities(identities []identity) []identity {
	kept := identities[:0]
	for _, item := range identities {
		if item.name != fancytreeName {
			kept = append(kept, item)
		}
	}
	return kept
}
