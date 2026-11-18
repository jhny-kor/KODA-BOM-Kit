package collect

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

const (
	IntegrityModifiedProperty = "koda:integrity:modified"
	IntegrityMissingProperty  = "koda:integrity:missing"
	maxIntegrityFindings      = 1000
	maxIntegrityFileBytes     = 512 << 20
	// DefaultIntegrityBudget bounds hashing on large servers.
	DefaultIntegrityBudget = int64(8) << 30
)

// IntegrityFinding is one installed executable or library whose content no
// longer matches the digest its package database recorded.
type IntegrityFinding struct {
	Path    string `json:"path"`
	Package string `json:"package"`
	PURL    string `json:"purl,omitempty"`
	State   string `json:"state"` // modified or missing
	id      artifact.ID
}

// IntegrityResult summarises a package file verification, like `rpm -V` or
// `debsums` restricted to executables and shared libraries.
type IntegrityResult struct {
	Status        string             `json:"status"` // completed, partial, not_applicable
	CheckedFiles  int                `json:"checkedFiles"`
	ModifiedFiles int                `json:"modifiedFiles"`
	MissingFiles  int                `json:"missingFiles"`
	SkippedFiles  int                `json:"skippedFiles"`
	BytesHashed   int64              `json:"bytesHashed"`
	Findings      []IntegrityFinding `json:"findings,omitempty"`
	Limitations   []string           `json:"limitations,omitempty"`
}

type packageFile struct {
	path, algorithm, digest string
}

// packageFiles lists the verifiable executable and library files a package
// database recorded. Configuration, ghost and digest-less entries are skipped:
// they are expected to differ from the packaged content.
func packageFiles(item pkg.Package) []packageFile {
	var files []packageFile
	add := func(p, algorithm, digest string) {
		if digest != "" && isBinaryPath(p) {
			files = append(files, packageFile{p, algorithm, digest})
		}
	}
	switch meta := item.Metadata.(type) {
	case pkg.RpmDBEntry:
		for _, f := range meta.Files {
			if !strings.ContainsAny(f.Flags, "cg") {
				add(f.Path, f.Digest.Algorithm, f.Digest.Value)
			}
		}
	case pkg.DpkgDBEntry:
		for _, f := range meta.Files {
			if f.Digest != nil && !f.IsConfigFile {
				add(f.Path, f.Digest.Algorithm, f.Digest.Value)
			}
		}
	case pkg.ApkDBEntry:
		for _, f := range meta.Files {
			if f.Digest != nil {
				add(f.Path, f.Digest.Algorithm, f.Digest.Value)
			}
		}
	}
	return files
}

func isBinaryPath(p string) bool {
	dir, base := path.Dir(p), path.Base(p)
	for _, part := range strings.Split(dir, "/") {
		if part == "bin" || part == "sbin" || part == "libexec" {
			return true
		}
	}
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func newHash(algorithm string) (hash.Hash, func([]byte) string) {
	hexOf := func(b []byte) string { return hex.EncodeToString(b) }
	switch algorithm {
	case "md5":
		return md5.New(), hexOf
	case "sha1":
		return sha1.New(), hexOf
	case "sha224":
		return sha256.New224(), hexOf
	case "sha256":
		return sha256.New(), hexOf
	case "sha384":
		return sha512.New384(), hexOf
	case "sha512":
		return sha512.New(), hexOf
	case "'Q1'+base64(sha1)":
		return sha1.New(), func(b []byte) string { return "Q1" + base64.StdEncoding.EncodeToString(b) }
	}
	return nil, nil
}

// VerifyPackageFiles compares installed executables and libraries with their
// package database digests. Only files in the scan plan are read, so user
// exclusions and mount boundaries apply. Run it before Scrub: package file
// lists are part of the catalog metadata.
func VerifyPackageFiles(ctx context.Context, inventory *sbom.SBOM, plan localfs.Plan, budget int64) IntegrityResult {
	result := IntegrityResult{Status: "not_applicable"}
	if inventory == nil || inventory.Artifacts.Packages == nil {
		return result
	}
	root, err := os.OpenRoot(plan.Root)
	if err != nil {
		return result
	}
	defer root.Close()
	present := make(map[string]bool, len(plan.Paths))
	for _, p := range plan.Paths {
		present[p] = true
	}
	merged := usrMerged(plan.Root)
	seen := map[string]bool{}
	partial := false
	for _, item := range inventory.Artifacts.Packages.Sorted() {
		for _, f := range packageFiles(item) {
			if ctx.Err() != nil {
				result.Status = "partial"
				return result
			}
			name := canonicalPath(f.path, merged)
			if seen[name] {
				continue // shared by several packages; checked once
			}
			seen[name] = true
			finding := IntegrityFinding{Path: name, Package: item.Name, id: item.ID()}
			if !present[name] {
				if plan.ExcludesPath(name) {
					continue
				}
				if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
					finding.State = "missing"
					result.MissingFiles++
					result.add(finding)
				}
				continue
			}
			h, encode := newHash(f.algorithm)
			if h == nil || budget <= 0 {
				result.SkippedFiles++
				partial = partial || budget <= 0
				continue
			}
			file, st, err := localfs.OpenRegularEvidence(root, name)
			if err != nil || st.Size() > maxIntegrityFileBytes {
				if file != nil {
					file.Close()
				}
				result.SkippedFiles++
				continue
			}
			n, err := io.Copy(h, io.LimitReader(file, maxIntegrityFileBytes))
			file.Close()
			budget -= n
			result.BytesHashed += n
			if err != nil {
				result.SkippedFiles++
				continue
			}
			result.CheckedFiles++
			if encode(h.Sum(nil)) != f.digest {
				finding.State = "modified"
				result.ModifiedFiles++
				result.add(finding)
			}
		}
	}
	result.Status = "completed"
	if partial {
		result.Status = "partial"
		result.Limitations = append(result.Limitations, "hashing budget reached; remaining files were not verified")
	}
	if result.CheckedFiles+result.MissingFiles == 0 {
		result.Status = "not_applicable"
	}
	result.Limitations = append(result.Limitations,
		"Only executables and shared libraries recorded with a digest by RPM, dpkg or apk are verified",
		"Prelinked binaries (older Red Hat releases) differ from their package digest without being replaced",
	)
	return result
}

func (r *IntegrityResult) add(f IntegrityFinding) {
	if len(r.Findings) < maxIntegrityFindings {
		r.Findings = append(r.Findings, f)
	}
}

// ResolvePURLs fills each finding's PURL from the inventory after Scrub, which
// may rewrite PURLs but keeps package IDs.
func (r *IntegrityResult) ResolvePURLs(inventory *sbom.SBOM) {
	for i := range r.Findings {
		if item := inventory.Artifacts.Packages.Package(r.Findings[i].id); item != nil {
			r.Findings[i].PURL = item.PURL
		}
	}
}

// Properties returns per-component SBOM properties for the findings.
func (r IntegrityResult) Properties() ComponentProperties {
	out := ComponentProperties{}
	for _, f := range r.Findings {
		name := IntegrityModifiedProperty
		if f.State == "missing" {
			name = IntegrityMissingProperty
		}
		if f.PURL != "" && !slices.Contains(out[f.PURL], [2]string{name, "/" + f.Path}) {
			out[f.PURL] = append(out[f.PURL], [2]string{name, "/" + f.Path})
		}
	}
	return out
}
