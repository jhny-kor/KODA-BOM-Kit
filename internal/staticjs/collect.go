// Package staticjs identifies browser libraries in deployed files and web archives.
package staticjs

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	packageurl "github.com/anchore/packageurl-go"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

const (
	Collector = "koda-static-javascript"

	probeBytes        = 512 << 10
	totalProbeBytes   = 512 << 20
	maxProbes         = 100_000
	maxReportedIssues = 500
	maxOccurrences    = 200_000
)

type Component struct {
	Name, Version, PURL string
	Locations           []string
	Fingerprints        []Fingerprint
}

type collector struct {
	ctx               context.Context
	plan              localfs.Plan
	root              *os.Root
	components        map[string]*Component
	issues            []model.Issue
	suppressed        int64
	bytes             int64
	indexBytes        int64
	nestedBytes       int64
	archiveReadBudget int64
	probes            int
	occurrences       int
	fingerprints      fingerprintIndex
}

// Collect uses only the root-relative regular files admitted by preflight.
// Archive paths are observed in place. It never extracts or executes files.
func Collect(ctx context.Context, plan localfs.Plan) ([]Component, []model.Issue) {
	c := collector{ctx: ctx, plan: plan, components: make(map[string]*Component), archiveReadBudget: totalArchiveReads, fingerprints: fancytreeFingerprintIndex()}
	dir, err := plan.OpenRoot()
	if err != nil {
		c.issue("", "static_js_root_unavailable", "JavaScript scan root could not be opened")
		return nil, c.issues
	}
	defer dir.Close()
	c.root = dir
	c.scanPaths(plan.Paths, false)
	c.scanPaths(plan.Paths, true)
	switch {
	case ctx.Err() != nil:
		c.issue("", "static_js_cancelled", "JavaScript collection was cancelled")
	case c.probes >= maxProbes || c.bytes >= totalProbeBytes || c.occurrences >= maxOccurrences:
		c.issue("", "static_js_scan_limit", "JavaScript collection reached its total probe limit")
	}
	if c.suppressed > 0 {
		c.issues = append(c.issues, model.Issue{Collector: Collector, Status: "incomplete", Code: "static_js_issue_limit",
			Message: "additional JavaScript collection issues were omitted", Observed: c.suppressed})
	}
	out := make([]Component, 0, len(c.components))
	for _, component := range c.components {
		slices.Sort(component.Locations)
		component.Locations = slices.Compact(component.Locations)
		sort.Slice(component.Fingerprints, func(i, j int) bool { return component.Fingerprints[i].Path < component.Fingerprints[j].Path })
		component.Fingerprints = slices.Compact(component.Fingerprints)
		out = append(out, *component)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out, c.issues
}

func (c *collector) scanPaths(paths []string, jars bool) {
	// Prefer loose scripts and web deployment artifacts over a large tree of
	// standalone JARs, most of which have no web resources.
	for _, rel := range paths {
		if c.stopped() {
			break
		}
		kind := archiveKind(rel)
		script := isScript(rel)
		if (!script && kind == "") || (kind == ".jar") != jars {
			continue
		}
		if !safePath(rel) {
			c.issue("", "static_js_invalid_path", "rejected an invalid root-relative evidence path")
			continue
		}
		c.scanFile(rel, kind)
	}
}

func (c *collector) stopped() bool {
	return c.ctx.Err() != nil || c.probes >= maxProbes || c.bytes >= totalProbeBytes || c.occurrences >= maxOccurrences
}

func (c *collector) issue(rel, code, message string) {
	if len(c.issues) >= maxReportedIssues {
		c.suppressed++
		return
	}
	c.issues = append(c.issues, model.Issue{Collector: Collector, Status: "incomplete", Code: code, Path: rel, Message: message})
}

func isScript(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func archiveKind(name string) string {
	switch ext := strings.ToLower(path.Ext(name)); ext {
	case ".war", ".zip", ".ear", ".jar":
		return ext
	default:
		return ""
	}
}

func safePath(name string) bool {
	return name != "" && len(name) <= 4096 && name != "." && name != ".." && !path.IsAbs(name) && path.Clean(name) == name &&
		!strings.HasPrefix(name, "../") && !strings.Contains(name, "!/") && !strings.ContainsAny(name, "\\:") &&
		utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) == -1
}

func (c *collector) scanFile(rel, kind string) {
	c.probes++
	f, st, err := c.plan.OpenIndexedRegular(c.root, rel)
	if err != nil {
		c.issue(rel, "static_js_file_unavailable", "evidence file is no longer a readable regular file")
		return
	}
	defer f.Close()
	if kind == "" {
		c.probe(f, rel)
	} else {
		c.scanArchive(f, st.Size(), rel, kind, 1)
	}
}

func (c *collector) probe(r io.Reader, rel string) {
	limit := min(int64(probeBytes), totalProbeBytes-c.bytes)
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	c.bytes += int64(len(buf))
	if err != nil {
		if errors.Is(err, errArchiveReadLimit) {
			c.issue(rel, "static_js_archive_read_limit", "total compressed archive read budget was exhausted")
		} else {
			c.issue(rel, "static_js_read_failed", "JavaScript evidence could not be read")
		}
		return
	}
	truncated := int64(len(buf)) > limit
	if truncated {
		buf = buf[:limit]
	}
	hint := filenameHint(path.Base(rel))
	hintMatched := false
	identities, identityLimit := identify(buf)
	fingerprint, fingerprintChecked := "", false
	if !truncated {
		identities, fingerprint, fingerprintChecked = c.applyFingerprint(buf, rel, identities)
	}
	if identityLimit || len(identities) > maxIdentitiesPerScript {
		c.issue(rel, "static_js_identity_limit", "only a bounded number of library identities were collected from this script")
	}
	for _, id := range identities[:min(len(identities), maxIdentitiesPerScript)] {
		if c.occurrences >= maxOccurrences {
			break
		}
		c.occurrences++
		purl := packageurl.NewPackageURL(packageurl.TypeNPM, "", id.name, id.version, nil, "").ToString()
		component := c.components[purl]
		if component == nil {
			component = &Component{Name: id.name, Version: id.version, PURL: purl}
			c.components[purl] = component
		}
		component.Locations = append(component.Locations, rel)
		if fingerprint != "" && id.name == fancytreeName {
			component.Fingerprints = append(component.Fingerprints, Fingerprint{Path: rel, PURL: purl, SHA256: fingerprint})
		}
		hintMatched = hintMatched || hint == id.name
	}
	if hint != "" && !hintMatched && !(hint == fancytreeName && fingerprintChecked) {
		c.issue(rel, "static_js_identity_unconfirmed", "JavaScript filename suggests a library but its package version could not be verified")
	}
	if truncated {
		c.issue(rel, "static_js_probe_truncated", "only a bounded prefix of this script was checked for library identity")
	}
}
