package collect

import (
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
)

const (
	npmDependencyMissing          = "npm_dependency_missing"
	npmDependencyScopeBlocked     = "npm_dependency_scope_blocked"
	npmDependencyVersionMismatch  = "npm_dependency_version_mismatch"
	npmDependencyIdentityMismatch = "npm_dependency_identity_mismatch"
	npmDependencyUnsupported      = "npm_dependency_unsupported"
	npmDependencyPeerShadowed     = "npm_dependency_peer_shadowed"
	npmManifestUnreadable         = "npm_dependency_manifest_unreadable"
	npmDependencyIssueLimit       = "npm_dependency_issue_limit"
)

var npmDependencyMessages = map[string]string{
	npmDependencyMissing:          "required dependency has no verified installed provider",
	npmDependencyScopeBlocked:     "dependency path is excluded or outside the permitted scan scope",
	npmDependencyVersionMismatch:  "the nearest installed version does not satisfy the dependency evidence",
	npmDependencyIdentityMismatch: "the nearest installed manifest identifies a different package name",
	npmDependencyUnsupported:      "dependency selector could not be verified from the installed files",
	npmDependencyPeerShadowed:     "the nearest private copy shadows the peer provider",
	npmManifestUnreadable:         "package.json could not be read or did not identify the indexed package",
	npmDependencyIssueLimit:       "additional npm dependency diagnostics were omitted",
}

type npmDependencyDiagnostics struct {
	bom               *sbom.SBOM
	count             int
	omitted           int
	omittedUnreadable bool
}

func (d *npmDependencyDiagnostics) add(coordinate file.Coordinates, code, dependency string) {
	const limit = 200
	if d.count >= limit {
		d.omitted++
		d.omittedUnreadable = d.omittedUnreadable || code == npmManifestUnreadable
		return
	}
	d.count++
	d.record(coordinate, code, dependency)
}

func (d *npmDependencyDiagnostics) finish() {
	if d.omitted > 0 {
		d.record(file.Coordinates{}, npmDependencyIssueLimit, strconv.Itoa(d.omitted)+" "+strconv.FormatBool(d.omittedUnreadable))
	}
}

func (d *npmDependencyDiagnostics) record(coordinate file.Coordinates, code, detail string) {
	if d.bom.Artifacts.Unknowns == nil {
		d.bom.Artifacts.Unknowns = make(map[file.Coordinates][]string)
	}
	d.bom.Artifacts.Unknowns[coordinate] = append(d.bom.Artifacts.Unknowns[coordinate], npmDependencySource+": "+code+" "+detail)
}

func npmDependencyIssue(message, manifestPath string) (model.Issue, bool) {
	code, detail, _ := strings.Cut(message, " ")
	description, known := npmDependencyMessages[code]
	if !known {
		return model.Issue{}, false
	}
	issue := model.Issue{Collector: npmDependencySource, Status: "not_observed", Code: code, Path: manifestPath, Message: description}
	if code == npmManifestUnreadable {
		issue.Status = "incomplete"
	}
	if code == npmDependencyIssueLimit {
		count, unreadable, _ := strings.Cut(detail, " ")
		issue.Observed, _ = strconv.ParseInt(count, 10, 64)
		if unreadable == "true" {
			issue.Status = "incomplete"
			issue.Message = "additional npm dependency diagnostics were omitted, including an unreadable manifest"
		}
	} else if npmDependencyName.MatchString(detail) && len(detail) <= 214 {
		issue.Message = detail + " — " + description
	}
	return issue, true
}
