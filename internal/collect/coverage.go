package collect

import (
	"encoding/json"
	"sort"

	"koda.local/security-sbom-linux/internal/model"
)

const CollectionCoverageProperty = "koda:collection:coverage:v1"

type collectionIssueCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// CollectionCoverage describes the scope and limitations of the collection
// run. It contains counts and controlled reason codes only. Detailed paths,
// file contents and diagnostics belong in the local collection report.
type CollectionCoverage struct {
	IncludeAllOccurrences  bool                   `json:"-"`
	Status                 string                 `json:"status"`
	SourceType             string                 `json:"sourceType"`
	ComponentCount         int                    `json:"componentCount"`
	ExcludedDirectoryCount int                    `json:"excludedDirectoryCount"`
	ExcludedPatternCount   int                    `json:"excludedPatternCount,omitempty"`
	IssueCounts            []collectionIssueCount `json:"issueCounts"`
	OmittedIssueCount      int                    `json:"omittedIssueCount,omitempty"`
}

const maxCoverageCount = 1<<31 - 1

func NewCollectionCoverage(status, sourceType string, componentCount, excludedDirectories, excludedPatterns int, issues []model.Issue) CollectionCoverage {
	coverage := CollectionCoverage{
		Status: status, SourceType: sourceType,
		ComponentCount: componentCount, ExcludedDirectoryCount: excludedDirectories, ExcludedPatternCount: excludedPatterns,
		IssueCounts: []collectionIssueCount{},
	}
	counts := map[string]int{}
	for _, issue := range issues {
		code := coverageIssueCode(issue)
		if code == "" {
			coverage.OmittedIssueCount = min(coverage.OmittedIssueCount+1, maxCoverageCount)
			continue
		}
		counts[code]++
		if (code == "static_js_issue_limit" || code == "binary_issue_limit" || code == "deployment_issue_limit" || code == npmDependencyIssueLimit) && issue.Observed > 0 {
			coverage.OmittedIssueCount = int(min(int64(coverage.OmittedIssueCount)+min(issue.Observed, int64(maxCoverageCount)), int64(maxCoverageCount)))
		}
	}
	for code, count := range counts {
		coverage.IssueCounts = append(coverage.IssueCounts, collectionIssueCount{Code: code, Count: min(count, maxCoverageCount)})
	}
	sort.Slice(coverage.IssueCounts, func(i, j int) bool { return coverage.IssueCounts[i].Code < coverage.IssueCounts[j].Code })
	return coverage
}

func coverageIssueCode(issue model.Issue) string {
	if issue.Collector == npmDependencySource && npmDependencyMessages[issue.Code] != "" {
		return issue.Code
	}
	switch issue.Code {
	case "static_js_archive_depth_limit", "static_js_archive_index_limit", "static_js_archive_invalid",
		"static_js_archive_invalid_entry", "static_js_archive_limit", "static_js_archive_path_limit",
		"static_js_archive_read_limit", "static_js_cancelled", "static_js_file_unavailable",
		"static_js_identity_limit", "static_js_identity_unconfirmed", "static_js_invalid_path",
		"static_js_fingerprint_ambiguous", "static_js_fingerprint_conflict",
		"binary_metadata_unreadable", "binary_issue_limit", "deployment_metadata_unreadable", "deployment_issue_limit",
		"static_js_issue_limit", "static_js_nested_archive_limit", "static_js_probe_truncated",
		"static_js_read_failed", "static_js_root_unavailable", "static_js_scan_limit",
		"aix_capture_failed", "aix_evidence_unreadable", "aix_filesets_partial", "aix_fixes_partial",
		"aix_home_evidence_unreadable", "aix_oslevel_invalid", "oracle_inventory_unverified",
		"oracle_listener_unverified", "oracle_listener_version_unknown", "oracle_ru_conflict",
		"oracle_ru_unknown", "oracle_sqlpatch_not_provided", "oracle_sqlpatch_partial":
		return issue.Code
	}
	// Older collectors still report controlled statuses with a free-form
	// message. Export a generic reason for each known collector instead.
	switch issue.Collector {
	case "filesystem":
		if issue.Status == "permission_denied" {
			return "filesystem_permission_denied"
		}
		return "filesystem_incomplete"
	case "products":
		if issue.Status == "not_supported" {
			return "product_not_supported"
		}
		return "product_evidence_incomplete"
	case "host-context":
		if issue.Status == "permission_denied" {
			return "host_context_permission_denied"
		}
		return "host_context_incomplete"
	case "livepatch-evidence":
		return "livepatch_evidence_incomplete"
	case "hardware", "asset-import":
		return "asset_evidence_incomplete"
	case "syft":
		return "package_catalog_incomplete"
	case "inventory":
		return "no_identified_components"
	}
	return ""
}

func addCycloneDXCoverage(document map[string]json.RawMessage, coverage []byte) error {
	metadata := map[string]json.RawMessage{}
	if raw := document["metadata"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return err
		}
	}
	if metadata == nil {
		metadata = map[string]json.RawMessage{}
	}
	var properties []json.RawMessage
	if raw := metadata["properties"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &properties); err != nil {
			return err
		}
	}
	property, err := json.Marshal(struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{Name: CollectionCoverageProperty, Value: string(coverage)})
	if err != nil {
		return err
	}
	metadata["properties"], err = json.Marshal(append(properties, property))
	if err != nil {
		return err
	}
	document["metadata"], err = json.Marshal(metadata)
	return err
}
