package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/hostcontext"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

type scanTarget struct {
	id           string
	root         string
	excludedDirs []string
}

type targetSummary struct {
	ID                  string         `json:"id"`
	Status              string         `json:"status"`
	FilesystemFileCount int64          `json:"filesystemFileCount"`
	PackageCount        int            `json:"packageCount"`
	Distribution        *linux.Release `json:"distribution,omitempty"`
	ExcludedPaths       []string       `json:"excludedPaths"`
	ExcludedDirectories []string       `json:"excludedDirectories"`
}

func validateScanTargets(ctx context.Context, targets, patterns, directories []string) ([]scanTarget, error) {
	scopes := make([]scanTarget, 0, len(targets))
	for i, target := range targets {
		id := fmt.Sprintf("target-%d", i+1)
		if strings.TrimSpace(target) == "" {
			return nil, fmt.Errorf("%s must be a nonempty directory path", id)
		}
		root, err := localfs.ResolveLocal(target)
		if err != nil || root == "/" {
			return nil, fmt.Errorf("%s must be a local directory below /", id)
		}
		// Syft interprets the absolute target prefix as part of every exclusion glob.
		if localfs.LiteralPathPattern(root) != root {
			return nil, fmt.Errorf("%s must have a path without glob special characters", id)
		}
		for _, previous := range scopes {
			if localfs.Within(previous.root, root) || localfs.Within(root, previous.root) {
				return nil, fmt.Errorf("%s and %s must be separate directories with no overlap", previous.id, id)
			}
		}
		scopes = append(scopes, scanTarget{id: id, root: root})
	}
	for i, directory := range directories {
		if !filepath.IsAbs(directory) {
			return nil, fmt.Errorf("--exclude-dir entry %d must use an absolute path with multiple targets", i+1)
		}
		clean := filepath.Clean(directory)
		matched := false
		for j := range scopes {
			if clean != scopes[j].root && localfs.Within(scopes[j].root, clean) {
				scopes[j].excludedDirs = append(scopes[j].excludedDirs, directory)
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("--exclude-dir entry %d must be below one scan target", i+1)
		}
	}
	for _, scope := range scopes {
		// The catch-all skips children while validating root and exclusion options.
		validation := append([]string{"/**"}, patterns...)
		if _, err := localfs.BuildWithOptions(ctx, scope.root, validation, localfs.Options{ExcludeDirs: scope.excludedDirs}); err != nil {
			return nil, fmt.Errorf("%s: %w", scope.id, err)
		}
	}
	return scopes, nil
}

func targetMatchesOutput(scopes []scanTarget, out string) bool {
	for _, scope := range scopes {
		if scope.root == out {
			return true
		}
	}
	return false
}

func excludeScanPath(patterns []string, root, excluded string) []string {
	if localfs.Within(root, excluded) {
		rel, _ := filepath.Rel(root, excluded)
		pattern := "/" + localfs.LiteralPathPattern(rel)
		return append(patterns, pattern, pattern+"/**")
	}
	return patterns
}

func appendScopedPaths(paths []string, target string, observed []string) []string {
	if target == "" {
		return observed
	}
	for _, value := range observed {
		paths = append(paths, target+"/"+strings.TrimPrefix(value, "/"))
	}
	return paths
}

func markTargetIssues(issues []model.Issue, target string) []model.Issue {
	if target == "" {
		return issues
	}
	for i := range issues {
		issues[i].Target = target
		if issues[i].Path != "" {
			issues[i].Path = target + "/" + strings.TrimPrefix(issues[i].Path, "/")
		}
	}
	return issues
}

func collectionStatus(issues []model.Issue) string {
	for _, issue := range issues {
		if issue.Status != "not_supported" && issue.Status != "not_observed" {
			return "partial"
		}
	}
	return "completed"
}

func collectScanContext(ctx context.Context, plan localfs.Plan, live bool, livepatch []model.LivepatchStatus) model.Context {
	data := hostcontext.CollectWithPaths(ctx, plan.Root, live, plan.Paths)
	data.Livepatch = append(data.Livepatch, livepatch...)
	for _, status := range data.Livepatch {
		if status.Status == "observed" || status.Status == "not_observed" {
			continue
		}
		data.Issues = append(data.Issues, model.Issue{Collector: "livepatch-evidence", Status: "incomplete", Message: status.Provider + " report is " + status.Status + "; patch application is not established"})
		if data.Status == "completed" {
			data.Status = "partial"
		}
	}
	return data
}

func catalogScanTarget(ctx context.Context, plan localfs.Plan) (*sbom.SBOM, *model.Issue, error) {
	audit := collect.NewAuditLog()
	syft.SetLogger(audit)
	type result struct {
		inventory *sbom.SBOM
		err       error
	}
	resultCh := make(chan result, 1)
	go func() {
		inventory, err := collect.Scan(ctx, plan, version)
		resultCh <- result{inventory, err}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case result := <-resultCh:
		var issue *model.Issue
		if audit.Warnings+audit.Errors > 0 {
			issue = &model.Issue{Collector: "syft", Status: "incomplete", Message: fmt.Sprintf("catalogers emitted %d warning(s) and %d error(s); raw messages are withheld to avoid leaking source content", audit.Warnings, audit.Errors)}
		}
		return result.inventory, issue, result.err
	}
}
