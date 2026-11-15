package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

type scanLimits struct {
	MaxFiles       int64   `json:"maxFiles"`
	Timeout        string  `json:"timeout"`
	TimeoutSeconds float64 `json:"timeoutSeconds"`
}

// The helper uses the scanner's own value parsers before querying clients.
// Validation is pure: no host identity, filesystem traversal or output creation.
func validateScanOptions(args []string) int {
	flags := flag.NewFlagSet("validate-scan-options", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var timeout time.Duration
	var maxFiles int64
	var excludes, excludedDirs stringsFlag
	flags.DurationVar(&timeout, "timeout", 30*time.Minute, "")
	flags.Int64Var(&maxFiles, "max-files", localfs.DefaultMaxFiles, "")
	flags.Var(&excludes, "exclude", "")
	flags.Var(&excludedDirs, "exclude-dir", "")
	invalid := flags.Parse(args) != nil || flags.NArg() != 0 || timeout < 0 || maxFiles < 0
	for _, pattern := range excludes {
		invalid = invalid || !doublestar.ValidatePattern(pattern)
	}
	for _, directory := range excludedDirs {
		invalid = invalid || strings.TrimSpace(directory) == "" || strings.ContainsAny(directory, "\x00\r\n\t")
	}
	if invalid {
		fmt.Fprintln(os.Stderr, "invalid scan option value; check --timeout, --max-files, --exclude and --exclude-dir")
		return 2
	}
	return 0
}

func scanContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

// Report only controlled diagnostics. Raw provider errors may include private
// filesystem paths, credentials in URLs or package contents.
func failureIssue(stage string, err, contextErr error) model.Issue {
	issue := model.Issue{Collector: stage, Status: "failed", Code: stage + "_failed", Message: "collection operation failed"}
	var limit *localfs.FileLimitError
	switch {
	case errors.Is(contextErr, context.Canceled) || errors.Is(err, context.Canceled):
		issue.Code, issue.Message = "collection_cancelled", "collection cancelled by interrupt"
	case errors.Is(contextErr, context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		issue.Code, issue.Message = "collection_timed_out", "collection time limit reached; increase --timeout or use 0 for no time limit"
	case errors.As(err, &limit):
		issue.Code, issue.Limit, issue.Observed = "file_limit_exceeded", limit.Limit, limit.Observed
		issue.Message = fmt.Sprintf("filesystem file limit exceeded: limit=%d, observed=%d; increase --max-files or use 0 for no file limit", limit.Limit, limit.Observed)
	case stage == "filesystem" && err != nil:
		switch {
		case err.Error() == "invalid exclude pattern":
			issue.Code, issue.Message = "invalid_exclude_pattern", "invalid exclusion pattern"
		case strings.HasPrefix(err.Error(), "cannot verify local mounts:"):
			issue.Code, issue.Message = "mount_table_unavailable", "cannot verify local filesystem mounts"
		case err.Error() == "network/virtual filesystem targets are not supported":
			issue.Code, issue.Message = "unsupported_target_filesystem", "network or virtual filesystem target is not supported"
		case err.Error() == "target must be a readable local directory":
			issue.Code, issue.Message = "invalid_target", "target must be a readable local directory"
		}
	}
	return issue
}
