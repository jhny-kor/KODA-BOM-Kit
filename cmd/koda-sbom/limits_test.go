package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
)

func TestUnlimitedScanHasNoDeadlineAndStillCancels(t *testing.T) {
	parent, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	ctx, cancel := scanContext(parent, 0)
	defer cancel()
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("zero timeout unexpectedly installed a deadline")
	}
	interrupt()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("unlimited scan ignored interruption")
	}
}

func TestFiniteScanPreservesDeadline(t *testing.T) {
	before := time.Now()
	ctx, cancel := scanContext(context.Background(), time.Minute)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(before.Add(time.Minute)) || deadline.After(time.Now().Add(time.Minute)) {
		t.Fatal("explicit finite timeout did not install the requested deadline")
	}
}

func TestFailureDiagnosticsExposeLimitsWithoutPrivatePaths(t *testing.T) {
	limit := failureIssue("filesystem", &localfs.FileLimitError{Limit: 2, Observed: 3}, nil)
	if limit.Code != "file_limit_exceeded" || limit.Limit != 2 || limit.Observed != 3 || !strings.Contains(limit.Message, "--max-files") {
		t.Fatalf("file limit diagnosis lost: %+v", limit)
	}
	for _, tc := range []struct {
		err  error
		code string
	}{{context.Canceled, "collection_cancelled"}, {context.DeadlineExceeded, "collection_timed_out"}} {
		issue := failureIssue("filesystem", tc.err, tc.err)
		if issue.Code != tc.code {
			t.Fatalf("%v: %+v", tc.err, issue)
		}
	}
	private := errors.New("open /home/PRIVATE_USER/private/TOKEN_SECRET: denied")
	issue := failureIssue("cataloging", private, nil)
	if strings.Contains(issue.Message, "PRIVATE_USER") || strings.Contains(issue.Message, "TOKEN_SECRET") {
		t.Fatal("raw error path or content leaked")
	}
}

func TestPureScanOptionValidation(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--timeout", "0", "--max-files", "0"},
		{"--timeout", "1h30m", "--max-files", "9223372036854775807"},
		{"--timeout=1.5s", "--exclude", "/data/docker/**"},
	} {
		if got := validateScanOptions(args); got != 0 {
			t.Fatalf("valid options %v returned %d", args, got)
		}
	}
	for _, args := range [][]string{
		{"--timeout", "not-a-duration"}, {"--timeout", "-1s"},
		{"--timeout", "999999999999999999999999h"},
		{"--max-files", "9223372036854775808"}, {"--max-files", "-1"},
		{"--exclude", "[invalid"}, {"--target", "/"},
		{"--output-dir", "/must-not-be-created"}, {"extra-positional"},
	} {
		if got := validateScanOptions(args); got != 2 {
			t.Fatalf("invalid options %v returned %d", args, got)
		}
	}
}
