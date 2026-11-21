package localfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestFileLimitAllowsExactBoundary(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		scanFixture(t, root, name)
	}
	if err := os.Mkdir(filepath.Join(root, "z-empty"), 0700); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildWithOptions(context.Background(), root, nil, Options{MaxFiles: 2})
	if err != nil {
		t.Fatalf("exact file limit rejected: %v", err)
	}
	if len(plan.Paths) != 2 {
		t.Fatalf("collected %d files, want 2", len(plan.Paths))
	}
}

func TestFileLimitReportsNextEligibleFile(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		scanFixture(t, root, name)
	}
	plan, err := BuildWithOptions(context.Background(), root, nil, Options{MaxFiles: 2})
	var limitErr *FileLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("got error %v, want FileLimitError", err)
	}
	if limitErr.Limit != 2 || limitErr.Observed != 3 {
		t.Fatalf("unexpected file limit details: %+v", limitErr)
	}
	// An over-limit plan is never scanned. Only successful plans must include
	// every eligible path; a rejected walk may encounter entries in disk order.
	if len(plan.Paths) != 2 || !slices.IsSorted(plan.Paths) {
		t.Fatalf("unexpected retained paths: %#v", plan.Paths)
	}
}

func TestFileLimitIgnoresExcludedAndIneligibleEntries(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "proc/default-excluded", "z-dir/skip.log", "z-unreadable"} {
		scanFixture(t, root, name)
	}
	if err := os.Chmod(filepath.Join(root, "z-unreadable"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "z-link")); err != nil {
		t.Fatal(err)
	}
	large, err := os.Create(filepath.Join(root, "z-large"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate((2 << 30) + 1); err != nil {
		large.Close()
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildWithOptions(context.Background(), root, []string{"**/*.log"}, Options{MaxFiles: 2})
	if err != nil {
		t.Fatalf("ineligible entries consumed file limit: %v", err)
	}
	if len(plan.Paths) != 2 || plan.Paths[0] != "a" || plan.Paths[1] != "b" {
		t.Fatalf("unexpected paths: %#v", plan.Paths)
	}
	if len(plan.Issues) != 2 {
		t.Fatalf("expected unreadable and oversized file issues: %+v", plan.Issues)
	}
}

func TestZeroFileLimitAllowsAllEligibleFiles(t *testing.T) {
	root := t.TempDir()
	const count = 257
	for i := 0; i < count; i++ {
		scanFixture(t, root, fmt.Sprintf("file-%03d", i))
	}
	plan, err := BuildWithOptions(context.Background(), root, nil, Options{MaxFiles: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Paths) != count {
		t.Fatalf("collected %d files, want %d", len(plan.Paths), count)
	}
}

func TestPlanOpensKnownFilesThroughPermittedLinks(t *testing.T) {
	root := t.TempDir()
	scanFixture(t, root, "app/metadata")
	scanFixture(t, root, "private/metadata")
	if err := os.Symlink("app", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	plan, err := BuildWithOptions(context.Background(), root, nil, Options{ExcludeDirs: []string{"private"}})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := plan.OpenRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	file, _, err := plan.OpenIndexedRegular(dir, "link/metadata")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if file, _, err := plan.OpenIndexedRegular(dir, "private/metadata"); err == nil {
		file.Close()
		t.Fatal("excluded file accepted")
	}
}

func TestFileLimitRejectsNegativeValue(t *testing.T) {
	if _, err := BuildWithOptions(context.Background(), t.TempDir(), nil, Options{MaxFiles: -1}); err == nil {
		t.Fatal("negative file limit accepted")
	}
}

func TestUnlimitedFileLimitStillHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	scanFixture(t, root, "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan, err := BuildWithOptions(ctx, root, nil, Options{MaxFiles: 0})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got error %v, want context.Canceled", err)
	}
	if len(plan.Paths) != 0 {
		t.Fatalf("cancelled scan returned files: %#v", plan.Paths)
	}
}
