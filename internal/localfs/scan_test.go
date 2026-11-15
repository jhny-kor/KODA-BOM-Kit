package localfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scanFixture(t *testing.T, root, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPreflightKeepsOnlyPermittedRegularPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	for _, p := range []string{"app/keep.txt", "app/skip.log", "proc/metadata", "sys/metadata", "dev/metadata", "run/metadata", "var/lib/docker/metadata"} {
		scanFixture(t, root, p)
	}
	scanFixture(t, outside, "outside.txt")
	if err := os.Symlink(filepath.Join(outside, "outside.txt"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	p, err := Build(context.Background(), root, []string{"**/*.log"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Paths) != 1 || p.Paths[0] != "app/keep.txt" {
		t.Fatalf("unexpected paths %#v", p.Paths)
	}
	if len(p.Issues) == 0 {
		t.Fatal("escaped link was not reported")
	}
	for _, issue := range p.Issues {
		if strings.Contains(issue.Path, outside) {
			t.Fatal("absolute outside path leaked")
		}
	}
}

func TestPreflightResolvesOnlyInScopeLinkChains(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "app")
	outside := filepath.Join(parent, "outside")
	for _, name := range []string{"store/target/package.json", "private/package.json"} {
		scanFixture(t, root, name)
	}
	scanFixture(t, outside, "canary/package.json")
	if err := os.Mkdir(filepath.Join(root, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"../outside/reentry":   "../app/store/target",
		"node_modules/ok":      "../store/target",
		"node_modules/chain":   "ok",
		"node_modules/abs":     filepath.Join(root, "store", "target"),
		"node_modules/escape":  "../../outside/reentry",
		"node_modules/blocked": "../private",
		"node_modules/dangle":  "../missing",
		"node_modules/dotdot":  "../missing//./../store/target",
		"node_modules/loop-a":  "loop-b",
		"node_modules/loop-b":  "loop-a",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := BuildWithOptions(context.Background(), root, nil, Options{ExcludeDirs: []string{"private"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ok", "chain", "abs"} {
		link := "node_modules/" + name
		canonical, leaf, err := plan.ResolveIndexedPath(link)
		if err != nil || !leaf || canonical != "store/target" || plan.ExcludesPath(link) {
			t.Errorf("resolve %s = %q, terminal link %t, error %v", link, canonical, leaf, err)
		}
		canonical, leaf, err = plan.ResolveIndexedPath(link + "/package.json")
		if err != nil || leaf || canonical != "store/target/package.json" {
			t.Errorf("resolve %s/package.json = %q, terminal link %t, error %v", link, canonical, leaf, err)
		}
	}
	for _, name := range []string{"escape", "blocked", "dotdot", "loop-a", "loop-b"} {
		link := "node_modules/" + name
		if _, _, err := plan.ResolveIndexedPath(link); err == nil || !plan.ExcludesPath(link) {
			t.Errorf("unsafe link %s accepted by the scan plan", link)
		}
	}
}

func TestPreflightRejectsExclusionsWithAmbiguousRootGlob(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app[prod]")
	scanFixture(t, root, "package.json")
	if _, err := Build(context.Background(), root, nil); err != nil {
		t.Fatalf("target with no matching exclusions: %v", err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), root, nil); err == nil || !strings.Contains(err.Error(), "cannot safely apply exclusions") {
		t.Fatalf("unsafe scan-root pattern accepted: %v", err)
	}
}
func TestPreflightRejectsInvalidGlobAndCancelledContext(t *testing.T) {
	root := t.TempDir()
	scanFixture(t, root, "a")
	if _, err := Build(context.Background(), root, []string{"[invalid"}); err == nil {
		t.Fatal("invalid exclusion accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, root, nil); err == nil {
		t.Fatal("cancelled preflight succeeded")
	}
}
func TestWithinUsesPathBoundary(t *testing.T) {
	if Within("/opt/app", "/opt/application/file") || Within("/opt/app", "/opt/app/../secret") {
		t.Fatal("scope boundary bypass")
	}
	if !Within("/opt/app", "/opt/app/file") {
		t.Fatal("child not within scope")
	}
}
func TestUnreadableFileNotClaimedCollected(t *testing.T) {
	root := t.TempDir()
	scanFixture(t, root, "unreadable")
	if err := os.Chmod(filepath.Join(root, "unreadable"), 0000); err != nil {
		t.Fatal(err)
	}
	p, err := Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Paths) != 0 || len(p.Issues) == 0 || p.Issues[0].Status != "permission_denied" {
		t.Fatalf("unreadable data treated as collected: %+v", p)
	}
}
