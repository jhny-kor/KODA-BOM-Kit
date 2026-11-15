//go:build linux

package hostcontext

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLivepatchDoesNotFollowSymlinkDirectoryOrAttribute(t *testing.T) {
	outside := t.TempDir()
	livepatchFixture(t, outside, "outside", "1\n", "0\n")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/kernel"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "sys/kernel/livepatch"), filepath.Join(root, "sys/kernel/livepatch")); err != nil {
		t.Fatal(err)
	}
	out := observeLivepatch(t, root)
	if out.Status != "partial" || len(out.Livepatch[0].Patches) != 0 {
		t.Fatalf("livepatch symlink directory followed: %+v", out)
	}
	root = t.TempDir()
	livepatchFixture(t, root, "inside", "1\n", "0\n")
	name := filepath.Join(root, "sys/kernel/livepatch/inside/enabled")
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "sys/kernel/livepatch/outside/enabled"), name); err != nil {
		t.Fatal(err)
	}
	out = observeLivepatch(t, root)
	if out.Status != "partial" || out.Livepatch[0].Patches[0].State != "unknown" {
		t.Fatalf("livepatch symlink attribute followed: %+v", out)
	}
}

func TestLinuxLivepatchEvidenceCaptureAndLoadUsesCurrentBoot(t *testing.T) {
	raw, err := CaptureLivepatchEvidence("uptrack", []byte("Installed updates:\n[abc123] CVE-2026-98432: Fixed.\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "livepatch.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := LoadLivepatchEvidence(context.Background(), name)
	if err != nil || status.Status != "observed" || status.Patches[0].State != "reported-applied" {
		t.Fatalf("current boot capture did not round trip: %+v %v", status, err)
	}
	for _, reason := range []string{"not_installed", "query_failed", "query_timed_out", "invalid_report"} {
		data, err := CaptureUnavailableLivepatchEvidence("uptrack", reason)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		status, err := LoadLivepatchEvidence(context.Background(), name)
		if err != nil || len(status.Patches) != 0 || status.Status == "observed" {
			t.Fatalf("unavailable client claimed observation: %+v %v", status, err)
		}
	}
}

func TestLinuxEvidenceRejectsSymlinkAndOversizedFile(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "status.json")
	if err := os.WriteFile(name, []byte(strings.Repeat("x", maxLivepatchReportBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLivepatchEvidence(context.Background(), name); err == nil {
		t.Fatal("oversized evidence accepted")
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLivepatchEvidence(context.Background(), link); err == nil {
		t.Fatal("symlink evidence accepted")
	}
}
