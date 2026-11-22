package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLivepatchInputIsBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "status.json")
	if err := os.WriteFile(input, []byte("{\"Status\":[]}"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readLivepatchInput(input); err != nil || string(data) != "{\"Status\":[]}" {
		t.Fatalf("read %q: %v", data, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(input, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readLivepatchInput(link); err == nil {
		t.Fatal("symlink input accepted")
	}
	if _, err := readLivepatchInput(dir); err == nil {
		t.Fatal("directory input accepted")
	}
	if err := os.WriteFile(input, []byte(strings.Repeat("x", (1<<20)+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLivepatchInput(input); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestLivepatchCaptureNeverOverwritesExistingEvidence(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("host identity capture requires target Linux x86_64")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "raw.txt"), filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(input, []byte("Installed updates:\n[abc123] CVE-2026-98432: Fixture update.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--provider", "uptrack", "--input", input, "--output", output}
	if got := captureLivepatchEvidence(args); got != 0 {
		t.Fatalf("capture returned %d", got)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := captureLivepatchEvidence(args); got != 2 {
		t.Fatalf("overwrite returned %d", got)
	}
	after, _ := os.ReadFile(output)
	if string(after) != string(before) {
		t.Fatal("existing evidence modified")
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("evidence permissions are not private")
	}
}

func TestLivepatchEvidenceRejectedForNonHostCollection(t *testing.T) {
	for _, extra := range [][]string{{"--no-context"}, {"--target", t.TempDir()}, {"--image-archive", "image.tar"}} {
		out := filepath.Join(t.TempDir(), "results")
		args := append([]string{"scan", "--output-dir", out, "--livepatch-evidence", "missing.json"}, extra...)
		if got := run(args); got != 2 {
			t.Fatalf("%v returned %d", args, got)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("invalid livepatch scope created output")
		}
	}
}
