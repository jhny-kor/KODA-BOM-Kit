package obom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/containers"
	"koda.local/security-sbom-linux/internal/model"
)

func fixtureJSON(t *testing.T, dir, name string, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func fixtureChecksums(t *testing.T, dir string, names ...string) {
	t.Helper()
	var out strings.Builder
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&out, "%x  %s\n", sha256.Sum256(b), name)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(out.String()), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (string, collection) {
	t.Helper()
	dir := t.TempDir()
	c := collection{Schema: "koda-sbom-collection-v1", Status: "partial", StartedAt: "2026-11-19T04:00:00Z", Host: &model.HostIdentity{MachineIDSHA256: "host-one"}}
	fixtureJSON(t, dir, "collection.json", c)
	s := model.Socket{Protocol: "tcp6", Address: "::", Port: 443, BindScope: "all-interfaces"}
	ctx := model.Context{Mode: "live-host", Status: "completed", ProcessLinks: []model.ProcessLink{{PID: 10, Executable: "usr/bin/server", FilesystemComparable: true, RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/server", Package: "server", InstalledVersion: "1", PURL: "pkg:generic/server@1"}, {Path: "usr/lib/libcrypto.so", Package: "openssl", InstalledVersion: "3", PURL: "pkg:generic/openssl@3"}, {Path: "usr/lib/unknown.so", State: "restart_review"}}, ListeningSockets: []model.Socket{s}}, {PID: 11, Executable: "usr/bin/server", FilesystemComparable: false, RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/server", PURL: "pkg:generic/unsafe@1"}}}}, UnattributedSockets: []model.Socket{{Protocol: "udp", Address: "127.0.0.1", Port: 53, BindScope: "loopback"}}}
	fixtureJSON(t, dir, "context.json", ctx)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	return dir, c
}
func TestRuntimeGraphOwnershipAndUnknowns(t *testing.T) {
	dir, _ := fixture(t)
	out := t.TempDir()
	if err := Write(context.Background(), dir, out, true); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components   []component  `json:"components"`
		Services     []service    `json:"services"`
		Dependencies []dependency `json:"dependencies"`
	}
	b, err := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var process, library, unknown string
	for _, c := range doc.Components {
		if c.PURL == "pkg:generic/unsafe@1" {
			t.Fatal("cross-root package attribution")
		}
		if c.Name == "process 10" {
			process = c.Ref
		}
		if c.Name == "openssl" {
			library = c.Ref
		}
		if c.Name == "usr/lib/unknown.so" {
			unknown = c.Ref
		}
	}
	if process == "" || library == "" || unknown == "" {
		t.Fatal("missing runtime evidence")
	}
	edges := map[string][]string{}
	for _, d := range doc.Dependencies {
		edges[d.Ref] = d.DependsOn
	}
	for _, s := range doc.Services {
		if s.Name == "tcp6 [::]:443" {
			if strings.Join(edges[s.Ref], ",") != process {
				t.Fatalf("listener should depend on process: %v", edges[s.Ref])
			}
			if s.Endpoints[0] != "tcp://[::]:443" {
				t.Fatal(s.Endpoints)
			}
		}
	}
	if len(doc.Services) != 2 {
		t.Fatalf("services %d", len(doc.Services))
	}
	if _, err = os.Stat(filepath.Join(out, "obom.cdx-1.7.json")); err != nil {
		t.Fatal(err)
	}
}
func TestReplayChecksumsAndNoOverwrite(t *testing.T) {
	dir, _ := fixture(t)
	out := t.TempDir()
	if err := Write(context.Background(), dir, out, false); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	if err := Write(context.Background(), dir, out, false); err == nil {
		t.Fatal("overwrote output")
	}
	after, _ := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	if string(before) != string(after) {
		t.Fatal("output changed")
	}
	f, err := os.OpenFile(filepath.Join(dir, "context.json"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(" ")
	f.Close()
	if err := Write(context.Background(), dir, t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tamper accepted: %v", err)
	}
	if err := WriteLive(context.Background(), dir, t.TempDir(), false); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyContainerStateAndNamespace(t *testing.T) {
	dir, c := fixture(t)
	s := model.Socket{Protocol: "tcp", Address: "0.0.0.0", Port: 80, BindScope: "all-interfaces"}
	for _, id := range []string{"one", "two"} {
		rel := "containers/" + id
		childDir := filepath.Join(dir, rel)
		if err := os.MkdirAll(childDir, 0700); err != nil {
			t.Fatal(err)
		}
		container := containers.Container{ID: id, Name: id, PID: 20}
		c.Containers = append(c.Containers, containerRecord{Container: container, Status: "partial", Output: rel})
		fixtureJSON(t, childDir, "collection.json", map[string]any{"container": container, "status": "partial", "listeningSockets": []map[string]any{{"executable": "usr/bin/server", "sockets": []model.Socket{s}}}})
		fixtureJSON(t, childDir, "sbom.cdx.json", map[string]any{"components": []component{{Type: "library", Ref: "same-ref", Name: "server", PURL: "pkg:generic/server@1", Properties: []property{{Name: "koda:runtime:listening", Value: "tcp/0.0.0.0:80 (all-interfaces)"}}}}})
		fixtureChecksums(t, childDir, "collection.json", "sbom.cdx.json")
	}
	c.Containers = append(c.Containers, containerRecord{Container: containers.Container{ID: "stopped", State: "stopped"}, Status: "completed", Output: "missing-stopped"})
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	out := t.TempDir()
	if err := Write(context.Background(), dir, out, false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services   []service   `json:"services"`
		Components []component `json:"components"`
	}
	b, _ := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	json.Unmarshal(b, &doc)
	count := 0
	refs := map[string]bool{}
	for _, s := range doc.Services {
		if s.Name == "tcp 0.0.0.0:80" {
			count++
			refs[s.Ref] = true
		}
	}
	if count != 2 || len(refs) != 2 {
		t.Fatal("container listener identities collapsed")
	}
	c.Containers[0].Output = "../escape"
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	if err := Write(context.Background(), dir, t.TempDir(), false); err == nil {
		t.Fatal("traversal accepted")
	}
}
func TestRejectNonLiveOrFailedAndCancellation(t *testing.T) {
	dir, c := fixture(t)
	c.Status = "failed"
	fixtureJSON(t, dir, "collection.json", c)
	if err := WriteLive(context.Background(), dir, t.TempDir(), false); err == nil {
		t.Fatal("failed accepted")
	}
	c.Status = "completed"
	fixtureJSON(t, dir, "collection.json", c)
	fixtureJSON(t, dir, "context.json", model.Context{Mode: "disabled"})
	if err := WriteLive(context.Background(), dir, t.TempDir(), false); err == nil {
		t.Fatal("disabled accepted")
	}
	dir, _ = fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Write(ctx, dir, t.TempDir(), false); err == nil {
		t.Fatal("cancel ignored")
	}
}

// Set KODA_OBOM_REPLAY_SOURCE and KODA_OBOM_REPLAY_OUTPUT to exercise saved
// evidence through the exact export API without rescanning a host.
func TestArchivedReplay(t *testing.T) {
	source := os.Getenv("KODA_OBOM_REPLAY_SOURCE")
	if source == "" {
		t.Skip("saved collection not requested")
	}
	output := os.Getenv("KODA_OBOM_REPLAY_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	if err := Write(context.Background(), source, output, true); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", output)
}

func TestMissingChildManifestRejected(t *testing.T) {
	dir, c := fixture(t)
	childDir := filepath.Join(dir, "containers", "one")
	os.MkdirAll(childDir, 0700)
	container := containers.Container{ID: "one", State: "running", PID: 20}
	c.Containers = []containerRecord{{Container: container, Status: "completed", Output: "containers/one"}}
	fixtureJSON(t, childDir, "collection.json", map[string]any{"container": container, "status": "completed"})
	fixtureJSON(t, childDir, "sbom.cdx.json", map[string]any{"components": []component{}})
	fixtureChecksums(t, childDir, "collection.json")
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	if err := Write(context.Background(), dir, t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("missing component checksum accepted: %v", err)
	}
}

func TestModernEmptyRuntimeAndSharedLegacySocket(t *testing.T) {
	dir, c := fixture(t)
	childDir := filepath.Join(dir, "containers", "one")
	os.MkdirAll(childDir, 0700)
	container := containers.Container{ID: "one", State: "running", PID: 20}
	c.Containers = []containerRecord{{Container: container, Status: "partial", Output: "containers/one"}}
	fixtureJSON(t, childDir, "collection.json", map[string]any{"container": container, "status": "partial", "runtimeObservation": "partial"})
	fixtureChecksums(t, childDir, "collection.json")
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	if err := Write(context.Background(), dir, t.TempDir(), false); err != nil {
		t.Fatal(err)
	}
	g := newGraph()
	scope := "container"
	g.components[scope] = component{Ref: scope, Type: "container", Name: "one"}
	socket := model.Socket{Protocol: "tcp", Address: "0.0.0.0", Port: 80, BindScope: "all-interfaces"}
	fixtureJSON(t, childDir, "sbom.cdx.json", map[string]any{"components": []component{{Type: "library", Ref: "pkg", Name: "server", Properties: []property{{Name: "koda:runtime:listening", Value: "tcp/0.0.0.0:80 (all-interfaces)"}}}}})
	fixtureJSON(t, childDir, "collection.json", map[string]any{"container": container, "status": "partial", "listeningSockets": []map[string]any{{"executable": "a", "sockets": []model.Socket{socket}}, {"executable": "b", "sockets": []model.Socket{socket}}}})
	fixtureChecksums(t, childDir, "collection.json", "sbom.cdx.json")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var child childCollection
	if err = readJSON(root, "containers/one/collection.json", &child, true); err != nil {
		t.Fatal(err)
	}
	if err = g.legacyContainer(context.Background(), root, "containers/one", scope, child); err != nil {
		t.Fatal(err)
	}
	for _, exe := range []string{"a", "b"} {
		ref := reference(scope, "executable", exe)
		if len(g.edges[ref]) != 0 {
			t.Fatalf("shared socket falsely assigned package to %s", exe)
		}
	}
}

func TestDeclaredMissingComponentEvidenceAndSPDXOnly(t *testing.T) {
	dir, c := fixture(t)
	childDir := filepath.Join(dir, "containers", "one")
	if err := os.MkdirAll(childDir, 0700); err != nil {
		t.Fatal(err)
	}
	container := containers.Container{ID: "one", State: "running", PID: 20}
	c.Containers = []containerRecord{{Container: container, Status: "partial", Output: "containers/one"}}
	fixtureJSON(t, childDir, "collection.json", map[string]any{"container": container, "status": "partial"})
	fixtureJSON(t, childDir, "sbom.cdx.json", map[string]any{"components": []component{}})
	fixtureChecksums(t, childDir, "collection.json", "sbom.cdx.json")
	if err := os.Remove(filepath.Join(childDir, "sbom.cdx.json")); err != nil {
		t.Fatal(err)
	}
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	if err := Write(context.Background(), dir, t.TempDir(), false); err == nil || !strings.Contains(err.Error(), "manifest-declared") {
		t.Fatalf("declared missing file accepted: %v", err)
	}
	fixtureJSON(t, childDir, "sbom.spdx.json", map[string]any{"spdxVersion": "SPDX-2.3"})
	fixtureChecksums(t, childDir, "collection.json", "sbom.spdx.json")
	if err := Write(context.Background(), dir, t.TempDir(), false); err != nil {
		t.Fatalf("SPDX-only collection rejected: %v", err)
	}
}

func TestImageIdentityAndUnconfirmedMembership(t *testing.T) {
	dir, c := fixture(t)
	c.Containers = []containerRecord{{Container: containers.Container{ID: "shared", State: "running"}, Status: "not_collected"}}
	c.Images = []containerRecord{{Container: containers.Container{ID: "shared", State: "image"}, Status: "completed"}}
	fixtureJSON(t, dir, "collection.json", c)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	out := t.TempDir()
	if err := Write(context.Background(), dir, out, false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []component `json:"components"`
	}
	data, err := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	states := map[string]bool{}
	unconfirmed := false
	for _, c := range doc.Components {
		for _, p := range c.Properties {
			if c.Type == "container" && p.Name == "koda:obom:state" {
				states[p.Value] = true
			}
			if c.Name == "process 11" && p.Name == "koda:obom:membership" && p.Value == "unconfirmed" {
				unconfirmed = true
			}
		}
	}
	if !states["running"] || !states["image"] {
		t.Fatalf("container/image identity collision: %v", states)
	}
	if !unconfirmed {
		t.Fatal("unconfirmed process membership missing")
	}
}

func TestOversizedSkippedScalarIsBounded(t *testing.T) {
	dir := t.TempDir()
	fixtureJSON(t, dir, "sbom.cdx.json", map[string]any{"components": []component{}, "unused": strings.Repeat("x", int(maxJSONRecordBytes)+1)})
	fixtureChecksums(t, dir, "sbom.cdx.json")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = streamComponents(context.Background(), root, "sbom.cdx.json", func(component) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "record exceeds") {
		t.Fatalf("oversized scalar accepted: %v", err)
	}
}
