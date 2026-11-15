package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"koda.local/security-sbom-linux/internal/localfs"
)

func TestInstalledNPMDependencies(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"app/package.json": `{
			"name":"app","version":"1.0.0",
			"dependencies":{"router":"^2.0.0","lock-only":"1.0.0","@scope/tool":"~3.1.0","shadowed":"^1.0.0","excluded":"1.0.0","elsewhere":"1.0.0","alias":"npm:actual@1.0.0","linked":"1.0.0","dangle":"1.0.0","optional":"^9.0.0"},
			"optionalDependencies":{"optional":"^1.0.0","missing-optional":"1.0.0"},
			"peerDependencies":{"app-peer":"^1.0.0","missing-peer":"*","optional":"^8.0.0","router":"^8.0.0"},
			"peerDependenciesMeta":{"missing-peer":{"optional":true}},
			"devDependencies":{"test-only":"1.0.0"}
		}`,
		"app/package-lock.json":                                      `{"lockfileVersion":3,"packages":{"node_modules/lock-only":{"version":"1.0.0"}}}`,
		"app/node_modules/router/package.json":                       `{"name":"router","version":"2.3.1","dependencies":{"util":"1.x","blocked":"1.0.0"},"peerDependencies":{"app-peer":"^1.0.0","own-peer":"^1.0.0"}}`,
		"app/node_modules/app-peer/package.json":                     `{"name":"app-peer","version":"1.0.0"}`,
		"app/node_modules/own-peer/package.json":                     `{"name":"own-peer","version":"1.0.0"}`,
		"app/node_modules/router/node_modules/own-peer/package.json": `{"name":"own-peer","version":"1.0.1"}`,
		"app/node_modules/router/node_modules/util/package.json":     `{"name":"util","version":"1.2.0"}`,
		"app/node_modules/router/node_modules/blocked/package.json":  `{"name":"different-package","version":"1.0.0"}`,
		"app/node_modules/blocked/package.json":                      `{"name":"blocked","version":"1.0.0"}`,
		"app/node_modules/util/package.json":                         `{"name":"util","version":"1.1.0"}`,
		"app/node_modules/@scope/tool/package.json":                  `{"name":"@scope/tool","version":"3.1.4","dependencies":{"util":"1.x"}}`,
		"app/node_modules/optional/package.json":                     `{"name":"optional","version":"1.0.0"}`,
		"app/node_modules/shadowed/package.json":                     `{"name":"shadowed","version":"2.0.0"}`,
		"app/node_modules/excluded/package.json":                     `{"name":"excluded","version":"1.0.0"}`,
		"app/node_modules/alias/package.json":                        `{"name":"actual","version":"1.0.0"}`,
		"app/node_modules/test-only/package.json":                    `{"name":"test-only","version":"1.0.0"}`,
		"node_modules/shadowed/package.json":                         `{"name":"shadowed","version":"1.0.0"}`,
		"node_modules/excluded/package.json":                         `{"name":"excluded","version":"1.0.0"}`,
		"node_modules/linked/package.json":                           `{"name":"linked","version":"1.0.0"}`,
		"sibling/node_modules/elsewhere/package.json":                `{"name":"elsewhere","version":"1.0.0"}`,
		"node_modules/dangle/package.json":                           `{"name":"dangle","version":"1.0.0"}`,
	}
	for rel, content := range files {
		filename := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "app/node_modules/linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../missing", filepath.Join(root, "app/node_modules/dangle")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	plan, err := localfs.BuildWithOptions(ctx, root, nil, localfs.Options{
		ExcludeDirs: []string{"app/node_modules/excluded"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bom, err := Scan(ctx, plan, "test")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"app@1.0.0 -> router@2.3.1":       true,
		"app@1.0.0 -> @scope/tool@3.1.4":  true,
		"app@1.0.0 -> optional@1.0.0":     true,
		"app@1.0.0 -> app-peer@1.0.0":     true,
		"router@2.3.1 -> util@1.2.0":      true,
		"router@2.3.1 -> app-peer@1.0.0":  true,
		"@scope/tool@3.1.4 -> util@1.1.0": true,
	}
	actual := map[string]bool{}
	for _, edge := range bom.Relationships {
		dependency, fromPackage := edge.From.(pkg.Package)
		depender, toPackage := edge.To.(pkg.Package)
		if edge.Type == artifact.DependencyOfRelationship && fromPackage && toPackage &&
			depender.Type == pkg.NpmPkg {
			actual[depender.Name+"@"+depender.Version+" -> "+dependency.Name+"@"+dependency.Version] = true
		}
	}
	if !maps.Equal(actual, want) {
		t.Fatalf("npm dependency graph got %v, want %v", actual, want)
	}
	for _, name := range []string{"lock-only", "missing-optional", "missing-peer"} {
		if len(bom.Artifacts.Packages.PackagesByName(name)) > 0 {
			t.Fatalf("declaration-only %s was added", name)
		}
	}

	Scrub(bom)
	out := t.TempDir()
	if err := WriteSBOMs(out, "both", bom); err != nil {
		t.Fatal(err)
	}
	cdx := readNPMTestJSON[struct {
		Components []struct {
			Name, Version string
			Ref           string `json:"bom-ref"`
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}](t, out, "sbom.cdx.json")
	names := map[string]string{}
	for _, component := range cdx.Components {
		names[component.Ref] = component.Name + "@" + component.Version
	}
	cdxEdges := map[string]bool{}
	for _, edge := range cdx.Dependencies {
		for _, target := range edge.DependsOn {
			if names[edge.Ref] != "" && names[target] != "" {
				cdxEdges[names[edge.Ref]+" -> "+names[target]] = true
			}
		}
	}
	if !maps.Equal(cdxEdges, want) {
		t.Fatalf("CycloneDX npm graph got %v, want %v", cdxEdges, want)
	}

	spdx := readNPMTestJSON[struct {
		Packages []struct {
			Name, SPDXID, VersionInfo string
		}
		Relationships []struct {
			SPDXElementID, RelatedSPDXElement, RelationshipType string
		}
	}](t, out, "sbom.spdx.json")
	clear(names)
	for _, item := range spdx.Packages {
		names[item.SPDXID] = item.Name + "@" + item.VersionInfo
	}
	spdxEdges := map[string]bool{}
	for _, edge := range spdx.Relationships {
		if edge.RelationshipType == "DEPENDENCY_OF" &&
			names[edge.SPDXElementID] != "" && names[edge.RelatedSPDXElement] != "" {
			spdxEdges[names[edge.RelatedSPDXElement]+" -> "+names[edge.SPDXElementID]] = true
		}
	}
	if !maps.Equal(spdxEdges, want) {
		t.Fatalf("SPDX npm graph got %v, want %v", spdxEdges, want)
	}
}

func readNPMTestJSON[T any](t *testing.T, out, name string) T {
	t.Helper()
	var value T
	data, err := os.ReadFile(filepath.Join(out, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNPMVersionEvidence(t *testing.T) {
	for _, test := range []struct {
		spec, version string
		want          bool
	}{
		{"^1.2.0 || ~3.0.0", "3.0.2", true},
		{"1.2.0 - 1.4.0", "1.3.0", true},
		{"2.0.0-rc.1", "2.0.0-rc.1", true},
		{"^2.0.0", "2.1.0-beta.1", false},
		{"^1.2.0", "2.0.0", false},
		{"npm:actual@1.0.0", "1.0.0", false},
		{"workspace:*", "1.0.0", false},
		{"file:../foo", "1.0.0", false},
		{"https://example.invalid/sample.tgz", "1.0.0", false},
		{"latest", "1.0.0", false},
		{"", "1.0.0", false},
		{strings.Repeat("1", 300), "1.0.0", false},
	} {
		if got := matchesNPMVersion(test.spec, test.version); got != test.want {
			t.Errorf("matchesNPMVersion(%q, %q) = %t, want %t", test.spec, test.version, got, test.want)
		}
	}
}

func TestNPMDiagnosticLimitKeepsUnreadableStatus(t *testing.T) {
	root := t.TempDir()
	dependencies := make(map[string]string)
	for i := range 200 {
		dependencies[fmt.Sprintf("missing-%03d", i)] = "1.0.0"
	}
	dependencies["zzz-unreadable"] = "1.0.0"
	manifest, err := json.Marshal(npmManifest{Name: "app", Version: "1.0.0", Dependencies: dependencies})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "zzz-unreadable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "zzz-unreadable", "package.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	plan, err := localfs.BuildWithOptions(ctx, root, nil, localfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	bom, err := Scan(ctx, plan, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, issue := range DeployedCollectionIssues(bom, plan.Root) {
		if issue.Code == npmDependencyIssueLimit && issue.Status == "incomplete" && issue.Observed == 1 {
			return
		}
	}
	t.Fatal("capped diagnostics did not report the omitted unreadable manifest")
}

func TestPNPMWorkspaceVersionEvidence(t *testing.T) {
	for _, test := range []struct {
		spec, version string
		want          bool
	}{
		{"workspace:*", "1.2.3", true},
		{"workspace:^", "1.2.3", true},
		{"workspace:~", "1.2.3", true},
		{"workspace:^1.2.0", "1.2.3", true},
		{"workspace:^1.2.0", "2.0.0", false},
		{"workspace:../sibling", "1.2.3", false},
		{"workspace:other@*", "1.2.3", false},
		{"workspace:*", "not-a-version", false},
	} {
		if got := matchesInstalledNPMVersion(test.spec, test.version); got != test.want {
			t.Errorf("matchesInstalledNPMVersion(%q, %q) = %t, want %t", test.spec, test.version, got, test.want)
		}
	}
}

func TestPNPMDeployFileEvidence(t *testing.T) {
	const valid = "node_modules/.pnpm/@scope+shared@file++++tmp+src/node_modules/@scope/shared/package.json"
	const local = "@scope/shared@file:///tmp/src"
	for _, test := range []struct {
		spec, location string
		want           bool
	}{
		{local, valid, true},
		{local, "other/" + valid, true},
		{"@scope/shared@file://remote/tmp/src", valid, false},
		{"alias@file:///tmp/src", valid, false},
		{local + "?query", valid, false},
		{local, "node_modules/@scope/shared/package.json", false},
		{local, strings.Replace(valid, "node_modules/.pnpm", "other_node_modules/.pnpm", 1), false},
		{local, strings.Replace(valid, "@file++++tmp+src", "@1.2.3", 1), false},
	} {
		if got := (pnpmLayouts{}).matchesDeployFile(test.spec, "@scope/shared", test.location, true); got != test.want {
			t.Errorf("matchesDeployFile(%q, %q) = %t, want %t", test.spec, test.location, got, test.want)
		}
	}
}

func TestHoistedPeerVersion(t *testing.T) {
	for _, test := range []struct{ id, want string }{
		{"app@1.0.0(other@4.0.0(@scope/peer@3.0.0))(@scope/peer@2.0.0)", "2.0.0"},
		{"app@1.0.0(other@4.0.0(@scope/peer@3.0.0))", ""},
		{"app@1.0.0(@scope/peer@2.0.0)(@scope/peer@3.0.0)", ""},
		{"app@9.0.0(@scope/peer@2.0.0)", ""},
		{"app@file:packages/app(@scope/peer@2.0.0)", "2.0.0"},
		{"other-app@1.0.0(@scope/peer@2.0.0)", ""},
	} {
		if got := hoistedPeerVersion(test.id, "app", "1.0.0", "@scope/peer"); got != test.want {
			t.Errorf("hoistedPeerVersion(%q) = %q, want %q", test.id, got, test.want)
		}
	}
}
