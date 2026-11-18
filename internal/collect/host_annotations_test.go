package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"koda.local/security-sbom-linux/internal/model"
)

func TestAnnotateSBOMsAddsHostIdentityAndListeningSockets(t *testing.T) {
	const purl = "pkg:deb/debian/nginx@1.22.1-9?arch=amd64"
	p := pkg.Package{Name: "nginx", Version: "1.22.1-9", Type: pkg.DebPkg, PURL: purl}
	p.SetID()
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(p)},
		Source:     source.Description{ID: "fixture", Name: "fixture", Metadata: source.DirectoryMetadata{Path: "."}},
		Descriptor: sbom.Descriptor{Name: "koda-sbom", Version: "test"}}
	dir := t.TempDir()
	if err := WriteSBOMsWithAssets(context.Background(), dir, "both", s, false, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	public := model.Socket{Protocol: "tcp6", Address: "::", Port: 443, BindScope: "all-interfaces"}
	local := model.Socket{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, BindScope: "loopback"}
	runtime := model.Context{ProcessLinks: []model.ProcessLink{
		{PID: 10, Executable: "usr/sbin/nginx", FilesystemComparable: true, ListeningSockets: []model.Socket{local, public},
			RuntimeFiles: []model.RuntimeFile{{Path: "usr/lib/libssl.so.3", PURL: "pkg:deb/debian/libssl3@3.0"}, {Path: "usr/sbin/nginx", PURL: purl}}},
		{PID: 11, Executable: "usr/sbin/nginx", FilesystemComparable: true, ListeningSockets: []model.Socket{public},
			RuntimeFiles: []model.RuntimeFile{{Path: "usr/sbin/nginx", PURL: purl}}},
		{PID: 12, Executable: "usr/bin/other", ListeningSockets: []model.Socket{public},
			RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/other", PURL: "pkg:deb/debian/other@1"}}},
	}}
	exposure := ListeningByPURL(runtime)
	if len(exposure) != 1 || len(exposure[purl]) != 2 {
		t.Fatalf("only the comparable executable owner should be linked once per socket: %+v", exposure)
	}
	host := model.HostIdentity{AssetTag: "web-01", MachineIDSHA256: "ab"}
	if err := AnnotateSBOMs(dir, HostProperties(host), exposure.Properties()); err != nil {
		t.Fatal(err)
	}
	type property struct{ Name, Value string }
	for _, name := range []string{"sbom.cdx.json", CycloneDX17Filename} {
		var cdx struct {
			Metadata   struct{ Properties []property }
			Components []struct {
				PURL       string
				Properties []property
			}
		}
		readJSON(t, filepath.Join(dir, name), &cdx)
		if !slices.Contains(cdx.Metadata.Properties, property{"koda:host:asset-tag", "web-01"}) ||
			!slices.Contains(cdx.Metadata.Properties, property{"koda:host:machine-id-sha256", "ab"}) {
			t.Fatalf("%s: host identity missing: %+v", name, cdx.Metadata.Properties)
		}
		props := cdx.Components[0].Properties
		if !slices.Contains(props, property{RuntimeBindScopeProperty, "all-interfaces"}) ||
			!slices.Contains(props, property{RuntimeListeningProperty, "tcp6/[::]:443 (all-interfaces)"}) ||
			!slices.Contains(props, property{RuntimeListeningProperty, "tcp/127.0.0.1:8080 (loopback)"}) {
			t.Fatalf("%s: runtime exposure missing: %+v", name, props)
		}
	}
	var spdx struct {
		Annotations []struct{ Annotator, AnnotationType, AnnotationDate, Comment string }
		Packages    []struct {
			Annotations []struct{ Comment string }
		}
	}
	readJSON(t, filepath.Join(dir, "sbom.spdx.json"), &spdx)
	if len(spdx.Annotations) != 2 || spdx.Annotations[0].Comment != "koda:host:asset-tag web-01" || spdx.Annotations[0].AnnotationDate == "" {
		t.Fatalf("SPDX document annotations: %+v", spdx.Annotations)
	}
	found := false
	for _, item := range spdx.Packages {
		for _, a := range item.Annotations {
			found = found || a.Comment == RuntimeListeningProperty+" tcp6/[::]:443 (all-interfaces)"
		}
	}
	if !found {
		t.Fatalf("SPDX package annotation missing: %+v", spdx.Packages)
	}
}

func TestAnnotateSBOMsWithoutDataLeavesFilesUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AnnotateSBOMs(dir, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, p string, v any) {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
