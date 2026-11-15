package collect

import (
	"encoding/json"
	"strings"
	"testing"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func TestPrivacyMetadataKeepsTypedIdentitiesLicensesAndGraph(t *testing.T) {
	root := "/private/build/person/target"
	py := pkg.Package{Name: "example-wheel", Version: "1.2.3", Type: pkg.PythonPkg, Metadata: pkg.PythonPackage{Name: "example-wheel", Version: "1.2.3", Author: "PRIVATE_AUTHOR", AuthorEmail: "person@example.invalid", SitePackagesRootPath: root + "/usr/lib/python3/site-packages", Files: []pkg.PythonFileRecord{{Path: root + "/usr/lib/python3/site-packages/example.py", Digest: &pkg.PythonFileDigest{Algorithm: "sha256", Value: "abc123"}}}, DirectURLOrigin: &pkg.PythonDirectURLOriginInfo{URL: "https://person:PRIVATE_PASSWORD@example.invalid/wheel?token=PRIVATE_QUERY#PRIVATE_FRAGMENT", VCS: "git", CommitID: "abcdef"}, RequiresDist: []string{"child>=1.0"}}, Locations: file.NewLocationSet(file.NewLocation(root + "/usr/lib/python3/site-packages/example.dist-info/METADATA")), Licenses: pkg.NewLicenseSet(pkg.License{SPDXExpression: "MIT", Value: "MIT", Type: license.Declared, Contents: "Copyright PRIVATE_LICENSE_AUTHOR", URLs: []string{"https://person:PRIVATE_PASSWORD@example.invalid/LICENSE?token=PRIVATE_QUERY"}})}
	child := pkg.Package{Name: "child", Version: "1.0", Type: pkg.PythonPkg, Metadata: pkg.PythonPackage{Name: "child", Version: "1.0"}}
	py.SetID()
	child.SetID()
	id := py.ID()
	loc := file.NewCoordinates(root+"/usr/lib/python3/site-packages/example.py", "")
	s := &sbom.SBOM{Source: source.Description{ID: "source", Name: root, Metadata: source.DirectoryMetadata{Path: root}}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(py, child), FileContents: map[file.Coordinates]string{loc: "PRIVATE_RAW_CONTENT"}, FileDigests: map[file.Coordinates][]file.Digest{loc: {{Algorithm: "sha256", Value: "abc123"}}}}, Relationships: []artifact.Relationship{{From: py, To: child, Type: artifact.DependencyOfRelationship}, {From: py, To: loc, Type: artifact.EvidentByRelationship}}}
	ScrubMetadata(s)
	got := s.Artifacts.Packages.Package(id)
	if got == nil {
		t.Fatal("package ID changed")
	}
	if got.Name != py.Name || got.Version != py.Version {
		t.Fatal("identity changed")
	}
	m, ok := got.Metadata.(pkg.PythonPackage)
	if !ok {
		t.Fatalf("metadata no longer typed: %T", got.Metadata)
	}
	if m.Author != "" || m.AuthorEmail != "" || m.DirectURLOrigin.URL != "https://example.invalid/wheel" || m.DirectURLOrigin.CommitID != "abcdef" || m.SitePackagesRootPath != "usr/lib/python3/site-packages" {
		t.Fatalf("bad scrub: %+v", m)
	}
	if len(m.RequiresDist) != 1 || m.Files[0].Digest.Value != "abc123" {
		t.Fatal("dependencies or hashes lost")
	}
	licenses := got.Licenses.ToSlice()
	if len(licenses) != 1 || licenses[0].SPDXExpression != "MIT" || licenses[0].Contents != "" {
		t.Fatalf("bad licenses: %+v", licenses)
	}
	if s.Relationships[0].From.ID() != id || s.Relationships[0].To.ID() != child.ID() {
		t.Fatal("dependency graph IDs changed")
	}
	endpoint := s.Relationships[0].From.(pkg.Package)
	if endpoint.Metadata.(pkg.PythonPackage).Author != "" {
		t.Fatal("unscrubbed relationship endpoint")
	}
	if len(s.Artifacts.FileContents) != 0 {
		t.Fatal("raw source contents retained")
	}
	for coords := range s.Artifacts.FileDigests {
		if coords.RealPath != "usr/lib/python3/site-packages/example.py" {
			t.Fatalf("absolute coordinate retained: %+v", coords)
		}
	}
	if c := s.Relationships[1].To.(file.Coordinates); c.RealPath != "usr/lib/python3/site-packages/example.py" {
		t.Fatalf("relationship coordinate is inconsistent: %+v", c)
	}
	b, _ := json.Marshal(m)
	for _, secret := range []string{"PRIVATE_", "person@example", "/private/build"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("leaked %s in %s", secret, b)
		}
	}
}
func TestPrivacyJavaScrubPersistsManifestAndBuildFieldRemoval(t *testing.T) {
	metadata := pkg.JavaArchive{VirtualPath: "/root-target/opt/app.jar", Manifest: &pkg.JavaManifest{Main: pkg.KeyValues{{Key: "Implementation-Title", Value: "Example"}, {Key: "Implementation-Version", Value: "1.2.3"}, {Key: "Implementation-Vendor", Value: "Oracle"}, {Key: "Built-By", Value: "PRIVATE_PERSON"}, {Key: "Build-Token", Value: "PRIVATE_TOKEN"}}, Sections: []pkg.KeyValues{{{Key: "Name", Value: "PRIVATE_SECTION"}}}}, PomProperties: &pkg.JavaPomProperties{GroupID: "org.example", ArtifactID: "example", Version: "1.2.3", Path: "/root-target/opt/app.jar!/META-INF/pom.properties", Extra: map[string]string{"secret": "PRIVATE_EXTRA"}}, PomProject: &pkg.JavaPomProject{GroupID: "org.example", ArtifactID: "example", Version: "1.2.3", Description: "PRIVATE_DESCRIPTION", URL: "https://person:PRIVATE_PASSWORD@example.invalid/repo?token=PRIVATE_QUERY"}}
	p := pkg.Package{Name: "example", Version: "1.2.3", Metadata: metadata, Type: pkg.JavaPkg}
	p.SetID()
	vm := pkg.Package{Name: "openjdk", Version: "17.0.13+11", Type: pkg.BinaryPkg, Metadata: pkg.JavaVMInstallation{Release: pkg.JavaVMRelease{JavaVersion: "17.0.13", JavaRuntimeVersion: "17.0.13+11", Implementor: "Oracle", BuildInfo: "PRIVATE_BUILD_PERSON", SourceRepo: "https://person:PRIVATE_PASSWORD@example.invalid/jdk?token=PRIVATE_QUERY"}}}
	vm.SetID()
	s := &sbom.SBOM{Source: source.Description{Metadata: source.DirectoryMetadata{Path: "/root-target"}}, Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(p, vm)}}
	ScrubMetadata(s)
	got := s.Artifacts.Packages.Package(p.ID()).Metadata.(pkg.JavaArchive)
	if got.PomProperties.Extra != nil || len(got.Manifest.Main) != 3 || len(got.Manifest.Sections) != 0 || got.PomProject.Description != "" || got.PomProject.URL != "https://example.invalid/repo" {
		t.Fatalf("bad Java scrub: %+v", got)
	}
	if got.PomProperties.GroupID != "org.example" || got.VirtualPath != "opt/app.jar" {
		t.Fatalf("identity/path lost: %+v", got)
	}
	gotVM := s.Artifacts.Packages.Package(vm.ID()).Metadata.(pkg.JavaVMInstallation)
	if gotVM.Release.Implementor != "Oracle" || gotVM.Release.JavaRuntimeVersion != "17.0.13+11" || gotVM.Release.BuildInfo != "" || gotVM.Release.SourceRepo != "https://example.invalid/jdk" {
		t.Fatalf("bad JVM scrub: %+v", gotVM)
	}
}
func TestPrivacyOSVendorEVRPreservedButContactsRemoved(t *testing.T) {
	epoch := 1
	rpm := pkg.Package{Name: "kernel-uek", Version: "5.4.17-2011.1.2.el8uek", Type: pkg.RpmPkg, Metadata: pkg.RpmDBEntry{Name: "kernel-uek", Version: "5.4.17", Epoch: &epoch, Release: "2011.1.2.el8uek", Arch: "x86_64", Vendor: "Oracle America", SourceRpm: "kernel-uek-5.4.17.src.rpm", Files: []pkg.RpmFileRecord{{Path: "/boot/vmlinuz", UserName: "PRIVATE_USER", GroupName: "PRIVATE_GROUP"}}}}
	deb := pkg.Package{Name: "openssl", Version: "3.0.0-1", Type: pkg.DebPkg, Metadata: pkg.DpkgDBEntry{Package: "openssl", Version: "3.0.0-1", Maintainer: "PRIVATE_PERSON <person@example.invalid>"}}
	rpm.SetID()
	deb.SetID()
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(rpm, deb)}}
	ScrubMetadata(s)
	got := s.Artifacts.Packages.Package(rpm.ID()).Metadata.(pkg.RpmDBEntry)
	if got.Vendor != "Oracle America" || got.Epoch == nil || *got.Epoch != 1 || got.Release != "2011.1.2.el8uek" || got.Arch != "x86_64" || got.SourceRpm == "" || got.Files[0].UserName != "" || got.Files[0].GroupName != "" {
		t.Fatalf("bad RPM scrub: %+v", got)
	}
	if s.Artifacts.Packages.Package(deb.ID()).Metadata.(pkg.DpkgDBEntry).Maintainer != "" {
		t.Fatal("DEB maintainer leaked")
	}
}
func TestPrivacyPURLQualifiersCleanURLsWithoutLosingDistro(t *testing.T) {
	raw := packageurl.NewPackageURL("rpm", "oracle", "kernel", "5.4.17", packageurl.QualifiersFromMap(map[string]string{"arch": "x86_64", "epoch": "1", "distro": "ol-8.2", "repository_url": "https://person:PRIVATE_PASSWORD@example.invalid/repo?token=PRIVATE_QUERY#PRIVATE_FRAGMENT", "api_token": "PRIVATE_TOKEN", "untrusted": "PRIVATE_UNKNOWN"}), "").ToString()
	got := privacyPURL(raw)
	p, err := packageurl.FromString(got)
	if err != nil {
		t.Fatal(err)
	}
	qual := p.Qualifiers.Map()
	if p.Type != "rpm" || p.Name != "kernel" || qual["arch"] != "x86_64" || qual["epoch"] != "1" || qual["distro"] != "ol-8.2" || qual["repository_url"] != "https://example.invalid/repo" || len(qual) != 4 {
		t.Fatalf("%s %+v", got, qual)
	}
	if strings.Contains(got, "PRIVATE_") {
		t.Fatal("PURL credentials leaked")
	}
}
func TestPrivacyRawImageConfigAndLabelsRemoved(t *testing.T) {
	s := &sbom.SBOM{Source: source.Description{Metadata: source.ImageMetadata{ID: "sha256:123", ManifestDigest: "sha256:456", UserInput: "/private/image.tar", RawConfig: []byte(`{"Env":["SECRET=PRIVATE_ENV"]}`), RawManifest: []byte(`{"annotations":{"secret":"PRIVATE_ANNOTATION"}}`), Labels: map[string]string{"author": "PRIVATE_PERSON"}, Annotations: map[string]string{"secret": "PRIVATE_ANNOTATION"}, Architecture: "amd64", OS: "linux"}}}
	ScrubMetadata(s)
	m := s.Source.Metadata.(source.ImageMetadata)
	if m.ID != "sha256:123" || m.Architecture != "amd64" || m.OS != "linux" || m.RawConfig != nil || m.RawManifest != nil || m.Labels != nil || m.Annotations != nil || m.UserInput != "local-image-archive" {
		t.Fatalf("bad image scrub: %+v", m)
	}
}
func TestPrivacyURLRejectsLocalFileMailAndMalformedOrigins(t *testing.T) {
	tests := map[string]string{"https://user:password@example.invalid/path?secret=q#fragment": "https://example.invalid/path", "git@example.invalid:repo/project.git": "ssh://example.invalid/repo/project.git", "file:///home/person/source": "", "mailto:person@example.invalid": "", "/home/person/source": "", "https://[invalid": ""}
	for raw, want := range tests {
		if got := privacyURL(raw); got != want {
			t.Errorf("privacyURL(%q)=%q want %q", raw, got, want)
		}
	}
}
