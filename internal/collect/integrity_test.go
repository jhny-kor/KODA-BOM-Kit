package collect

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

func TestVerifyPackageFiles(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0755); err != nil {
			t.Fatal(err)
		}
	}
	md5hex := func(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
	sha256hex := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	q1 := func(s string) string { h := sha1.Sum([]byte(s)); return "Q1" + base64.StdEncoding.EncodeToString(h[:]) }
	put("usr/bin/dash", "dash")
	put("usr/bin/good", "good")
	put("usr/bin/replaced", "patched by hand")
	put("etc/tool.conf", "edited")
	put("usr/sbin/nginx", "nginx")
	put("usr/lib64/libssl.so.3", "ssl")
	put("opt/excluded/bin/tool", "changed")
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	digest := func(alg, value string) *file.Digest { return &file.Digest{Algorithm: alg, Value: value} }
	deb := pkg.Package{Name: "tools", Version: "1", Type: pkg.DebPkg, PURL: "pkg:deb/debian/tools@1", Metadata: pkg.DpkgDBEntry{Files: []pkg.DpkgFileRecord{
		{Path: "/bin/dash", Digest: digest("md5", md5hex("dash"))},
		{Path: "/usr/bin/good", Digest: digest("md5", md5hex("good"))},
		{Path: "/usr/bin/replaced", Digest: digest("md5", md5hex("original"))},
		{Path: "/etc/tool.conf", Digest: digest("md5", md5hex("default")), IsConfigFile: true},
		{Path: "/usr/bin/removed", Digest: digest("md5", md5hex("gone"))},
		{Path: "/opt/excluded/bin/tool", Digest: digest("md5", md5hex("original"))},
		{Path: "/usr/share/doc/README", Digest: digest("md5", md5hex("not a binary"))},
	}}}
	rpm := pkg.Package{Name: "openssl-libs", Version: "3", Type: pkg.RpmPkg, PURL: "pkg:rpm/redhat/openssl-libs@3", Metadata: pkg.RpmDBEntry{Files: []pkg.RpmFileRecord{
		{Path: "/usr/lib64/libssl.so.3", Digest: file.Digest{Algorithm: "sha256", Value: sha256hex("ssl")}},
	}}}
	apk := pkg.Package{Name: "nginx", Version: "1", Type: pkg.ApkPkg, PURL: "pkg:apk/alpine/nginx@1", Metadata: pkg.ApkDBEntry{Files: []pkg.ApkFileRecord{
		{Path: "usr/sbin/nginx", Digest: digest("'Q1'+base64(sha1)", q1("nginx"))},
	}}}
	for _, p := range []*pkg.Package{&deb, &rpm, &apk} {
		p.SetID()
	}
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(deb, rpm, apk)}}
	plan, err := localfs.Build(context.Background(), root, []string{"/opt/excluded"})
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyPackageFiles(context.Background(), inventory, plan, DefaultIntegrityBudget)
	if result.Status != "completed" || result.CheckedFiles != 5 || result.ModifiedFiles != 1 || result.MissingFiles != 1 {
		t.Fatalf("unexpected result %+v", result)
	}
	result.ResolvePURLs(inventory)
	props := result.Properties()["pkg:deb/debian/tools@1"]
	if len(props) != 2 || props[0] != [2]string{IntegrityModifiedProperty, "/usr/bin/replaced"} || props[1] != [2]string{IntegrityMissingProperty, "/usr/bin/removed"} {
		t.Fatalf("properties %v", props)
	}
	if budget := VerifyPackageFiles(context.Background(), inventory, plan, 1); budget.Status != "partial" {
		t.Fatalf("exhausted budget must be partial: %+v", budget)
	}
}
