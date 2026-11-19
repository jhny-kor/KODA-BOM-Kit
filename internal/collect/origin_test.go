package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/pierrec/lz4/v4"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

func originFixture(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, v := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func originInventory(packages ...pkg.Package) *sbom.SBOM {
	for i := range packages {
		packages[i].SetID()
	}
	return &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(packages...)}}
}

func originsOf(t *testing.T, root string, inventory *sbom.SBOM) (OriginResult, map[string]string) {
	t.Helper()
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := PackageOrigins(context.Background(), inventory, plan)
	result.ResolvePURLs(inventory)
	got := map[string]string{}
	for purl, pairs := range result.Properties() {
		for _, p := range pairs {
			got[purl+" "+p[0]] = p[1]
		}
	}
	return result, got
}

func TestDebOriginsFromAptIndexes(t *testing.T) {
	root := t.TempDir()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte("Package: curl\nVersion: 7.88.1-10\n\n"))
	w.Close()
	var lz bytes.Buffer
	lw := lz4.NewWriter(&lz)
	lw.Write([]byte("Package: openssl\nVersion: 3.0.15-1\n\n"))
	lw.Close()
	originFixture(t, root, map[string]string{
		"var/lib/apt/lists/mirror.example_debian_dists_bookworm_main_binary-amd64_Packages":                       "Package: bash\nVersion: 5.2.15-2\nDescription: shell\n\n",
		"var/lib/apt/lists/mirror.example_debian_dists_bookworm-updates_main_binary-amd64_Packages.gz":            gz.String(),
		"var/lib/apt/lists/mirror.example_debian-security_dists_bookworm-security_main_binary-amd64_Packages.lz4": lz.String(),
	})
	inventory := originInventory(
		pkg.Package{Name: "bash", Version: "5.2.15-1", PURL: "pkg:deb/debian/bash@5.2.15-1", Metadata: pkg.DpkgDBEntry{Package: "bash"}},
		pkg.Package{Name: "curl", Version: "7.88.1-10", PURL: "pkg:deb/debian/curl@7.88.1-10", Metadata: pkg.DpkgDBEntry{Package: "curl"}},
		pkg.Package{Name: "openssl", Version: "3.0.15-1", PURL: "pkg:deb/debian/openssl@3.0.15-1", Metadata: pkg.DpkgDBEntry{Package: "openssl"}},
		pkg.Package{Name: "vendor-agent", Version: "3.1", PURL: "pkg:deb/debian/vendor-agent@3.1", Metadata: pkg.DpkgDBEntry{Package: "vendor-agent"}},
	)
	result, got := originsOf(t, root, inventory)
	if got["pkg:deb/debian/bash@5.2.15-1 "+PackageOriginProperty] != OriginRepository ||
		got["pkg:deb/debian/curl@7.88.1-10 "+PackageOriginProperty] != OriginRepository ||
		got["pkg:deb/debian/openssl@3.0.15-1 "+PackageOriginProperty] != OriginRepository ||
		got["pkg:deb/debian/vendor-agent@3.1 "+PackageOriginProperty] != OriginNotRecorded {
		t.Fatalf("properties %v", got)
	}
	if len(result.Findings) != 1 || result.Findings[0].Package != "vendor-agent" || result.Sources[0] != "var/lib/apt/lists" {
		t.Fatalf("result %+v", result)
	}
	// Without any index the origin is unknown, not "not-recorded".
	if empty, _ := originsOf(t, t.TempDir(), inventory); empty.Status != "not_applicable" {
		t.Fatalf("no index must not classify packages: %+v", empty)
	}
}

func TestRPMOriginsFromDnfHistory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "var/lib/dnf")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "history.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE repo (id INTEGER PRIMARY KEY, repoid TEXT)`,
		`CREATE TABLE rpm (item_id INTEGER PRIMARY KEY, name TEXT, epoch INTEGER, version TEXT, release TEXT, arch TEXT)`,
		`CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER, item_id INTEGER, repo_id INTEGER, action INTEGER, reason INTEGER, state INTEGER)`,
		`INSERT INTO repo VALUES (1, 'baseos'), (2, '@commandline'), (3, 'appstream')`,
		`INSERT INTO rpm VALUES (10, 'bash', 0, '5.1.8', '9.el9', 'x86_64'), (11, 'agent', 0, '2.0', '1', 'x86_64'), (12, 'nginx', 1, '1.20.1', '14.el9', 'x86_64')`,
		`INSERT INTO trans_item VALUES (1, 1, 10, 1, 1, 0, 1), (2, 2, 11, 2, 1, 0, 1), (3, 3, 12, 3, 1, 0, 2)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	rpm := func(name, version, release string) pkg.Package {
		return pkg.Package{Name: name, Version: version + "-" + release, PURL: "pkg:rpm/redhat/" + name + "@" + version + "-" + release,
			Metadata: pkg.RpmDBEntry{Name: name, Version: version, Release: release, Arch: "x86_64"}}
	}
	inventory := originInventory(rpm("bash", "5.1.8", "9.el9"), rpm("agent", "2.0", "1"), rpm("nginx", "1.20.1", "14.el9"))
	result, got := originsOf(t, root, inventory)
	want := map[string]string{
		"pkg:rpm/redhat/bash@5.1.8-9.el9 " + PackageOriginProperty:     OriginRepository,
		"pkg:rpm/redhat/bash@5.1.8-9.el9 " + PackageRepositoryProperty: "baseos",
		"pkg:rpm/redhat/agent@2.0-1 " + PackageOriginProperty:          OriginLocalFile,
		"pkg:rpm/redhat/nginx@1.20.1-14.el9 " + PackageOriginProperty:  OriginNotRecorded, // failed transaction
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if result.Counts[OriginRepository] != 1 || len(result.Findings) != 2 {
		t.Fatalf("result %+v", result)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("history directory must stay untouched: %v", entries)
	}
}

func TestRPMOriginsFromYumdb(t *testing.T) {
	root := t.TempDir()
	originFixture(t, root, map[string]string{
		"var/lib/yum/yumdb/b/0123456789abcdef0123456789abcdef01234567-bash-4.2.46-35.el7_9-x86_64/from_repo": "updates\n",
		"var/lib/yum/yumdb/a/0123456789abcdef0123456789abcdef01234567-agent-2.0-1-x86_64/from_repo":          "/root/agent-2.0-1.x86_64\n",
		"var/lib/yum/yumdb/a/0123456789abcdef0123456789abcdef01234567-agent-2.0-1-x86_64/installed_by":       "0\n",
	})
	inventory := originInventory(
		pkg.Package{Name: "bash", PURL: "pkg:rpm/centos/bash@4.2.46-35.el7_9", Metadata: pkg.RpmDBEntry{Name: "bash", Version: "4.2.46", Release: "35.el7_9", Arch: "x86_64"}},
		pkg.Package{Name: "agent", PURL: "pkg:rpm/centos/agent@2.0-1", Metadata: pkg.RpmDBEntry{Name: "agent", Version: "2.0", Release: "1", Arch: "x86_64"}},
	)
	_, got := originsOf(t, root, inventory)
	if got["pkg:rpm/centos/bash@4.2.46-35.el7_9 "+PackageRepositoryProperty] != "updates" || got["pkg:rpm/centos/agent@2.0-1 "+PackageOriginProperty] != OriginLocalFile {
		t.Fatalf("properties %v", got)
	}
	for k, v := range got {
		if v == "/root/agent-2.0-1.x86_64" {
			t.Fatalf("local file path leaked in %s", k)
		}
	}
}

func TestLinkServicesNamesUnitsOnOwningPackage(t *testing.T) {
	inventory := originInventory(pkg.Package{Name: "openssh-server", PURL: "pkg:deb/debian/openssh-server@1", Metadata: pkg.DpkgDBEntry{Files: []pkg.DpkgFileRecord{{Path: "/usr/sbin/sshd"}}}})
	context := model.Context{EnabledServices: []model.Service{
		{Unit: "ssh.socket", Executable: "usr/sbin/sshd", State: "stopped"},
		{Unit: "custom.service", Executable: "opt/app/bin/app"},
	}}
	props := LinkServices(&context, inventory, t.TempDir())
	if got := props["pkg:deb/debian/openssh-server@1"]; len(got) != 1 || got[0] != [2]string{EnabledServiceProperty, "ssh.socket (stopped)"} {
		t.Fatalf("properties %v", props)
	}
	if context.EnabledServices[0].PURL != "pkg:deb/debian/openssh-server@1" || context.EnabledServices[1].PURL != "" {
		t.Fatalf("services %+v", context.EnabledServices)
	}
}
