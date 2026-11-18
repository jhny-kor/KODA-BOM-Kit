package collect

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/model"
	"testing"
)

func TestRuntimePackageLinkUsesInstalledOwnership(t *testing.T) {
	component := pkg.Package{Name: "openssl", Version: "3.0.1-fixed", Type: pkg.RpmPkg, Metadata: pkg.RpmDBEntry{Files: []pkg.RpmFileRecord{{Path: "/usr/lib/libssl.so"}}}}
	component.SetID()
	inventory := &sbom.SBOM{}
	inventory.Artifacts.Packages = pkg.NewCollection(component)
	ctx := model.Context{ProcessLinks: []model.ProcessLink{{FilesystemComparable: true, RuntimeFiles: []model.RuntimeFile{{Path: "usr/lib/libssl.so", Deleted: true, State: "restart_review"}}}}}
	LinkRuntimePackages(&ctx, inventory)
	got := ctx.ProcessLinks[0].RuntimeFiles[0]
	if got.Package != "openssl" || got.InstalledVersion != "3.0.1-fixed" || got.State != "restart_review" || !got.Deleted {
		t.Fatalf("lost runtime evidence: %+v", got)
	}
	component.Name = "other-owner"
	component.SetID()
	inventory.Artifacts.Packages.Add(component)
	ctx.ProcessLinks[0].RuntimeFiles[0].Package = ""
	ctx.ProcessLinks[0].RuntimeFiles[0].InstalledVersion = ""
	LinkRuntimePackages(&ctx, inventory)
	if ctx.ProcessLinks[0].RuntimeFiles[0].Package != "" {
		t.Fatal("ambiguous ownership selected")
	}
}

func TestUnidentifiedExecutables(t *testing.T) {
	gobin := pkg.Package{Name: "github.com/acme/agent", Version: "v1.2.0", Type: pkg.GoModulePkg, Locations: file.NewLocationSet(file.NewLocation("/opt/agent/bin/agent"))}
	gobin.SetID()
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(gobin)}}
	ctx := model.Context{ProcessLinks: []model.ProcessLink{
		{PID: 10, Executable: "usr/sbin/sshd", FilesystemComparable: true, RuntimeFiles: []model.RuntimeFile{{Path: "usr/sbin/sshd", PURL: "pkg:deb/debian/openssh-server@1"}}},
		{PID: 11, Executable: "opt/agent/bin/agent", FilesystemComparable: true},
		{PID: 12, Executable: "opt/jdk-21/bin/java", FilesystemComparable: true},
		{PID: 13, Executable: "usr/local/bin/miner", FilesystemComparable: true},
		{PID: 14, Executable: "usr/local/bin/miner", FilesystemComparable: true},
		{PID: 15, Executable: "usr/bin/inside-container"},
		{PID: 16, Executable: "usr/local/bin/replaced", FilesystemComparable: true, ExecutableDeleted: true},
	}}
	UnidentifiedExecutables(&ctx, inventory, []model.Product{{Name: "OpenJDK", InstallPath: "opt/jdk-21"}})
	if len(ctx.UnidentifiedExecutables) != 1 || ctx.UnidentifiedExecutables[0].Path != "usr/local/bin/miner" || len(ctx.UnidentifiedExecutables[0].PIDs) != 2 {
		t.Fatalf("got %+v", ctx.UnidentifiedExecutables)
	}
}

func TestRuntimeLinkMatchesUsrMergedPackagePaths(t *testing.T) {
	previous := usrMerged
	usrMerged = func() map[string]string { return map[string]string{"bin": "usr/bin"} }
	defer func() { usrMerged = previous }()
	dash := pkg.Package{Name: "dash", Version: "0.5.12-2", Type: pkg.DebPkg, PURL: "pkg:deb/debian/dash@0.5.12-2",
		Metadata: pkg.DpkgDBEntry{Files: []pkg.DpkgFileRecord{{Path: "/bin/dash"}}}}
	dash.SetID()
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(dash)}}
	ctx := model.Context{ProcessLinks: []model.ProcessLink{{PID: 1, Executable: "usr/bin/dash", FilesystemComparable: true,
		RuntimeFiles: []model.RuntimeFile{{Path: "usr/bin/dash"}}}}}
	LinkRuntimePackages(&ctx, inventory)
	UnidentifiedExecutables(&ctx, inventory, nil)
	if ctx.ProcessLinks[0].RuntimeFiles[0].Package != "dash" || len(ctx.UnidentifiedExecutables) != 0 {
		t.Fatalf("usr-merged owner not linked: %+v %+v", ctx.ProcessLinks[0].RuntimeFiles, ctx.UnidentifiedExecutables)
	}
	if got := canonicalPath("/binary/x", map[string]string{"bin": "usr/bin"}); got != "binary/x" {
		t.Fatalf("prefix must match a whole directory name: %q", got)
	}
}
