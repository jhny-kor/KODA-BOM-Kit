package collect

import (
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
