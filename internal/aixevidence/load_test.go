package aixevidence

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	testHome  = "/u01/app/oracle/dbhome_1"
	testPatch = `Patch 36912597 : applied on Tue Oct 15 02:55:20 UTC 2024
Patch description: "DATABASE RELEASE UPDATE : 19.25.0.0.241015 (36912597)"`
	testListener = "01 f7 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 00 00 00\n"
)

func bundle(t *testing.T, withOracle bool) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"oslevel.txt": "7200-05-10-2420\n",
		"lslpp.txt":   "#Package Name:Fileset:Level:State:PTF Id:Fix State:Type:Description\nbos.rte:bos.rte:7.2.5.0: : : C : F :Base OS\nOpenSSL:openssl.base:1.1.2.2000:A:U000000::F:OpenSSL\n",
		"emgr.txt":    "1 S IJ49378m1d 02/06/24 23:23:27 IJ49378 EFIXTOOLS MULTI-FIX\nEFIX LABEL: IJ49378m1d\nAPAR number: IJ49378\n",
	}
	if withOracle {
		files["oracle-home.txt"] = testHome + "\n"
		files["opatch.txt"] = "Oracle Home : " + testHome + "\nInterim patches (1) :\n" + testPatch + "\nOPatch succeeded.\n"
		files["listener.txt"] = testListener
		files["sqlpatch.csv"] = "database_id,patch_id,action,status,action_time\nsecret-db,36912597,APPLY,SUCCESS,2024-10-15T03:00:00.012345\nsecret-db,36912597,ROLLBACK,WITH ERRORS,2024-10-15T04:00:00\n"
	}
	for name, contents := range files {
		write(t, dir, name, contents)
	}
	manifest := Schema + "\n"
	for _, name := range sources {
		status := "omitted"
		if _, ok := files[name]; ok {
			status = "ok"
		}
		manifest += name + "\t" + status + "\n"
	}
	write(t, dir, "capture.tsv", manifest)
	return dir
}

func write(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCorroboratesOracleHomeAndPreservesSQLHistory(t *testing.T) {
	dir := bundle(t, true)
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.Issues) != 0 || len(inventory.OracleHomes) != 1 {
		t.Fatalf("unexpected inventory: %+v, %v", inventory, err)
	}
	if inventory.OSLevel != "7200-05-10-2420" || len(inventory.Filesets) != 2 || len(inventory.InterimFixes) != 1 || len(inventory.EvidenceSHA256) != 8 {
		t.Fatalf("missing AIX evidence: %+v", inventory)
	}
	if f := inventory.InterimFixes[0]; f.State != "S" || !slices.Equal(f.APARs, []string{"IJ49378"}) {
		t.Fatalf("wrong interim fix: %+v", f)
	}
	home := inventory.OracleHomes[0]
	if strings.Contains(home.Path, testHome) || home.ReleaseUpdate != "19.25.0.0.241015" || home.DatabaseVersion != "19.25.0.0.0" ||
		!home.ListenerInstalled || home.ListenerVersion != home.DatabaseVersion || !slices.Equal(home.PatchIDs, []string{"36912597"}) {
		t.Fatalf("wrong Home or Listener evidence: %+v", home)
	}
	if home.ListenerVersionSource != "opatch_inventory_ru" || home.ListenerReleaseBasis != "database_ru" ||
		!slices.Equal(home.ListenerReleasePatchIDs, []string{"36912597"}) {
		t.Fatalf("missing Listener version provenance: %+v", home)
	}
	if len(home.SQLPatches) != 2 || home.SQLPatches[0].DatabaseID == "secret-db" || home.SQLPatches[0].DatabaseID != home.SQLPatches[1].DatabaseID ||
		home.SQLPatches[1].Action != "ROLLBACK" || home.SQLPatches[1].Status != "WITH ERRORS" {
		t.Fatalf("wrong SQL patch history: %+v", home.SQLPatches)
	}
}

func TestLoadRejectsUnverifiedOPatch(t *testing.T) {
	tests := map[string]string{
		"other home":      "Oracle Home : /u01/grid\nInterim patches (1) :\n" + testPatch + "\nOPatch succeeded.\n",
		"failed":          "Oracle Home : " + testHome + "\nInterim patches (1) :\n" + testPatch + "\nOPatch failed.\n",
		"missing count":   "Oracle Home : " + testHome + "\n" + testPatch + "\nOPatch succeeded.\n",
		"missing patch":   "Oracle Home : " + testHome + "\nInterim patches (2) :\n" + testPatch + "\nOPatch succeeded.\n",
		"duplicate patch": "Oracle Home : " + testHome + "\nInterim patches (2) :\n" + testPatch + "\n" + testPatch + "\nOPatch succeeded.\n",
		"invalid count":   "Oracle Home : " + testHome + "\nInterim patches (99999999999999) :\n" + testPatch + "\nOPatch succeeded.\n",
	}
	for name, report := range tests {
		t.Run(name, func(t *testing.T) {
			dir := bundle(t, true)
			write(t, dir, "opatch.txt", report)
			inventory, err := Load(context.Background(), dir)
			if err != nil || len(inventory.OracleHomes) != 0 || len(inventory.Issues) != 1 || inventory.Issues[0].Code != "oracle_inventory_unverified" {
				t.Fatalf("unverified report entered inventory: %+v, %v", inventory, err)
			}
		})
	}
}

func TestConflictDoesNotBorrowOtherHomeComponentVersion(t *testing.T) {
	dir := bundle(t, true)
	report := "Oracle Home : " + testHome + "\nInterim patches (3) :\n" + testPatch + `
Patch 39990000 : applied on Tue Oct 15 02:55:20 UTC 2024
Patch description: "DATABASE RELEASE UPDATE : 19.24.0.0.240715 (39990000)"
Patch 38889900 : applied on Tue Oct 15 02:55:20 UTC 2024
Patch description: "Grid Infrastructure Oct 2024 Release Update : 19.25.0.0.241015 (38889900)"
OPatch succeeded.
`
	write(t, dir, "opatch.txt", report)
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.OracleHomes) != 1 {
		t.Fatalf("could not retain verified patch IDs: %+v, %v", inventory, err)
	}
	home := inventory.OracleHomes[0]
	if home.DatabaseVersion != "" || home.GridVersion == "" || home.ListenerVersion != "" || !home.ListenerInstalled {
		t.Fatalf("version conflict was hidden: %+v", home)
	}
	if home.ListenerReleaseBasis != "" || home.ListenerVersionSource != "" || len(home.ListenerReleasePatchIDs) > 0 {
		t.Fatalf("conflicting patch evidence claimed a Listener release: %+v", home)
	}
	if len(inventory.Issues) != 2 || inventory.Issues[0].Code != "oracle_ru_conflict" || inventory.Issues[1].Code != "oracle_listener_version_unknown" {
		t.Fatalf("version conflict was not reported: %+v", inventory.Issues)
	}
}

func TestListenerReleaseUsesOnlyConsistentRUDescriptions(t *testing.T) {
	for _, release := range []string{"19.25.0.0.241015", "19.25.0.0.241016"} {
		t.Run(release, func(t *testing.T) {
			report := "Oracle Home : " + testHome + "\nInterim patches (3) :\n" + testPatch +
				"\nPatch 38889900 : applied on Tue Oct 15 02:55:20 UTC 2024\n" +
				"Patch description: \"GI Release Update : " + release + " (38889900)\"\n" +
				"Patch 39990000 : applied on Tue Oct 15 02:55:20 UTC 2024\n" +
				"Patch description: \"Interim patch for another component\"\nOPatch succeeded.\n"
			home, err := parseOracle(testHome, []byte(report))
			if err != nil || len(home.PatchIDs) != 3 {
				t.Fatalf("invalid OPatch result: %+v, %v", home, err)
			}
			if release != home.DatabaseRelease {
				if !home.releaseConflict || home.ListenerReleaseBasis != "" || listenerVersion(home) != "" {
					t.Fatalf("different raw releases collapsed to one Listener version: %+v", home)
				}
				return
			}
			if home.releaseConflict || home.ListenerReleaseBasis != "database_and_grid_ru" ||
				!slices.Equal(home.ListenerReleasePatchIDs, []string{"36912597", "38889900"}) || listenerVersion(home) != "19.25.0.0.0" {
				t.Fatalf("Listener release provenance included unrelated patches or lost an RU: %+v", home)
			}
		})
	}
}

func TestMissingOrUnboundedEvidenceBecomesPartial(t *testing.T) {
	dir := bundle(t, false)
	if err := os.Remove(filepath.Join(dir, "lslpp.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "oslevel.txt"), filepath.Join(dir, "lslpp.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "emgr.txt", strings.Repeat("x", 300<<10))
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.Issues) != 2 || len(inventory.Filesets) != 0 || len(inventory.InterimFixes) != 0 || inventory.OSLevel == "" {
		t.Fatalf("failed evidence was not isolated: %+v, %v", inventory, err)
	}
}

func TestBadManifestRejectedAndFailedSourceNeverImported(t *testing.T) {
	dir := bundle(t, true)
	path := filepath.Join(dir, "capture.tsv")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, "capture.tsv", strings.Replace(string(raw), "listener.txt\tok", "listener.txt\tfailed", 1))
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.OracleHomes) != 1 || inventory.OracleHomes[0].ListenerInstalled || len(inventory.Issues) != 1 {
		t.Fatalf("failed capture data used: %+v, %v", inventory, err)
	}
	write(t, dir, "capture.tsv", string(raw)+"unexpected\tok\n")
	if _, err := Load(context.Background(), dir); err == nil {
		t.Fatal("accepted an unknown manifest field")
	}
}

func TestListenerNeedsExecutableXCOFF(t *testing.T) {
	for _, value := range []string{"01 f7", strings.Replace(testListener, "00 02", "00 00", 1), "present", "#! sh"} {
		if ok, err := parseListener([]byte(value)); ok || err == nil {
			t.Errorf("accepted invalid Listener header %q", value)
		}
	}
	if ok, err := parseListener([]byte("absent\n")); ok || err != nil {
		t.Fatalf("explicit absence was not understood: %v, %v", ok, err)
	}
}
