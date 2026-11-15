package aixevidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const gridHome = "/u01/app/grid/gridhome_1"

func multiHomeManifest(count int) string {
	var manifest strings.Builder
	manifest.WriteString(SchemaMulti + "\n")
	for _, name := range sources[:3] {
		fmt.Fprintf(&manifest, "%s\tok\n", name)
	}
	for i := 1; i <= count; i++ {
		for _, name := range sources[3:] {
			status := "ok"
			if i > 1 && name == "sqlpatch.csv" {
				status = "omitted"
			}
			fmt.Fprintf(&manifest, "homes/%d/%s\t%s\n", i, name, status)
		}
	}
	return manifest.String()
}

func multiHomeBundle(t *testing.T) string {
	t.Helper()
	dir := bundle(t, true)
	for _, i := range []string{"1", "2"} {
		if err := os.MkdirAll(filepath.Join(dir, "homes", i), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range sources[3:] {
		if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, "homes", "1", name)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, dir, "homes/2/oracle-home.txt", gridHome+"\n")
	write(t, dir, "homes/2/opatch.txt", "Oracle Home : "+gridHome+"\n"+
		"Interim patches (1) :\n"+
		"Patch 38889900 : applied on Tue Jan 21 02:55:20 UTC 2025\n"+
		"Patch description: \"Grid Infrastructure Jan 2025 Release Update : 19.26.0.0.250121 (38889900)\"\n"+
		"OPatch succeeded.\n")
	write(t, dir, "homes/2/listener.txt", testListener)
	write(t, dir, "capture.tsv", multiHomeManifest(2))
	return dir
}

func TestLoadMultipleOracleHomesKeepsInstallationsSeparate(t *testing.T) {
	inventory, err := Load(context.Background(), multiHomeBundle(t))
	if err != nil || len(inventory.Issues) != 0 || len(inventory.OracleHomes) != 2 {
		t.Fatalf("unexpected inventory: %+v, %v", inventory, err)
	}
	db, grid := inventory.OracleHomes[0], inventory.OracleHomes[1]
	if db.Path == grid.Path || db.EvidencePrefix != "homes/1" || grid.EvidencePrefix != "homes/2" {
		t.Fatalf("home identities were not preserved: %+v", inventory.OracleHomes)
	}
	if db.DatabaseVersion != "19.25.0.0.0" || db.GridVersion != "" || db.ListenerVersion != "19.25.0.0.0" ||
		!slices.Equal(db.PatchIDs, []string{"36912597"}) || len(db.SQLPatches) != 2 {
		t.Fatalf("database evidence mixed with Grid: %+v", db)
	}
	if grid.GridVersion != "19.26.0.0.0" || grid.DatabaseVersion != "" || grid.ListenerVersion != "19.26.0.0.0" ||
		!slices.Equal(grid.PatchIDs, []string{"38889900"}) || len(grid.SQLPatches) != 0 {
		t.Fatalf("Grid evidence mixed with database: %+v", grid)
	}
	if len(inventory.EvidenceSHA256) != 11 || inventory.EvidenceSHA256["homes/1/opatch.txt"] == inventory.EvidenceSHA256["homes/2/opatch.txt"] {
		t.Fatalf("missing separate evidence digests: %+v", inventory.EvidenceSHA256)
	}
	raw, err := json.Marshal(inventory)
	if err != nil || strings.Contains(string(raw), testHome) || strings.Contains(string(raw), gridHome) || strings.Contains(string(raw), "secret-db") {
		t.Fatalf("private source data exported: %s, %v", raw, err)
	}
}

func TestLoadMultipleOracleHomesKeepsUsableEvidenceAfterFailure(t *testing.T) {
	dir := multiHomeBundle(t)
	write(t, dir, "capture.tsv", strings.Replace(multiHomeManifest(2), "homes/2/opatch.txt\tok", "homes/2/opatch.txt\tfailed", 1))
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.OracleHomes) != 1 || inventory.OracleHomes[0].EvidencePrefix != "homes/1" {
		t.Fatalf("failed Home changed the verified Home: %+v, %v", inventory, err)
	}
	if len(inventory.Issues) == 0 || inventory.Issues[0].Path != "homes/2/opatch.txt" ||
		inventory.Issues[0].Code != "aix_capture_failed" || inventory.EvidenceSHA256["homes/2/opatch.txt"] != "" {
		t.Fatalf("failed report was used or not attributed: %+v", inventory)
	}
}

func TestLoadRejectsDuplicateHomesAndInvalidManifest(t *testing.T) {
	dir := multiHomeBundle(t)
	write(t, dir, "homes/2/oracle-home.txt", testHome+"\n")
	if _, err := Load(context.Background(), dir); err == nil {
		t.Fatal("accepted a duplicate Oracle Home")
	}
	for _, invalid := range []string{
		multiHomeManifest(9),
		strings.ReplaceAll(multiHomeManifest(2), "homes/2/", "homes/1/"),
		strings.ReplaceAll(multiHomeManifest(2), "homes/2/", "homes/3/"),
		strings.ReplaceAll(multiHomeManifest(2), "homes/2/", "../"),
		strings.Replace(multiHomeManifest(2), "homes/2/oracle-home.txt\tok", "homes/2/oracle-home.txt\tomitted", 1),
	} {
		write(t, dir, "capture.tsv", invalid)
		if _, err := Load(context.Background(), dir); err == nil {
			t.Fatal("accepted an invalid Oracle Home manifest")
		}
	}
}

func TestLoadRejectsSymlinkedEvidenceDirectory(t *testing.T) {
	dir := multiHomeBundle(t)
	if err := os.Rename(filepath.Join(dir, "homes", "2"), filepath.Join(dir, "unlisted")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../unlisted", filepath.Join(dir, "homes", "2")); err != nil {
		t.Fatal(err)
	}
	inventory, err := Load(context.Background(), dir)
	if err != nil || len(inventory.OracleHomes) != 1 || len(inventory.Issues) != 1 ||
		inventory.Issues[0].Path != "homes/2" || inventory.Issues[0].Code != "aix_home_evidence_unreadable" {
		t.Fatalf("symlinked evidence was accepted or affected other Homes: %+v, %v", inventory, err)
	}
}
