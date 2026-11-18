package assetimport

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImports(t *testing.T) {
	for _, raw := range []string{
		`{"Devices":[{"Name":"NVMe","Version":"2.1","Serial":"SECRET","VersionRaw":12}]}`,
		`{"@odata.type":"#SoftwareInventory.v1_15_0.SoftwareInventory","Name":"BMC","Version":"1.2","ImageState":"Staged"}`,
		`{"schema":"koda-assets-1","assets":[{"id":"board","kind":"device","name":"PLC"},{"id":"fw","parentId":"board","kind":"firmware","name":"Controller firmware","version":"1.1","properties":{"password":"SECRET","storedVersion":"1.2"}}]}`,
	} {
		p := filepath.Join(t.TempDir(), "input.json")
		os.WriteFile(p, []byte(raw), 0600)
		assets, _, err := Load(context.Background(), p)
		if err != nil || len(assets) == 0 {
			t.Fatalf("import: %v", err)
		}
		for _, a := range assets {
			if len(a.Properties["evidenceSHA256"]) != 64 {
				t.Fatal("missing digest")
			}
			for _, v := range a.Properties {
				if strings.Contains(v, "SECRET") {
					t.Fatal("private field leaked")
				}
			}
		}
	}
}
func TestRejectInvalidEvidence(t *testing.T) {
	for _, raw := range []string{`{}`, `{"schema":"wrong"}`, `{"Devices":[]}`, `{"Devices":[{"Name":42}]}`, `{"schema":"koda-assets-1","assets":[{"id":"x","kind":"device","name":"x","parentId":"missing"}]}`, `{"schema":"koda-assets-1","assets":[{"id":"x","kind":"device","name":"x"},{"id":"x","kind":"device","name":"y"}]}`} {
		p := filepath.Join(t.TempDir(), "input.json")
		os.WriteFile(p, []byte(raw), 0600)
		if _, _, err := Load(context.Background(), p); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestUnexpandedRedfish(t *testing.T) {
	p := filepath.Join(t.TempDir(), "input.json")
	os.WriteFile(p, []byte(`{"Members":[{"@odata.id":"https://example.invalid/private"}]}`), 0600)
	a, i, e := Load(context.Background(), p)
	if e != nil || len(a) != 0 || len(i) != 1 {
		t.Fatalf("%v %v %v", a, i, e)
	}
}

func TestSoftwareEvidence(t *testing.T) {
	raw := `{"schema":"koda-assets-1","assets":[{"id":"a","kind":"library","name":"example","version":"1.0","purl":"pkg:npm/example@1.0","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	p := filepath.Join(t.TempDir(), "input.json")
	os.WriteFile(p, []byte(raw), 0600)
	a, _, err := Load(context.Background(), p)
	if err != nil || a[0].PURL != "pkg:npm/example@1.0" || len(a[0].SHA256) != 64 {
		t.Fatalf("software import %v %v", a, err)
	}
	for _, bad := range []string{strings.ReplaceAll(raw, "pkg:npm/example@1.0", "pkg:npm/example@2.0"), strings.ReplaceAll(raw, "pkg:npm/example@1.0", "pkg:npm/example@1.0?token=secret"), strings.ReplaceAll(raw, strings.Repeat("a", 64), "bad")} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, _, err := Load(context.Background(), p); err == nil {
			t.Fatal("invalid software identity accepted")
		}
	}
}

func TestDevlinkVersions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "input.json")
	os.WriteFile(p, []byte(`{"info":{"pci/0000:01:00.0":{"driver":"ice","serial_number":"SECRET","versions":{"fixed":{"board.id":"A"},"running":{"fw":"1.0"},"stored":{"fw":"2.0"}}}}}`), 0600)
	a, _, err := Load(context.Background(), p)
	if err != nil || len(a) != 1 || a[0].Version != "1.0" || a[0].Properties["stored.fw"] != "2.0" {
		t.Fatalf("devlink import %v %v", a, err)
	}
}
