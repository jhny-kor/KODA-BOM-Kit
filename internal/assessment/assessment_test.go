package assessment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestAdvisoryCorrelatesActivationAndDeviceIdentity(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","components":[
		{"type":"device","name":"System board","bom-ref":"board","manufacturer":{"name":"OEM"},"properties":[{"name":"koda:asset:model","value":"R5"}]},
		{"type":"firmware","name":"BMC firmware","bom-ref":"active","version":"1.0","properties":[{"name":"koda:asset:parent-id","value":"board"},{"name":"koda:asset:evidence:applicationState","value":"Active"}]},
		{"type":"firmware","name":"BMC firmware","bom-ref":"staged","version":"2.0","properties":[{"name":"koda:asset:parent-id","value":"board"},{"name":"koda:asset:evidence:applicationState","value":"Staged"}]},
		{"type":"firmware","name":"BMC firmware","bom-ref":"unrelated","version":"1.0"},
		{"type":"library","name":"ssh","bom-ref":"ssh","version":"8.7p1-38.el9_4.1","purl":"pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1?distro=rhel-9.4"},
		{"type":"library","name":"ssh","bom-ref":"other-dist","version":"8.7p1-38.el9_4.1","purl":"pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1?distro=other-9.4"}]}`
	rules := Rules{Schema: "koda-advisory-rules-v1", PublishedAt: "2026-11-18T00:00:00Z", Rules: []Rule{
		{ID: "OEM-advisory", Source: "OEM", Component: &Selector{Kind: "firmware", Name: "BMC firmware", Vendor: "OEM", Model: "R5"}, AffectedVersions: []string{"1.0"}, FixedVersions: []string{"2.0"}},
		{ID: "RPM-advisory", Source: "Security Advisory", Component: &Selector{PURL: "pkg:rpm/redhat/openssh?distro=rhel-9.4"}, FixedVersions: []string{"8.7p1-38.el9_4.1"}},
		{ID: "CONFIG", Source: "Policy", Setting: &SettingSelector{Product: "Linux kernel", Name: "net.ipv4.ip_forward", Equals: "0"}},
	}}
	encoded, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	c := model.Context{
		ProcessLinks: []model.ProcessLink{{RuntimeFiles: []model.RuntimeFile{{PURL: "pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1?distro=rhel-9.4", State: "restart_review"}}}},
		Settings:     []model.Setting{{Product: "Linux kernel", Name: "net.ipv4.ip_forward", Value: "1", State: "declared"}},
	}
	got, err := evaluate(context.Background(), []byte(bom), encoded, c)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"active": "affected_version_observed", "staged": "activation_review", "ssh": "activation_review", "": "review_required"}
	if len(got.Findings) != len(want) {
		t.Fatalf("findings = %#v", got.Findings)
	}
	for _, f := range got.Findings {
		if want[f.ComponentRef] != f.Status {
			t.Fatalf("incorrect finding %#v", f)
		}
	}
}

func TestContextMustMatchScanChecksums(t *testing.T) {
	dir := t.TempDir()
	bom := filepath.Join(dir, "sbom.cdx.json")
	snapshot := filepath.Join(dir, "context.json")
	for _, path := range []string{bom, snapshot} {
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	checksums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(checksums, []byte("abc  sbom.cdx.json\ndef  context.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := boundContext(bom, "abc", snapshot, "def"); err != nil {
		t.Fatal(err)
	}
	if err := boundContext(bom, "abc", snapshot, "different"); err == nil {
		t.Fatal("mismatched context accepted")
	}
}
