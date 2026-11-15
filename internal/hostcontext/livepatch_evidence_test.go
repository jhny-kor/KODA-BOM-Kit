package hostcontext

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testLivepatchIdentity() livepatchIdentity {
	return livepatchIdentity{Kernel: "6.8.0-47-generic", BootIDHash: strings.Repeat("a", 64), Now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
}

func TestCanonicalEvidenceRetainsOnlyRunningPatchedCVEs(t *testing.T) {
	raw := []byte(`{"Last-Check":"2026-10-29T11:59:00Z","Machine-Id":"PRIVATE_MACHINE","Client-Version":"1","Token":"PRIVATE_TOKEN","Status":[{"Running":false,"Kernel":"6.8.0-99-generic","Livepatch":{"State":"applied","Fixes":[{"Name":"CVE-2026-99999","Patched":true}]}},{"Running":true,"Kernel":"6.8.0-47.47-generic","Livepatch":{"State":"applied","CheckState":"checked","Version":"108.3","Fixes":[{"Name":"CVE-2026-98432","Patched":true},{"Name":"CVE-2026-12345","Patched":false}]}}]}`)
	encoded, err := captureLivepatchEvidence("canonical-livepatch", raw, "", testLivepatchIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"PRIVATE_MACHINE", "PRIVATE_TOKEN", "CVE-2026-99999"} {
		if strings.Contains(string(encoded), value) {
			t.Fatalf("unrelated/private value retained: %s", value)
		}
	}
	status, err := loadLivepatchEvidenceBytes(context.Background(), encoded, testLivepatchIdentity())
	if err != nil || status.Status != "observed" || len(status.Patches) != 2 {
		t.Fatalf("unexpected status %+v %v", status, err)
	}
	if status.Patches[0].State != "reported-applied" || status.Patches[1].State != "not-reported-patched" {
		t.Fatalf("patched/unpatched distinction lost: %+v", status.Patches)
	}
}

func TestCanonicalReportKernelMustMatchCaptureKernelWithPackageBuildNormalization(t *testing.T) {
	for _, kernel := range []string{"6.8.0-47-generic", "6.8.0-47.47-generic", "6.8.0-99-generic"} {
		raw := []byte(`{"Status":[{"Running":true,"Kernel":"` + kernel + `","Livepatch":{"State":"applied","Fixes":[{"Name":"CVE-2026-98432","Patched":true}]}}]}`)
		_, err := captureLivepatchEvidence("canonical-livepatch", raw, "", testLivepatchIdentity())
		if (err != nil) != strings.Contains(kernel, "-99-") {
			t.Fatalf("unexpected matching outcome for %s: %v", kernel, err)
		}
	}
}

func TestCanonicalCachedLastCheckCannotBeRefreshedByNewCaptureTime(t *testing.T) {
	for _, tc := range []struct{ lastCheck, checkState, want string }{
		{"2026-10-27T12:00:00Z", "checked", "stale"},
		{"2026-10-29T12:10:00Z", "checked", "stale"},
		{"", "checked", "unknown"},
		{"2026-10-29T11:59:00Z", "check-failed", "unknown"},
	} {
		raw := []byte(`{"Last-Check":"` + tc.lastCheck + `","Status":[{"Running":true,"Kernel":"6.8.0-47.47-generic","Livepatch":{"State":"applied","CheckState":"` + tc.checkState + `","Fixes":[{"Name":"CVE-2026-98432","Patched":true}]}}]}`)
		encoded, err := captureLivepatchEvidence("canonical-livepatch", raw, "", testLivepatchIdentity())
		if err != nil {
			t.Fatal(err)
		}
		status, err := loadLivepatchEvidenceBytes(context.Background(), encoded, testLivepatchIdentity())
		if err != nil || status.Status != tc.want || status.Patches[0].State != "unknown" {
			t.Fatalf("stale/failed client cache remained current: %+v %v", status, err)
		}
	}
}

func TestKspliceEvidenceOnlyUsesInstalledSectionAndCVEFixPrefix(t *testing.T) {
	raw := []byte("Ksplice kernel updates:\nInstalled updates:\n[abcd12] CVE-2026-98432: Fix kernel issue.\n[other12] Known exploit detection for CVE-2026-11111.\nAvailable updates:\n[future12] CVE-2026-22222: Available update.\nEffective kernel version is 5.4.17-2136.360.3.1.el8uek\n")
	encoded, err := captureLivepatchEvidence("ksplice", raw, "", testLivepatchIdentity())
	if err != nil {
		t.Fatal(err)
	}
	status, err := loadLivepatchEvidenceBytes(context.Background(), encoded, testLivepatchIdentity())
	if err != nil || len(status.Patches) != 2 {
		t.Fatalf("unexpected Ksplice status %+v %v", status, err)
	}
	if len(status.Patches[0].CVEs) != 1 || len(status.Patches[1].CVEs) != 0 || strings.Contains(string(encoded), "CVE-2026-22222") {
		t.Fatalf("uninstalled or detection CVE treated as fixed: %s", encoded)
	}
}

func TestEvidenceStaleBootMismatchAndFutureCannotRemainApplied(t *testing.T) {
	identity := testLivepatchIdentity()
	encoded, err := captureLivepatchEvidence("uptrack", []byte("Installed updates:\n[abc123] CVE-2026-98432: Fixed.\n"), "5.4.17-2136.360.3.1.el8uek", identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		want   string
		change func(*livepatchIdentity)
	}{
		{"stale", "stale", func(i *livepatchIdentity) { i.Now = i.Now.Add(25 * time.Hour) }},
		{"future", "stale", func(i *livepatchIdentity) { i.Now = i.Now.Add(-10 * time.Minute) }},
		{"boot", "identity_mismatch", func(i *livepatchIdentity) { i.BootIDHash = strings.Repeat("b", 64) }},
		{"kernel", "identity_mismatch", func(i *livepatchIdentity) { i.Kernel = "6.8.0-99-generic" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := identity
			tc.change(&i)
			status, err := loadLivepatchEvidenceBytes(context.Background(), encoded, i)
			if err != nil || status.Status != tc.want || status.Patches[0].State != "unknown" || status.Patches[0].ReportedState != "applied" {
				t.Fatalf("unbound evidence remained applied: %+v %v", status, err)
			}
		})
	}
}

func TestLivepatchEvidenceRejectsUnstructuredAndOversizedReports(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"Status":[{"Running":true,"Livepatch":{"State":"applied"}}],"unexpected":"allowed raw but missing kernel"}`), []byte("available updates only"), []byte(strings.Repeat("x", maxLivepatchReportBytes+1))} {
		if _, err := captureLivepatchEvidence("uptrack", raw, "", testLivepatchIdentity()); err == nil {
			t.Fatal("invalid client report accepted")
		}
	}
	if _, err := captureLivepatchEvidence("untrusted-provider", nil, "", testLivepatchIdentity()); err == nil {
		t.Fatal("arbitrary provider accepted")
	}
}

func TestEvidenceImportRejectsUnknownFieldsAndArbitraryStatusText(t *testing.T) {
	encoded, err := captureLivepatchEvidence("uptrack", []byte("Installed updates:\nNone\n"), "", testLivepatchIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		t.Fatal(err)
	}
	data["secret"] = "TOKEN_SECRET"
	mutated, _ := json.Marshal(data)
	if _, err := loadLivepatchEvidenceBytes(context.Background(), mutated, testLivepatchIdentity()); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
	delete(data, "secret")
	data["report"].(map[string]any)["limitations"] = []string{"TOKEN_SECRET"}
	mutated, _ = json.Marshal(data)
	status, err := loadLivepatchEvidenceBytes(context.Background(), mutated, testLivepatchIdentity())
	if err != nil {
		t.Fatal(err)
	}
	clean, _ := json.Marshal(status)
	if strings.Contains(string(clean), "TOKEN_SECRET") {
		t.Fatal("arbitrary imported metadata leaked")
	}
}
