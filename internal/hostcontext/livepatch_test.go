package hostcontext

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func livepatchFixture(t *testing.T, root, id, enabled, transition string) {
	t.Helper()
	write(t, root, "sys/kernel/livepatch/"+id+"/enabled", enabled)
	write(t, root, "sys/kernel/livepatch/"+id+"/transition", transition)
}

func observeLivepatch(t *testing.T, directory string) model.Context {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	out := model.Context{Status: "completed", Issues: []model.Issue{}}
	collectLivepatch(context.Background(), root, &out)
	return out
}

func TestLivepatchSysfsDistinguishesAppliedTransitioningAndDisabled(t *testing.T) {
	root := t.TempDir()
	livepatchFixture(t, root, "livepatch_applied", "1\n", "0\n")
	livepatchFixture(t, root, "livepatch_transition", "1\n", "1\n")
	livepatchFixture(t, root, "livepatch_disabled", "0\n", "0\n")
	out := observeLivepatch(t, root)
	if out.Status != "completed" || len(out.Livepatch) == 0 {
		t.Fatalf("unexpected observation: %+v", out)
	}
	status := out.Livepatch[0]
	if status.Provider != "linux-livepatch" || status.Status != "observed" || status.EvidenceKind != "live-kernel-sysfs" {
		t.Fatalf("unexpected source: %+v", status)
	}
	states := map[string]string{}
	for _, p := range status.Patches {
		states[p.ID] = p.State
		if len(p.CVEs) != 0 {
			t.Fatal("generic sysfs observation inferred CVE coverage")
		}
	}
	for id, want := range map[string]string{"livepatch_applied": "applied", "livepatch_transition": "transitioning", "livepatch_disabled": "disabled"} {
		if states[id] != want {
			t.Fatalf("%s=%s, want %s", id, states[id], want)
		}
	}
}

func TestMissingLivepatchSourceDoesNotClaimNotInstalledOrSafe(t *testing.T) {
	out := observeLivepatch(t, t.TempDir())
	if out.Status != "completed" || len(out.Livepatch) == 0 || out.Livepatch[0].Status != "not_observed" {
		t.Fatalf("unexpected absent source: %+v", out)
	}
	if len(out.Livepatch[0].Patches) != 0 || len(out.Livepatch[0].Limitations) == 0 {
		t.Fatal("absence was interpreted as a complete negative result")
	}
}

func TestInvalidLivepatchValuesAreUnknownAndNeverExported(t *testing.T) {
	root := t.TempDir()
	livepatchFixture(t, root, "invalid", "PASSWORD_CANARY\n", "0\n")
	out := observeLivepatch(t, root)
	if out.Status != "partial" || out.Livepatch[0].Status != "partial" || out.Livepatch[0].Patches[0].State != "unknown" {
		t.Fatalf("invalid state accepted: %+v", out)
	}
	data, _ := json.Marshal(out)
	if strings.Contains(string(data), "PASSWORD_CANARY") {
		t.Fatal("unvalidated sysfs value exported")
	}
}

func TestStaticTargetDoesNotCollectLivepatchSysfs(t *testing.T) {
	root := t.TempDir()
	livepatchFixture(t, root, "not_host", "1\n", "0\n")
	out := CollectWithPaths(context.Background(), root, true, nil)
	if len(out.Livepatch) != 0 || out.Mode != "filesystem" {
		t.Fatalf("non-host target inherited runtime facts: %+v", out)
	}
}

func TestLivepatchDirectoryAndReadLimits(t *testing.T) {
	root := t.TempDir()
	for i := range maxLivepatchEntries + 1 {
		id := strings.Repeat("a", i/26+1) + string(rune('a'+i%26))
		livepatchFixture(t, root, id, "1\n", "0\n")
	}
	out := observeLivepatch(t, root)
	if out.Status != "partial" || len(out.Livepatch[0].Patches) > maxLivepatchEntries {
		t.Fatalf("directory limit was not enforced: %+v", out)
	}
	root = t.TempDir()
	livepatchFixture(t, root, "large", strings.Repeat("1", maxLivepatchAttributeBytes+1), "0\n")
	out = observeLivepatch(t, root)
	if out.Status != "partial" || out.Livepatch[0].Patches[0].State != "unknown" {
		t.Fatal("oversized sysfs attribute accepted")
	}
}

func TestLivepatchKspliceLegacyStageDoesNotInferCVEs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sys/kernel/ksplice/test_id/stage", "applied\n")
	out := observeLivepatch(t, root)
	var seen bool
	for _, status := range out.Livepatch {
		if status.Provider != "ksplice-legacy" || status.Source != "sys/kernel/ksplice" {
			continue
		}
		if status.Status != "observed" || len(status.Patches) != 1 || status.Patches[0].State != "applied" || len(status.Patches[0].CVEs) != 0 {
			t.Fatalf("unexpected legacy Ksplice evidence: %+v", status)
		}
		seen = true
	}
	if !seen {
		t.Fatal("legacy Ksplice stage not collected")
	}
}

func TestStandaloneKspliceStage(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sys/module/ksplice_test/ksplice/stage", "applied\n")
	out := observeLivepatch(t, root)
	status := out.Livepatch[2]
	if status.Status != "observed" || len(status.Patches) != 1 || status.Patches[0].ID != "ksplice_test" || status.Patches[0].State != "applied" {
		t.Fatalf("standalone state missing: %+v", status)
	}
}

func TestEmptyLivepatchDirectoryIsNotObserved(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sys/kernel/livepatch"), 0700); err != nil {
		t.Fatal(err)
	}
	out := observeLivepatch(t, root)
	if out.Livepatch[0].Status != "not_observed" {
		t.Fatalf("empty source implied patch coverage: %+v", out.Livepatch[0])
	}
}
