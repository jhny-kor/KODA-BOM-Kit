package hardware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func TestHostIdentityHashesValuesAndSkipsPlaceholders(t *testing.T) {
	root := t.TempDir()
	for p, v := range map[string]string{
		"etc/machine-id":                  "0123456789ABCDEF0123456789abcdef\n",
		"sys/class/dmi/id/product_uuid":   "4C4C4544-0042-3510-8051-B4C04F4B4E32\n",
		"sys/class/dmi/id/product_serial": "To Be Filled By O.E.M.\n",
		"sys/class/dmi/id/board_serial":   "  CN7016361G00ZX  \n",
	} {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	id, issues := HostIdentity(context.Background(), root)
	if id.MachineIDSHA256 != digest("0123456789abcdef0123456789abcdef") ||
		id.ProductUUIDSHA256 != digest("4c4c4544-0042-3510-8051-b4c04f4b4e32") ||
		id.BoardSerialSHA256 != digest("CN7016361G00ZX") || id.ProductSerialSHA256 != "" {
		t.Fatalf("unexpected identity %+v (issues %+v)", id, issues)
	}
	if id.ObservationScope != "host-or-guest-unverified" {
		t.Fatalf("unexpected scope %q", id.ObservationScope)
	}
}

func TestIdentityDigestRejectsSharedValues(t *testing.T) {
	for _, v := range []string{"", "  ", "None", "Default string", "00000000-0000-0000-0000-000000000000", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "0"} {
		if got := identityDigest(v, true); got != "" {
			t.Errorf("%q should be treated as absent, got %s", v, got)
		}
	}
}

func TestHostIdentityReportsMissingIdentifiers(t *testing.T) {
	id, issues := HostIdentity(context.Background(), t.TempDir())
	if id.MachineIDSHA256 != "" || len(issues) == 0 || issues[len(issues)-1].Status != "not_observed" {
		t.Fatalf("expected not_observed issue, got %+v %+v", id, issues)
	}
}
