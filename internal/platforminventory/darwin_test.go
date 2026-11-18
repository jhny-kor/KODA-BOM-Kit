//go:build darwin

package platforminventory

import (
	"context"
	"os"
	"testing"
)

func TestNativeMac(t *testing.T) {
	if os.Getenv("KODA_TEST_NATIVE_PLATFORM") != "1" {
		t.Skip("opt-in native platform test")
	}
	a, i, e := Collect(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var hardware, osFound, firmware bool
	for _, v := range a {
		hardware = hardware || v.Kind == "device"
		osFound = osFound || v.Kind == "operating-system"
		firmware = firmware || v.Kind == "firmware"
	}
	if !hardware || !osFound || !firmware {
		t.Fatalf("missing native categories across %d assets", len(a))
	}
	t.Logf("native assets %d, coverage issues %d", len(a), len(i))
}
