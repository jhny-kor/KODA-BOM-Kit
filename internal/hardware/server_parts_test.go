package hardware

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalPartsDoNotInventModulesOrFans(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"sys/devices/system/edac/mc/mc0/dimm1/size": "16384", "sys/devices/system/edac/mc/mc0/dimm2/size": "0", "sys/devices/system/edac/mc/mc0/rank0/size": "8192", "sys/class/power_supply/ac/type": "Mains", "sys/class/power_supply/ac/model_name": "Rack-A", "sys/class/power_supply/bat/type": "Battery", "sys/class/power_supply/bat/model_name": "Battery-A", "sys/class/hwmon/hwmon0/fan1_input": "1200"}
	for p, s := range files {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	assets, _ := Collect(context.Background(), root)
	found := map[string]string{}
	for _, a := range assets {
		switch a.Name {
		case "Memory module":
			found[a.Name] = a.Properties["capacityMiB"]
		case "Fan speed sensor":
			found[a.Name] = a.Properties["speedRPM"]
		case "Power supply":
			found[a.Name] = a.Model
		}
	}
	if len(assets) != 3 || found["Memory module"] != "16384" || found["Fan speed sensor"] != "1200" || found["Power supply"] != "Rack-A" {
		t.Fatalf("unexpected parts: %+v", assets)
	}
}
