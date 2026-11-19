package hardware

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCPUIDSignature(t *testing.T) {
	for _, c := range []struct{ family, model, stepping, signature, fms string }{
		{"6", "85", "7", "00050657", "06-55-07"},  // Intel Cascade Lake, Intel-SA "CPUID 50657"
		{"6", "143", "8", "000806F8", "06-8f-08"}, // Intel Sapphire Rapids
		{"25", "1", "1", "00A00F11", "19-01-01"},  // AMD Milan B1
		{"23", "49", "0", "00830F10", "17-31-00"}, // AMD Rome
	} {
		signature, fms, ok := cpuidSignature(c.family, c.model, c.stepping)
		if !ok || signature != c.signature || fms != c.fms {
			t.Errorf("%v: got %s %s %v", c, signature, fms, ok)
		}
	}
	if _, _, ok := cpuidSignature("6", "", "7"); ok {
		t.Error("missing model must not produce a signature")
	}
}

func TestCPUTopologyAndARMNames(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 50.00\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0xd0c\nCPU revision\t: 1\n\n" +
			"processor\t: 1\nCPU implementer\t: 0xc0\nCPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xfff\nCPU revision\t: 0\n",
		"sys/devices/system/cpu/cpu0/topology/physical_package_id": "0\n",
		"sys/devices/system/cpu/cpu0/topology/core_id":             "12\n",
		"sys/devices/system/cpu/cpu1/topology/physical_package_id": "../x\n",
	}
	for p, v := range files {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	assets, _ := Collect(context.Background(), root)
	cpus := map[string]map[string]string{}
	for _, a := range assets {
		if a.Name == "CPU" {
			cpus[a.Properties["processor"]] = map[string]string{"vendor": a.Vendor, "model": a.Model, "revision": a.Revision, "socket": a.Properties["socket"], "core": a.Properties["core"], "sig": a.Properties["cpuidSignature"]}
		}
	}
	want0 := map[string]string{"vendor": "ARM", "model": "Neoverse-N1", "revision": "r3p1", "socket": "0", "core": "12", "sig": ""}
	for k, v := range want0 {
		if cpus["0"][k] != v {
			t.Errorf("cpu0 %s = %q, want %q", k, cpus["0"][k], v)
		}
	}
	if cpus["1"]["vendor"] != "Ampere" || cpus["1"]["model"] != "" || cpus["1"]["socket"] != "" {
		t.Errorf("unknown part or non-numeric topology must stay empty: %v", cpus["1"])
	}
}

func TestHardwareCPEs(t *testing.T) {
	for name, want := range map[string]string{
		"Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz":  "cpe:2.3:h:intel:xeon_gold_6248:-:*:*:*:*:*:*:*",
		"Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz": "cpe:2.3:h:intel:xeon_e5-2680_v4:-:*:*:*:*:*:*:*",
		"Intel(R) Xeon(R) CPU E5-2650 0 @ 2.00GHz":  "cpe:2.3:h:intel:xeon_e5-2650:-:*:*:*:*:*:*:*",
		"Intel(R) Xeon(R) E-2288G CPU @ 3.70GHz":    "cpe:2.3:h:intel:xeon_e-2288g:-:*:*:*:*:*:*:*",
		"Intel(R) Xeon(R) 6980P":                    "cpe:2.3:h:intel:xeon_6980p:-:*:*:*:*:*:*:*",
		"Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz":   "cpe:2.3:h:intel:core_i7-8700:-:*:*:*:*:*:*:*",
		"AMD EPYC 7763 64-Core Processor":           "cpe:2.3:h:amd:epyc_7763:-:*:*:*:*:*:*:*",
		"AMD Ryzen 9 5950X 16-Core Processor":       "cpe:2.3:h:amd:ryzen_9_5950x:-:*:*:*:*:*:*:*",
		"Intel Xeon Processor (Cascadelake)":        "",
		"Intel(R) Xeon(R) CPU @ 2.20GHz":            "",
		"AMD EPYC-Rome Processor":                   "",
		"Intel(R) Xeon(R) Platinum 8480+":           "",
		"QEMU Virtual CPU version 2.5+":             "",
	} {
		if got := cpuCPE(name); got != want {
			t.Errorf("cpuCPE(%q) = %q, want %q", name, got, want)
		}
	}
	for _, c := range []struct{ vendor, product, bios, hw, fw string }{
		{"Dell Inc.", "PowerEdge R740xd", "2.9.4", "cpe:2.3:h:dell:poweredge_r740xd:-:*:*:*:*:*:*:*", "cpe:2.3:o:dell:poweredge_r740xd_firmware:2.9.4:*:*:*:*:*:*:*"},
		{"Lenovo", "ThinkSystem SR650 -[7X06CTO1WW]-", "IVE178I-3.30", "cpe:2.3:h:lenovo:thinksystem_sr650:-:*:*:*:*:*:*:*", ""},
		{"HPE", "ProLiant DL380 Gen10", "U30", "", ""},
		{"Dell Inc.", "PowerEdge R740", "2.9.4 (beta)", "cpe:2.3:h:dell:poweredge_r740:-:*:*:*:*:*:*:*", ""},
	} {
		hw, fw := systemCPEs(c.vendor, c.product, c.bios)
		if hw != c.hw || fw != c.fw {
			t.Errorf("%v: got %q %q", c, hw, fw)
		}
	}
}
