package hardware

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryRelationshipsAndConfinement(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"proc/cpuinfo": "processor : 0\nvendor_id : GenuineIntel\nmodel name : Example CPU\nstepping : 3\nmicrocode : 0x123\nflags : fpu hypervisor\n",
		"sys/devices/system/cpu/vulnerabilities/gather_data_sampling": "Unknown: Dependent on hypervisor status",
		"sys/devices/virtual/dmi/id/sys_vendor":                       "Example",
		"sys/devices/virtual/dmi/id/product_name":                     "Server X",
		"sys/devices/virtual/dmi/id/bios_version":                     "1.2.3",
		"sys/class/nvme/nvme0/model":                                  "Example SSD",
		"sys/class/nvme/nvme0/firmware_rev":                           "ABCD",
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
	if err := os.MkdirAll(filepath.Join(root, "sys/class/dmi"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/virtual/dmi/id", filepath.Join(root, "sys/class/dmi/id")); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "model"), []byte("ESCAPED"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sys/class/nvme/nvme1")); err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), root)
	ids := map[string]bool{}
	firmware := 0
	guest := false
	for _, a := range assets {
		ids[a.ID] = true
		if a.Model == "ESCAPED" {
			t.Fatal("read outside root")
		}
		if a.Kind == "firmware" {
			firmware++
		}
		if a.Properties["virtualization"] == "guest" {
			guest = true
		}
	}
	for _, a := range assets {
		if a.ParentID != "" && !ids[a.ParentID] {
			t.Fatalf("dangling parent: %+v", a)
		}
	}
	if firmware != 3 || !guest {
		t.Fatalf("firmware=%d guest=%v assets=%+v issues=%+v", firmware, guest, assets, issues)
	}
	if len(issues) == 0 {
		t.Fatal("escaping symlink must report incomplete evidence")
	}
}

func TestMissingInventoryDoesNotInventDevices(t *testing.T) {
	assets, issues := Collect(context.Background(), t.TempDir())
	if len(assets) != 0 || len(issues) == 0 {
		t.Fatalf("assets=%v issues=%v", assets, issues)
	}
}

func TestContainerInventoryCarriesLimitedScope(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".dockerenv"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "sys/class/nvme/nvme0")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model"), []byte("Host SSD"), 0600); err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), root)
	if len(assets) != 1 {
		t.Fatalf("assets=%+v", assets)
	}
	if assets[0].Properties["observationScope"] != "container-visible" {
		t.Fatal(assets[0])
	}
	found := false
	for _, issue := range issues {
		if issue.Status == "incomplete" {
			found = true
		}
	}
	if !found {
		t.Fatal("container scope must surface incomplete host evidence")
	}
}

func TestReadOnlyUEFIFlagsAndESRT(t *testing.T) {
	root := t.TempDir()
	write := func(name string, value []byte) {
		t.Helper()
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", []byte{7, 0, 0, 0, 1})
	write("sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", []byte{7, 0, 0, 0, 0, 1})
	write("sys/firmware/efi/esrt/entries/entry0/fw_class", []byte("e1f5e450-60d8-4fd8-99bd-2b806a4bd039\n"))
	write("sys/firmware/efi/esrt/entries/entry0/fw_version", []byte("0x00102030\n"))
	rows, _ := Collect(context.Background(), root)
	var platformID, parentID string
	for _, a := range rows {
		switch a.Name {
		case "UEFI platform":
			platformID = a.ID
			if a.Properties["secureBoot"] != "true" || a.Properties["setupMode"] != "" {
				t.Fatalf("invalid parsed UEFI flags %#v", a.Properties)
			}
		case "UEFI ESRT firmware":
			parentID = a.ParentID
			if a.Version != "0x00102030" || a.Properties["versionFormat"] != "uefi-esrt-uint32" {
				t.Fatalf("invalid ESRT identity %#v", a)
			}
		}
	}
	if platformID == "" || parentID != platformID {
		t.Fatalf("ESRT parent not linked: %q %q", parentID, platformID)
	}
}
