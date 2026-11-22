package hardware

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAdapterAndGPUFirmware(t *testing.T) {
	root := t.TempDir()
	for p, v := range map[string]string{
		"sys/bus/pci/devices/0000:41:00.0/vendor":          "0x10de",
		"sys/bus/pci/devices/0000:42:00.0/vendor":          "0x10de",
		"proc/driver/nvidia/gpus/0000:41:00.0/information": "Model: NVIDIA H100 PCIe\nVideo BIOS: ??.??.??.??.??\n",
		"proc/driver/nvidia/gpus/0000:42:00.0/information": "Model: NVIDIA H100 PCIe\nVideo BIOS: 96.00.00.00.01\n",
		"sys/class/scsi_host/host0/version_fw":             "16.00.12.00",
		"sys/class/scsi_host/host0/version_bios":           "08.37.00.00",
		"sys/class/scsi_host/host0/board_name":             "HBA 9400-8i",
		"sys/class/scsi_host/host0/proc_name":              "mpt3sas",
		"sys/class/scsi_host/host1/proc_name":              "ahci",
		"sys/class/scsi_host/host2/fwrev":                  "12.8.351.47, sli-4:2:c",
		"sys/class/scsi_host/host2/modelname":              "LPe32002-M2",
		"sys/class/scsi_host/host2/proc_name":              "lpfc",
		"sys/class/infiniband/mlx5_0/fw_ver":               "22.36.1010",
		"sys/class/infiniband/mlx5_0/hca_type":             "MT4125",
		"sys/class/drm/card0/device/vbios_version":         "113-D1631700-111",
		"sys/class/drm/renderD128/device/vbios_version":    "113-D1631700-111",
		"proc/driver/nvidia/gpus/0000:3b:00.0/information": "Model: \t\t NVIDIA A100-SXM4-40GB\nIRQ:   \t\t 156\nVideo BIOS: \t 92.00.45.00.03\n",
	} {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	assets, _ := Collect(context.Background(), root)
	models := map[string]string{}
	for _, a := range assets {
		if a.Kind == "device" && a.Vendor == "NVIDIA" {
			models[a.Source] = a.Model
		}
		if a.Kind == "firmware" && a.Source == "proc/driver/nvidia/gpus/0000:42:00.0/information" && a.ParentID != assetID("device", "sys/bus/pci/devices/0000:42:00.0") {
			t.Errorf("GPU firmware references wrong PCI device: %s", a.ParentID)
		}
		if a.Kind == "firmware" && a.Source == "proc/driver/nvidia/gpus/0000:3b:00.0/information" && a.ParentID != "" {
			t.Error("GPU firmware must not reference an unobserved PCI device")
		}
	}
	if len(models) != 2 || models["sys/bus/pci/devices/0000:41:00.0"] != "NVIDIA H100 PCIe" || models["sys/bus/pci/devices/0000:42:00.0"] != "NVIDIA H100 PCIe" {
		t.Errorf("expected the driver-reported model of both observed PCI devices: %v", models)
	}
	firmware := map[string]string{}
	devices := map[string]map[string]string{}
	for _, a := range assets {
		switch a.Kind {
		case "firmware":
			firmware[a.Source] = a.Version
		case "device":
			devices[a.Source] = a.Properties
		}
	}
	want := map[string]string{
		"proc/driver/nvidia/gpus/0000:42:00.0/information": "96.00.00.00.01",
		"sys/class/scsi_host/host0/version_fw":             "16.00.12.00",
		"sys/class/scsi_host/host2/fwrev":                  "12.8.351.47, sli-4:2:c",
		"sys/class/infiniband/mlx5_0/fw_ver":               "22.36.1010",
		"sys/class/drm/card0/device/vbios_version":         "113-D1631700-111",
		"proc/driver/nvidia/gpus/0000:3b:00.0/information": "92.00.45.00.03",
	}
	for source, version := range want {
		if firmware[source] != version {
			t.Errorf("%s: firmware %q, want %q", source, firmware[source], version)
		}
	}
	if len(firmware) != len(want) {
		t.Errorf("unexpected firmware set %v", firmware)
	}
	if d := devices["sys/class/scsi_host/host0"]; d["driver"] != "mpt3sas" || d["model"] != "HBA 9400-8i" || d["biosVersion"] != "08.37.00.00" {
		t.Errorf("mpt3sas adapter properties %v", d)
	}
	if _, ok := devices["sys/class/scsi_host/host1"]; ok {
		t.Error("an adapter without identity fields must not become an asset")
	}
	if _, ok := devices["sys/class/drm/renderD128"]; ok {
		t.Error("render node duplicates the GPU card")
	}
}
