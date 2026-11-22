package hardware

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func smbiosStruct(kind byte, handle uint16, length int, fields map[int][]byte, strs ...string) []byte {
	b := make([]byte, length)
	b[0], b[1] = kind, byte(length)
	binary.LittleEndian.PutUint16(b[2:], handle)
	for off, v := range fields {
		copy(b[off:], v)
	}
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	if len(strs) == 0 {
		b = append(b, 0)
	}
	return append(b, 0)
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

func TestSMBIOSMemoryPowerAndSlots(t *testing.T) {
	var table []byte
	// Installed DIMM: 32 GiB DDR5, 4800 MT/s, strings 1..5.
	table = append(table, smbiosStruct(17, 0x1100, 0x28, map[int][]byte{
		0x0c: le16(0x7fff), 0x1c: binary.LittleEndian.AppendUint32(nil, 32768), 0x10: {1}, 0x11: {2}, 0x12: {0x22}, 0x15: le16(4800), 0x17: {3}, 0x18: {4}, 0x1a: {5}, 0x20: le16(4400),
	}, "DIMM_A1", "BANK 0", "Samsung", "S3R14L", "M321R4GA3BB6-CQK")...)
	// Empty slot must be skipped.
	table = append(table, smbiosStruct(17, 0x1101, 0x28, map[int][]byte{0x0c: le16(0), 0x10: {1}}, "DIMM_A2")...)
	// Present PSU, 800 W.
	table = append(table, smbiosStruct(39, 0x2700, 0x16, map[int][]byte{
		0x05: {1}, 0x07: {2}, 0x08: {3}, 0x0a: {4}, 0x0b: {5}, 0x0c: le16(800), 0x0e: le16(0x0003),
	}, "PSU1", "Delta", "Not Specified", "PWS-801", "A01")...)
	// Absent PSU.
	table = append(table, smbiosStruct(39, 0x2701, 0x16, map[int][]byte{0x07: {1}, 0x0e: le16(0x0001)}, "Delta")...)
	// In-use PCIe slot at 0000:3b:00.0.
	table = append(table, smbiosStruct(9, 0x0900, 0x11, map[int][]byte{
		0x04: {1}, 0x05: {0xb6}, 0x07: {4}, 0x0d: le16(0), 0x0f: {0x3b}, 0x10: {0x00},
	}, "PCIe Slot 1")...)
	table = append(table, smbiosStruct(127, 0xffff, 4, nil)...)

	root := t.TempDir()
	write := func(p string, b []byte) {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(smbiosTable, table)
	write("sys/devices/system/edac/mc/mc0/dimm0/size", []byte("16384")) // superseded by SMBIOS
	assets, _ := Collect(context.Background(), root)
	byName := map[string][]map[string]string{}
	for _, a := range assets {
		props := map[string]string{"vendor": a.Vendor, "model": a.Model}
		for k, v := range a.Properties {
			props[k] = v
		}
		byName[a.Name] = append(byName[a.Name], props)
	}
	mem := byName["Memory module"]
	if len(mem) != 1 || mem[0]["capacityMiB"] != "32768" || mem[0]["memoryType"] != "DDR5" || mem[0]["speedMTs"] != "4800" ||
		mem[0]["configuredSpeedMTs"] != "4400" || mem[0]["vendor"] != "Samsung" || mem[0]["partNumber"] != "M321R4GA3BB6-CQK" ||
		mem[0]["locator"] != "DIMM_A1" || len(mem[0]["serialNumberSha256"]) != 64 {
		t.Fatalf("memory: %+v", mem)
	}
	psu := byName["Power supply"]
	if len(psu) != 1 || psu[0]["maxPowerWatts"] != "800" || psu[0]["model"] != "PWS-801" || psu[0]["serialNumberSha256"] != "" || psu[0]["hotReplaceable"] != "true" {
		t.Fatalf("power: %+v", psu)
	}
	slot := byName["System slot"]
	if len(slot) != 1 || slot[0]["pciAddress"] != "0000:3b:00.0" || slot[0]["usage"] != "in-use" {
		t.Fatalf("slot: %+v", slot)
	}
}

func TestSMBIOSTruncatedTableStops(t *testing.T) {
	if got := parseSMBIOS([]byte{17, 0x28, 0, 0, 1}); len(got) != 0 {
		t.Fatalf("truncated structure parsed: %+v", got)
	}
}
