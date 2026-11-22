package hardware

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const smbiosTable = "sys/firmware/dmi/tables/DMI"

// smbiosTableLimit bounds the raw table read; real tables are a few KiB to tens of KiB.
const smbiosTableLimit = 1 << 20

// smbiosRecord is one structure from the raw SMBIOS table: its formatted area
// (including the 4-byte header) and its 1-based string set.
type smbiosRecord struct {
	kind    byte
	handle  uint16
	data    []byte
	strings []string
}

func (r smbiosRecord) byteAt(off int) (byte, bool) {
	if off >= len(r.data) {
		return 0, false
	}
	return r.data[off], true
}
func (r smbiosRecord) word(off int) (uint16, bool) {
	if off+2 > len(r.data) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(r.data[off:]), true
}
func (r smbiosRecord) dword(off int) (uint32, bool) {
	if off+4 > len(r.data) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(r.data[off:]), true
}

// str returns the string referenced at off, dropping vendor placeholders.
func (r smbiosRecord) str(off int) string {
	i, ok := r.byteAt(off)
	if !ok || i == 0 || int(i) > len(r.strings) {
		return ""
	}
	s := strings.TrimSpace(r.strings[i-1])
	if identityPlaceholders[strings.ToLower(s)] || !printable(s) {
		return ""
	}
	return s
}

func printable(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// parseSMBIOS splits a raw table into structures. A truncated trailing
// structure ends parsing; type 127 marks the end of the table.
func parseSMBIOS(b []byte) []smbiosRecord {
	var out []smbiosRecord
	for len(b) >= 4 {
		length := int(b[1])
		if length < 4 || length > len(b) {
			break
		}
		rec := smbiosRecord{kind: b[0], handle: binary.LittleEndian.Uint16(b[2:]), data: b[:length]}
		rest := b[length:]
		end := -1
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == 0 && rest[i+1] == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			break
		}
		if end > 0 {
			rec.strings = strings.Split(string(rest[:end]), "\x00")
		}
		out = append(out, rec)
		if rec.kind == 127 {
			break
		}
		b = rest[end+2:]
	}
	return out
}

// smbios reads memory devices (type 17), power supplies (type 39) and system
// slots (type 9) from the raw firmware table. It reports whether any installed
// memory module was found so EDAC entries can be skipped as a weaker source.
func (c *collector) smbios(board string) bool {
	f, err := c.root.Open(smbiosTable)
	if err != nil {
		switch {
		case os.IsNotExist(err):
		case os.IsPermission(err):
			c.issue(smbiosTable, "permission_denied", "SMBIOS table requires root; memory part numbers, power supplies and slots are unavailable")
		default:
			c.issue(smbiosTable, "incomplete", "SMBIOS table unreadable")
		}
		return false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		c.issue(smbiosTable, "incomplete", "SMBIOS table is not a regular file")
		return false
	}
	raw, err := io.ReadAll(io.LimitReader(f, smbiosTableLimit+1))
	if err != nil || len(raw) > smbiosTableLimit {
		c.issue(smbiosTable, "incomplete", "SMBIOS table read limit or error")
		return false
	}
	memory := false
	for _, r := range parseSMBIOS(raw) {
		p := fmt.Sprintf("%s/handle-0x%04x", smbiosTable, r.handle)
		switch r.kind {
		case 17:
			if c.smbiosMemory(r, p, board) {
				memory = true
			}
		case 39:
			c.smbiosPower(r, p, board)
		case 9:
			c.smbiosSlot(r, p, board)
		}
	}
	return memory
}

var memoryTypes = map[byte]string{
	0x07: "RAM", 0x0f: "SDRAM", 0x12: "DDR", 0x13: "DDR2", 0x18: "DDR3", 0x1a: "DDR4", 0x1b: "LPDDR",
	0x1c: "LPDDR2", 0x1d: "LPDDR3", 0x1e: "LPDDR4", 0x1f: "Logical non-volatile device", 0x20: "HBM",
	0x21: "HBM2", 0x22: "DDR5", 0x23: "LPDDR5", 0x24: "HBM3",
}

func (c *collector) smbiosMemory(r smbiosRecord, p, board string) bool {
	size, ok := r.word(0x0c)
	if !ok || size == 0 || size == 0xffff {
		return false // empty slot or unknown size
	}
	var mib uint64
	switch {
	case size == 0x7fff:
		ext, ok := r.dword(0x1c)
		if !ok {
			return false
		}
		mib = uint64(ext & 0x7fffffff)
	case size&0x8000 != 0:
		mib = uint64(size&0x7fff) / 1024 // KiB granularity
	default:
		mib = uint64(size)
	}
	props := map[string]string{"source": "smbios-type17", "locator": r.str(0x10), "bankLocator": r.str(0x11)}
	if mib > 0 {
		props["capacityMiB"] = strconv.FormatUint(mib, 10)
	}
	if t, ok := r.byteAt(0x12); ok {
		if name := memoryTypes[t]; name != "" {
			props["memoryType"] = name
		}
	}
	if speed, ok := r.word(0x15); ok && speed != 0 {
		if speed == 0xffff {
			if ext, ok := r.dword(0x54); ok && ext != 0 {
				props["speedMTs"] = strconv.FormatUint(uint64(ext), 10)
			}
		} else {
			props["speedMTs"] = strconv.Itoa(int(speed))
		}
	}
	if speed, ok := r.word(0x20); ok && speed != 0 && speed != 0xffff {
		props["configuredSpeedMTs"] = strconv.Itoa(int(speed))
	}
	// Serial numbers are pseudonymized like host DMI serials.
	if digest := identityDigest(r.str(0x18), false); digest != "" {
		props["serialNumberSha256"] = digest
	}
	part := r.str(0x1a)
	props["partNumber"] = part
	a := c.asset("device", "Memory module", p, board, compact(props))
	a.Vendor, a.Model = r.str(0x17), part
	c.assets = append(c.assets, a)
	return true
}

func (c *collector) smbiosPower(r smbiosRecord, p, board string) {
	props := map[string]string{"source": "smbios-type39", "location": r.str(0x05), "deviceName": r.str(0x06), "revision": r.str(0x0b)}
	if chars, ok := r.word(0x0e); ok {
		if chars&0x0002 == 0 {
			return // bit 1: power supply not present
		}
		if chars&0x0004 != 0 {
			props["unplugged"] = "true"
		}
		if chars&0x0001 != 0 {
			props["hotReplaceable"] = "true"
		}
	}
	if watts, ok := r.word(0x0c); ok && watts != 0x8000 && watts != 0 {
		props["maxPowerWatts"] = strconv.Itoa(int(watts))
	}
	if digest := identityDigest(r.str(0x08), false); digest != "" {
		props["serialNumberSha256"] = digest
	}
	vendor, model := r.str(0x07), r.str(0x0a)
	if vendor == "" && model == "" {
		return
	}
	props["partNumber"] = model
	a := c.asset("device", "Power supply", p, board, compact(props))
	a.Vendor, a.Model, a.Revision = vendor, model, props["revision"]
	c.assets = append(c.assets, a)
}

var slotUsage = map[byte]string{3: "available", 4: "in-use", 5: "unavailable"}

func (c *collector) smbiosSlot(r smbiosRecord, p, board string) {
	designation := r.str(0x04)
	if designation == "" {
		return
	}
	props := map[string]string{"source": "smbios-type9", "designation": designation}
	if t, ok := r.byteAt(0x05); ok {
		props["slotType"] = fmt.Sprintf("0x%02x", t)
	}
	if u, ok := r.byteAt(0x07); ok {
		props["usage"] = slotUsage[u]
	}
	// SMBIOS 2.6+: segment/bus/device-function locate the PCI device in the slot.
	if seg, ok := r.word(0x0d); ok && seg != 0xffff {
		bus, okB := r.byteAt(0x0f)
		df, okD := r.byteAt(0x10)
		if okB && okD && bus != 0xff && df != 0xff {
			props["pciAddress"] = fmt.Sprintf("%04x:%02x:%02x.%d", seg, bus, df>>3, df&7)
		}
	}
	c.assets = append(c.assets, c.asset("device", "System slot", p, board, compact(props)))
}

func compact(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	return m
}
