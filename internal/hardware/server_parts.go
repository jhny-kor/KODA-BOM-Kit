package hardware

import (
	"path"
	"strconv"
	"strings"
)

// serverParts reads component identity where a Linux driver exposes it.
// EDAC rank entries and fan tachometer channels are not physical FRU counts.
// EDAC DIMMs are skipped when SMBIOS already identified the installed modules.
func (c *collector) serverParts(board string, smbiosMemory bool) {
	const edac = "sys/devices/system/edac/mc"
	for _, controller := range c.dirs(edac) {
		if smbiosMemory {
			break
		}
		if !numbered(controller.Name(), "mc") {
			continue
		}
		base := path.Join(edac, controller.Name())
		for _, entry := range c.dirs(base) {
			if !numbered(entry.Name(), "dimm") {
				continue
			}
			p := path.Join(base, entry.Name())
			size, err := strconv.ParseUint(c.read(p+"/size"), 10, 64)
			if err != nil || size == 0 {
				continue
			}
			props := map[string]string{"capacityMiB": strconv.FormatUint(size, 10), "locator": c.read(p + "/dimm_location"), "label": c.read(p + "/dimm_label"), "memoryType": c.read(p + "/dimm_mem_type")}
			c.assets = append(c.assets, c.asset("device", "Memory module", p, board, props))
		}
	}
	const power = "sys/class/power_supply"
	for _, entry := range c.dirs(power) {
		p := path.Join(power, entry.Name())
		kind := c.read(p + "/type")
		if kind != "Mains" && kind != "UPS" || c.read(p+"/present") == "0" {
			continue
		}
		model, vendor := c.read(p+"/model_name"), c.read(p+"/manufacturer")
		if model == "" && vendor == "" {
			continue
		}
		a := c.asset("device", "Power supply", p, board, map[string]string{"powerSupplyType": kind})
		a.Model, a.Vendor = model, vendor
		c.assets = append(c.assets, a)
	}
	const hwmon = "sys/class/hwmon"
	for _, hw := range c.dirs(hwmon) {
		base := path.Join(hwmon, hw.Name())
		for _, entry := range c.dirs(base) {
			channel, ok := strings.CutSuffix(entry.Name(), "_input")
			if !ok || !numbered(channel, "fan") {
				continue
			}
			p := path.Join(base, entry.Name())
			rpm, err := strconv.ParseUint(c.read(p), 10, 32)
			if err != nil {
				continue
			}
			props := map[string]string{"channel": channel, "speedRPM": strconv.FormatUint(rpm, 10), "sensor": c.read(base + "/name"), "label": c.read(path.Join(base, channel+"_label"))}
			c.assets = append(c.assets, c.asset("device", "Fan speed sensor", p, board, props))
		}
	}
}
func numbered(s, prefix string) bool {
	n, ok := strings.CutPrefix(s, prefix)
	if !ok || n == "" {
		return false
	}
	_, err := strconv.ParseUint(n, 10, 32)
	return err == nil
}
