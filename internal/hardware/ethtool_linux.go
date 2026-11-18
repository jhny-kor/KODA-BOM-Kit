//go:build linux

package hardware

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// ethtool reads NIC firmware with the read-only ETHTOOL_GDRVINFO ioctl, the
// same query as `ethtool -i`, without running an external program.
func (c *collector) ethtool() {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		c.issue("sys/class/net", "incomplete", "ethtool query socket unavailable; NIC firmware not read")
		return
	}
	defer unix.Close(fd)
	text := func(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
	for _, entry := range c.dirs("sys/class/net") {
		name := entry.Name()
		if _, err := c.root.Stat("sys/class/net/" + name + "/device"); err != nil {
			continue // virtual interface
		}
		info, err := unix.IoctlGetEthtoolDrvinfo(fd, name)
		if err != nil {
			continue
		}
		version, bus := text(info.Fw_version[:]), text(info.Bus_info[:])
		if version == "" || version == "N/A" || !pciAddress.MatchString(bus) {
			continue
		}
		device := "sys/bus/pci/devices/" + bus
		f := c.asset("firmware", "NIC firmware", device+"/ethtool", assetID("device", device), map[string]string{
			"interface": name, "driver": text(info.Driver[:]), "driverVersion": text(info.Version[:]),
			"expansionRomVersion": text(info.Erom_version[:]), "state": "reported-running", "versionFormat": "vendor",
		})
		f.Version = version
		c.assets = append(c.assets, f)
		c.nicFirmware[bus] = true
	}
}
