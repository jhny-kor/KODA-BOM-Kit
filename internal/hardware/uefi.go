package hardware

import (
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
)

const uefiSystem = "sys/firmware/efi"

func (c *collector) uefi(parent string) {
	if c.ctx.Err() != nil {
		return
	}
	if _, err := c.root.Stat(uefiSystem); err != nil {
		return
	}
	facts := map[string]string{"bootMode": "UEFI"}
	for _, item := range []struct{ name, field string }{{"SecureBoot", "secureBoot"}, {"SetupMode", "setupMode"}} {
		p := uefiSystem + "/efivars/" + item.name + "-8be4df61-93ca-11d2-aa0d-00e098032b8c"
		val, err := c.efiFlag(p)
		if err != nil {
			c.issue(p, "not_observed", "UEFI variable unavailable")
			continue
		}
		facts[item.field] = strconv.FormatBool(val)
	}
	a := c.asset("device", "UEFI platform", uefiSystem, parent, facts)
	c.assets = append(c.assets, a)
	for _, entry := range c.dirs(uefiSystem + "/esrt/entries") {
		if !strings.HasPrefix(entry.Name(), "entry") {
			continue
		}
		p := path.Join(uefiSystem, "esrt", "entries", entry.Name())
		guid := c.read(p + "/fw_class")
		if guid == "" {
			continue
		}
		version := c.read(p + "/fw_version")
		if _, err := strconv.ParseUint(version, 0, 32); err != nil {
			version = ""
		}
		firmware := c.asset("firmware", "UEFI ESRT firmware", p, a.ID, map[string]string{
			"guid": guid, "rawVersion": version, "versionFormat": "uefi-esrt-uint32",
			"lastAttemptStatus": c.read(p + "/last_attempt_status"), "state": "observed",
		})
		firmware.Version = version
		c.assets = append(c.assets, firmware)
	}
}

func (c *collector) efiFlag(name string) (bool, error) {
	file, err := c.root.Open(name)
	if err != nil {
		return false, err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false, errors.New("expected UEFI variable file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 6))
	if err != nil || len(data) != 5 || data[4] > 1 {
		return false, errors.New("unexpected UEFI boolean encoding")
	}
	return data[4] == 1, nil
}
