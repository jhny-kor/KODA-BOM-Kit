// Package hardware reads bounded, allowlisted Linux inventory attributes.
package hardware

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

type collector struct {
	ctx    context.Context
	root   *os.Root
	assets []model.Asset
	issues []model.Issue
	now    string
	scope  string
	// PCI addresses whose NIC firmware was read through ethtool.
	nicFirmware map[string]bool
}

// Collect reads the supplied Linux root. The caller determines whether this is
// a live host; no values are obtained from outside root, including symlink targets.
func Collect(ctx context.Context, root string) ([]model.Asset, []model.Issue) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, []model.Issue{{Collector: "hardware", Status: "failed", Message: "hardware root unavailable"}}
	}
	defer r.Close()
	c := collector{ctx: ctx, root: r, now: time.Now().UTC().Format(time.RFC3339), nicFirmware: map[string]bool{}}
	c.detectScope()
	board := c.dmi()
	c.uefi(board)
	c.cpu()
	if root == "/" {
		// The ethtool ioctl reads the running kernel, never a supplied directory.
		c.ethtool()
	}
	c.devices("sys/bus/pci/devices", "PCI device", map[string]string{"vendor": "vendorId", "device": "deviceId", "subsystem_vendor": "subsystemVendorId", "subsystem_device": "subsystemDeviceId", "revision": "revision", "class": "class"})
	c.devices("sys/class/nvme", "NVMe controller", map[string]string{"model": "model", "firmware_rev": "firmwareVersion"})
	c.devices("sys/class/scsi_device", "SCSI storage device", map[string]string{"device/vendor": "vendor", "device/model": "model", "device/rev": "firmwareVersion", "device/type": "deviceType"})
	// RAID/HBA controllers. Each driver exposes its own attribute names (checked
	// against the kernel source); megaraid_sas exposes no firmware version.
	c.devices("sys/class/scsi_host", "Storage host adapter", map[string]string{
		"version_fw": "firmwareVersion", "version_bios": "biosVersion", "board_name": "model", // mpt3sas
		"fw_version": "firmwareVersion", "optrom_bios_version": "biosVersion", "model_name": "model", // qla2xxx
		"fwrev": "firmwareVersion", "option_rom_version": "biosVersion", "modelname": "model", // lpfc
		"firmware_revision": "firmwareVersion",                                       // hpsa
		"firmware_version":  "firmwareVersion", "model": "model", "vendor": "vendor", // smartpqi
	})
	c.devices("sys/class/infiniband", "RDMA adapter", map[string]string{"fw_ver": "firmwareVersion", "hca_type": "model", "board_id": "boardId"})
	c.devices("sys/class/drm", "GPU", map[string]string{"device/vbios_version": "firmwareVersion"})
	c.nvidia()
	c.devices("sys/bus/usb/devices", "USB device", map[string]string{"idVendor": "vendorId", "idProduct": "deviceId", "manufacturer": "vendor", "product": "model", "bcdDevice": "deviceRelease"})
	c.devices("sys/class/tpm", "TPM", map[string]string{"tpm_version_major": "specificationMajor"})
	ids := map[string]bool{}
	for _, a := range c.assets {
		ids[a.ID] = true
	}
	for i := range c.assets {
		if !ids[c.assets[i].ParentID] {
			c.assets[i].ParentID = "" // never emit a relationship to a missing element
		}
	}
	sort.Slice(c.assets, func(i, j int) bool { return c.assets[i].ID < c.assets[j].ID })
	return c.assets, c.issues
}
func (c *collector) issue(p, status, message string) {
	if len(c.issues) < 200 {
		c.issues = append(c.issues, model.Issue{Collector: "hardware", Path: p, Status: status, Message: message})
	}
}
func (c *collector) read(p string) string {
	if c.ctx.Err() != nil {
		return ""
	}
	f, err := c.root.Open(p)
	if err != nil {
		if !os.IsNotExist(err) {
			c.issue(p, "incomplete", "attribute unreadable")
		}
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		c.issue(p, "incomplete", "attribute is not a regular file")
		return ""
	}
	limit := 65536
	if p == "proc/cpuinfo" {
		limit = 4 * 1024 * 1024
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(b) > limit {
		c.issue(p, "incomplete", "attribute read limit or error")
		return ""
	}
	s := strings.TrimSpace(string(b))
	if (p != "proc/cpuinfo" && len(s) > 4096) || strings.ContainsRune(s, 0) {
		return ""
	}
	return s
}
func (c *collector) dirs(p string) []os.DirEntry {
	if c.ctx.Err() != nil {
		return nil
	}
	f, err := c.root.Open(p)
	if err != nil {
		if !os.IsNotExist(err) {
			c.issue(p, "incomplete", "inventory directory unreadable")
		}
		return nil
	}
	defer f.Close()
	entries, err := f.ReadDir(4097)
	if err != nil && err != io.EOF {
		c.issue(p, "incomplete", "inventory directory read error")
	}
	if len(entries) > 4096 {
		entries = entries[:4096]
		c.issue(p, "incomplete", "inventory directory limit reached")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries
}

var drmCard = regexp.MustCompile(`^card[0-9]+$`)
var pciAddress = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)

// nvidia reads the GPU video BIOS version reported by the NVIDIA kernel driver.
// The driver version itself comes from the PCI device's driver module.
func (c *collector) nvidia() {
	for _, entry := range c.dirs("proc/driver/nvidia/gpus") {
		if !pciAddress.MatchString(entry.Name()) {
			continue
		}
		p := "proc/driver/nvidia/gpus/" + entry.Name() + "/information"
		props := map[string]string{"state": "reported-running", "versionFormat": "vendor"}
		version := ""
		for _, line := range strings.Split(c.read(p), "\n") {
			k, v, _ := strings.Cut(line, ":")
			switch strings.TrimSpace(k) {
			case "Model":
				props["model"] = strings.TrimSpace(v)
			case "Video BIOS":
				version = strings.TrimSpace(v)
			}
		}
		if version == "" || strings.EqualFold(version, "??.??.??.??.??") {
			continue
		}
		parent := "sys/bus/pci/devices/" + entry.Name()
		f := c.asset("firmware", "GPU video BIOS", p, assetID("device", parent), props)
		f.Version, f.Vendor, f.Model = version, "NVIDIA", props["model"]
		c.assets = append(c.assets, f)
	}
}

func assetID(kind, p string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + p))
	return fmt.Sprintf("hardware-%x", sum[:12])
}
func (c *collector) asset(kind, name, p, parent string, props map[string]string) model.Asset {
	props["observationScope"] = c.scope
	return model.Asset{ID: assetID(kind, p), Kind: kind, Name: name, Source: p, ParentID: parent, ObservedAt: c.now, Properties: props}
}

// devices records one asset per directory below base. A field mapped to
// firmwareVersion also yields a firmware child asset sourced from that file.
func (c *collector) devices(base, name string, fields map[string]string) {
	files := make([]string, 0, len(fields))
	for file := range fields {
		files = append(files, file)
	}
	sort.Strings(files) // first match wins when drivers share a key
	for _, entry := range c.dirs(base) {
		if base == "sys/class/drm" && !drmCard.MatchString(entry.Name()) {
			continue // connectors and render nodes repeat the card's device
		}
		p := path.Join(base, entry.Name())
		props := map[string]string{}
		firmware := ""
		for _, file := range files {
			key := fields[file]
			if props[key] != "" {
				continue
			}
			if v := c.read(path.Join(p, file)); v != "" {
				props[key] = v
				if key == "firmwareVersion" {
					firmware = file
				}
			}
		}
		if len(props) == 0 {
			continue
		}
		if base == "sys/class/scsi_host" {
			props["driver"] = c.read(p + "/proc_name")
		}
		a := c.asset("device", name, p, "", props)
		a.Model = props["model"]
		a.Vendor = props["vendor"]
		a.Revision = props["revision"]
		c.assets = append(c.assets, a)
		if base == "sys/bus/pci/devices" && strings.HasPrefix(props["class"], "0x02") && !c.nicFirmware[entry.Name()] {
			c.issue(p, "not_supported", "NIC firmware requires devlink or vendor evidence; PCI identity does not establish firmware version")
		}
		if firmware != "" {
			f := c.asset("firmware", name+" firmware", p+"/"+firmware, a.ID, map[string]string{"state": "observed", "versionFormat": "vendor"})
			f.Version = props["firmwareVersion"]
			c.assets = append(c.assets, f)
		}
		// Read a driver's name only after os.Root has validated its symlink target.
		if driver, err := c.root.Open(p + "/driver"); err == nil {
			driver.Close()
			if target, err := c.root.Readlink(p + "/driver"); err == nil {
				d := c.asset("device-driver", path.Base(target), p+"/driver", a.ID, map[string]string{})
				d.Version = c.read(p + "/driver/module/version")
				c.assets = append(c.assets, d)
			}
		}
	}
}
func (c *collector) dmi() string {
	p := "sys/class/dmi/id"
	props := map[string]string{}
	for _, field := range []string{"sys_vendor", "product_name", "product_version", "board_vendor", "board_name", "board_version", "bios_vendor", "bios_version", "bios_date"} {
		if v := c.read(p + "/" + field); v != "" {
			props[field] = v
		}
	}
	if len(props) == 0 {
		c.issue(p, "not_observed", "DMI identity unavailable; physical host identity requires other evidence")
		return ""
	}
	a := c.asset("device", "System board", p, "", props)
	a.Vendor = props["sys_vendor"]
	a.Model = props["product_name"]
	a.Revision = props["board_version"]
	c.assets = append(c.assets, a)
	if v := props["bios_version"]; v != "" {
		b := c.asset("firmware", "BIOS/UEFI", p+"/bios_version", a.ID, map[string]string{"releaseDate": props["bios_date"], "state": "observed"})
		b.Version = v
		b.Vendor = props["bios_vendor"]
		c.assets = append(c.assets, b)
	}
	return a.ID
}
func (c *collector) cpu() {
	// Read each processor record so mixed stepping or microcode remains visible.
	data := c.read("proc/cpuinfo")
	if data == "" {
		c.issue("proc/cpuinfo", "not_observed", "CPU identity unavailable")
		return
	}
	mitigations := map[string]string{}
	for _, e := range c.dirs("sys/devices/system/cpu/vulnerabilities") {
		if v := c.read("sys/devices/system/cpu/vulnerabilities/" + e.Name()); v != "" {
			mitigations["mitigation."+e.Name()] = v
		}
	}
	for i, record := range strings.Split(data, "\n\n") {
		props := map[string]string{}
		for k, v := range mitigations {
			props[k] = v
		}
		for _, line := range strings.Split(record, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "processor", "vendor_id", "cpu family", "model", "model name", "stepping", "microcode", "CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision":
				props[k] = v
			case "flags":
				if strings.Contains(" "+v+" ", " hypervisor ") {
					props["virtualization"] = "guest"
				}
			}
		}
		if props["processor"] == "" {
			continue
		}
		props["hostPatchState"] = "unknown"
		a := c.asset("device", "CPU", fmt.Sprintf("proc/cpuinfo/%d", i), "", props)
		a.Model = props["model name"]
		a.Vendor = props["vendor_id"]
		a.Revision = props["stepping"]
		c.assets = append(c.assets, a)
		if v := props["microcode"]; v != "" {
			f := c.asset("firmware", "CPU microcode", a.Source+"/microcode", a.ID, map[string]string{"state": "reported-running"})
			f.Version = v
			c.assets = append(c.assets, f)
		}
	}
}

// Container markers establish a limited observation scope. Their absence cannot
// prove a physical host, since container runtimes may hide namespace metadata.
func (c *collector) detectScope() {
	c.scope = "host-or-guest-unverified"
	for _, p := range []string{".dockerenv", "run/.containerenv"} {
		if _, err := c.root.Stat(p); err == nil {
			c.scope = "container-visible"
		}
	}
	if c.read("run/systemd/container") != "" {
		c.scope = "container-visible"
	}
	for _, p := range []string{"proc/self/cgroup", "proc/1/cgroup"} {
		data := c.read(p)
		for _, marker := range []string{"/docker/", "docker-", "/kubepods/", "kubepods-", "/lxc/", "libpod-"} {
			if strings.Contains(data, marker) {
				c.scope = "container-visible"
			}
		}
	}
	if c.scope == "container-visible" {
		c.issue("proc/self/cgroup", "incomplete", "container-visible hardware may belong to the host; physical host ownership and firmware state require host evidence")
	}
}
