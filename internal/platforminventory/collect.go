// Package platforminventory collects native platform metadata with fixed read-only commands.
package platforminventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

const maxOutput = 32 << 20

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		return 0, errors.New("platform inventory output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func command(ctx context.Context, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	var out boundedOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, errors.New("platform inventory command failed or exceeded limits")
	}
	return out.Bytes(), nil
}
func value(r map[string]json.RawMessage, key string) string {
	var s string
	if json.Unmarshal(r[key], &s) != nil {
		return ""
	}
	s = strings.TrimSpace(s)
	if len(s) > 512 || strings.ContainsAny(s, "\x00\r\n") {
		return ""
	}
	return s
}
func asset(kind, name, version, source, identity string) model.Asset {
	h := sha256.Sum256([]byte(source + "\x00" + kind + "\x00" + identity))
	return model.Asset{ID: "platform-" + hex.EncodeToString(h[:12]), Kind: kind, Name: name, Version: version, Source: source, ObservedAt: time.Now().UTC().Format(time.RFC3339), Properties: map[string]string{}}
}
func issue(code, message string) model.Issue {
	return model.Issue{Collector: "platform-inventory", Status: "incomplete", Code: code, Message: message}
}

func parseMac(raw []byte) ([]model.Asset, error) {
	var doc map[string][]map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil, errors.New("invalid system_profiler JSON")
	}
	out := []model.Asset{}
	for _, r := range doc["SPHardwareDataType"] {
		a := asset("device", value(r, "machine_name"), "", "system-profiler", "system")
		a.Vendor = "Apple"
		a.Model = value(r, "machine_model")
		a.Properties["productCode"] = value(r, "model_number")
		out = append(out, a)
		for _, f := range []struct{ key, name string }{{"boot_rom_version", "System firmware"}, {"os_loader_version", "OS loader"}} {
			if v := value(r, f.key); v != "" {
				fw := asset("firmware", f.name, v, "system-profiler", f.key)
				fw.Vendor = "Apple"
				fw.ParentID = a.ID
				out = append(out, fw)
			}
		}
		if chip := value(r, "chip_type"); chip != "" {
			cpu := asset("device", chip, "", "system-profiler", "cpu")
			cpu.Vendor = "Apple"
			cpu.ParentID = a.ID
			out = append(out, cpu)
		}
	}
	for _, r := range doc["SPSoftwareDataType"] {
		a := asset("operating-system", "macOS", value(r, "os_version"), "system-profiler", "macos")
		a.Vendor = "Apple"
		for _, key := range []string{"kernel_version", "system_integrity", "secure_vm", "boot_mode"} {
			a.Properties[key] = value(r, key)
		}
		out = append(out, a)
	}
	for i, r := range doc["SPApplicationsDataType"] {
		if i >= 4096 {
			return nil, errors.New("application inventory exceeds 4096 entries")
		}
		name := value(r, "_name")
		if name == "" {
			continue
		}
		path := value(r, "path")
		a := asset("application", name, value(r, "version"), "system-profiler", path+"\x00"+name)
		a.Properties["obtainedFrom"] = value(r, "obtained_from")
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("empty system_profiler inventory")
	}
	return out, nil
}

func parseWindows(raw []byte) ([]model.Asset, error) {
	var rows []map[string]json.RawMessage
	if json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), &rows) != nil {
		return nil, errors.New("invalid Windows inventory JSON")
	}
	if len(rows) > 4096 {
		return nil, errors.New("Windows inventory exceeds 4096 entries")
	}
	out := []model.Asset{}
	for _, r := range rows {
		kind := value(r, "kind")
		if kind != "device" && kind != "firmware" && kind != "operating-system" && kind != "application" {
			return nil, errors.New("invalid Windows component kind")
		}
		name := value(r, "name")
		if name == "" {
			continue
		}
		a := asset(kind, name, value(r, "version"), "windows-cim-registry", value(r, "identity"))
		a.Vendor = value(r, "vendor")
		a.Model = value(r, "model")
		for _, key := range []string{"build", "architecture", "hotfixId", "installedOn"} {
			if v := value(r, key); v != "" {
				a.Properties[key] = v
			}
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("empty Windows inventory")
	}
	return out, nil
}
