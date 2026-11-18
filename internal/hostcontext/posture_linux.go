//go:build linux

package hostcontext

import (
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

// collectSecurityPosture records kernel protections that change whether a
// vulnerability is exploitable, and signals that a reboot is still pending.
// Values are observations of this collection, not a compliance verdict.
func collectSecurityPosture(root *os.Root, out *model.Context) {
	add := func(product, name, value, p, state string) {
		out.Settings = append(out.Settings, model.Setting{Product: product, Name: name, Value: value, Path: p, State: state})
	}
	read := func(p string) (string, bool) {
		data, err := readBounded(root, p)
		if os.IsNotExist(err) {
			return "", false
		}
		if err != nil {
			issue(out, statusFor(err), p, "security setting unavailable")
			return "", false
		}
		return strings.TrimSpace(string(data)), true
	}

	if value, ok := read("sys/fs/selinux/enforce"); ok {
		mode := map[string]string{"1": "enforcing", "0": "permissive"}[value]
		if mode == "" {
			mode = "unknown"
		}
		add("SELinux", "mode", mode, "sys/fs/selinux/enforce", "observed")
	} else if _, err := root.Stat("sys/fs/selinux"); os.IsNotExist(err) {
		add("SELinux", "mode", "not_enabled", "sys/fs/selinux", "observed")
	}
	if value, ok := read("sys/module/apparmor/parameters/enabled"); ok {
		add("AppArmor", "enabled", strconv.FormatBool(value == "Y"), "sys/module/apparmor/parameters/enabled", "observed")
	}
	if value, ok := read("sys/kernel/security/apparmor/profiles"); ok {
		counts := map[string]int{}
		for _, line := range strings.Split(value, "\n") {
			if i := strings.LastIndex(line, " ("); i >= 0 && strings.HasSuffix(line, ")") {
				counts[line[i+2:len(line)-1]]++
			}
		}
		for _, mode := range []string{"enforce", "complain", "kill", "unconfined"} {
			add("AppArmor", "profiles."+mode, strconv.Itoa(counts[mode]), "sys/kernel/security/apparmor/profiles", "observed")
		}
	}
	if value, ok := read("sys/kernel/security/lockdown"); ok {
		if mode := selectedLockdown(value); mode != "" {
			add("Linux kernel", "lockdown", mode, "sys/kernel/security/lockdown", "observed")
		}
	}

	// Reboot signals. Each is reported separately so a reader can weigh them.
	pending := false
	if _, err := root.Lstat("run/reboot-required"); err == nil {
		add("Linux kernel", "reboot.required-file", "true", "run/reboot-required", "observed")
		pending = true
	}
	installed := installedKernels(root)
	if out.RunningKernel != "" && len(installed) > 0 {
		present := false
		for _, release := range installed {
			present = present || release == out.RunningKernel
		}
		add("Linux kernel", "kernel.running-modules-installed", strconv.FormatBool(present), "lib/modules", "observed")
		if newer := newerKernel(out.RunningKernel, installed); newer != "" {
			add("Linux kernel", "kernel.newer-installed", newer, "lib/modules", "observed")
			pending = true
		}
		pending = pending || !present
	}
	if out.RunningKernel != "" {
		value := "not_observed" // absence of a signal is not proof that no reboot is needed
		if pending {
			value = "true"
		}
		add("Linux kernel", "reboot.recommended", value, "", "derived")
	}
}

// installedKernels lists module trees that depmod completed (modules.dep).
// A leftover directory without it is usually a removed kernel.
func installedKernels(root *os.Root) []string {
	seen := map[string]bool{}
	for _, base := range []string{"usr/lib/modules", "lib/modules"} {
		dir, err := openNoFollow(root, base) // lib is often a symlink to usr/lib
		if err != nil {
			continue
		}
		entries, err := dir.ReadDir(1025)
		dir.Close()
		if err != nil && err != io.EOF {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !simpleToken.MatchString(entry.Name()) {
				continue
			}
			if st, err := root.Lstat(base + "/" + entry.Name() + "/modules.dep"); err == nil && st.Mode().IsRegular() {
				seen[entry.Name()] = true
			}
		}
	}
	releases := make([]string, 0, len(seen))
	for release := range seen {
		releases = append(releases, release)
	}
	sort.Strings(releases)
	return releases
}
