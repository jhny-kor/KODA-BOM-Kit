package hostcontext

import (
	"regexp"
	"strconv"
	"strings"
)

// selectedLockdown returns the bracketed mode of /sys/kernel/security/lockdown,
// for example "integrity" from "none [integrity] confidentiality".
func selectedLockdown(data string) string {
	start, end := strings.IndexByte(data, '['), strings.IndexByte(data, ']')
	if start < 0 || end <= start+1 {
		return ""
	}
	mode := data[start+1 : end]
	if mode != "none" && mode != "integrity" && mode != "confidentiality" {
		return ""
	}
	return mode
}

// selinuxConfigMode reads the persisted SELINUX= mode, which applies after
// the next boot and may differ from the running mode.
func selinuxConfigMode(data string) string {
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(key) != "SELINUX" {
			continue
		}
		switch value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`)); value {
		case "enforcing", "permissive", "disabled":
			return value
		}
		return "unknown"
	}
	return ""
}

var taintFlags = regexp.MustCompile(`^\(([A-Z]{1,26})\)$`)

// parseTaintedModules returns name and taint letters for /proc/modules lines
// that end with a flag group, for example "nvidia ... Live 0x0 (POE)".
func parseTaintedModules(data string) [][2]string {
	var out [][2]string
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || !simpleToken.MatchString(fields[0]) {
			continue
		}
		if m := taintFlags.FindStringSubmatch(fields[len(fields)-1]); m != nil {
			out = append(out, [2]string{fields[0], m[1]})
		}
	}
	return out
}

var releaseSegment = regexp.MustCompile(`[0-9]+|[A-Za-z]+`)
var releaseLetters = regexp.MustCompile(`[A-Za-z]+`)

// kernelFlavor groups releases that replace one another on upgrade:
// "6.8.0-45-generic" and "6.8.0-49-generic" share "generic", while an Oracle
// UEK and a Red Hat compatible kernel installed side by side do not.
// ponytail: letter-token heuristic; a distro-specific default boot entry
// (grubenv/BLS) is the upgrade path if flavors collide in practice.
func kernelFlavor(release string) string {
	return strings.Join(releaseLetters.FindAllString(release, -1), " ")
}

// compareKernelRelease orders releases segment by segment like rpmvercmp:
// numbers numerically, letters lexically, a number above a letter.
func compareKernelRelease(a, b string) int {
	x, y := releaseSegment.FindAllString(a, -1), releaseSegment.FindAllString(b, -1)
	for i := 0; i < len(x) && i < len(y); i++ {
		xn, xErr := strconv.ParseUint(x[i], 10, 64)
		yn, yErr := strconv.ParseUint(y[i], 10, 64)
		switch {
		case xErr == nil && yErr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xErr == nil:
			return 1
		case yErr == nil:
			return -1
		default:
			if c := strings.Compare(x[i], y[i]); c != 0 {
				return c
			}
		}
	}
	return len(x) - len(y)
}

// newerKernel returns the newest installed release of the running kernel's
// flavor when it is newer than the running one.
func newerKernel(running string, installed []string) string {
	newest := running
	for _, release := range installed {
		if kernelFlavor(release) == kernelFlavor(running) && compareKernelRelease(release, newest) > 0 {
			newest = release
		}
	}
	if newest == running {
		return ""
	}
	return newest
}

const maxKernelConfigOptions = 20000

var kernelConfigName = regexp.MustCompile(`^CONFIG_[A-Za-z0-9_]{1,128}$`)

// parseKernelConfig returns the built-in (y) and module (m) options of a
// kernel .config. Whether a feature is built decides if many kernel CVEs apply;
// unset and valued options are omitted.
func parseKernelConfig(data string) map[string]string {
	options := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && (value == "y" || value == "m") && kernelConfigName.MatchString(key) && len(options) < maxKernelConfigOptions {
			options[key] = value
		}
	}
	return options
}

// Boot parameters that switch kernel protections. Only these are recorded:
// the full command line may carry storage paths or credentials (iSCSI, NFS).
var cmdlineParameters = map[string]bool{
	"mitigations": true, "nospectre_v1": true, "nospectre_v2": true, "spectre_v2": true, "spectre_v2_user": true,
	"spectre_bhi": true, "spec_store_bypass_disable": true, "nospec_store_bypass_disable": true, "ssbd": true,
	"l1tf": true, "mds": true, "tsx": true, "tsx_async_abort": true, "mmio_stale_data": true, "retbleed": true,
	"srbds": true, "gather_data_sampling": true, "reg_file_data_sampling": true, "spec_rstack_overflow": true,
	"pti": true, "nopti": true, "kpti": true, "nosmt": true, "nokaslr": true, "nosmap": true, "nosmep": true,
	"vsyscall": true, "init_on_alloc": true, "init_on_free": true, "slab_nomerge": true, "randomize_kstack_offset": true,
	"lockdown": true, "module.sig_enforce": true, "ima_appraise": true, "ima_policy": true, "selinux": true,
	"enforcing": true, "apparmor": true, "security": true, "lsm": true, "audit": true, "fips": true,
	"iommu": true, "intel_iommu": true, "amd_iommu": true, "debugfs": true, "sysrq_always_enabled": true,
}

var cmdlineValue = regexp.MustCompile(`^[A-Za-z0-9_.,:+-]{1,128}$`)

// cmdlineSettings returns allowlisted security parameters of /proc/cmdline in
// order. A flag without a value is reported as "set"; the last occurrence wins,
// as it does for the kernel.
func cmdlineSettings(cmdline string) [][2]string {
	var out [][2]string
	index := map[string]int{}
	for _, field := range strings.Fields(cmdline) {
		name, value, hasValue := strings.Cut(field, "=")
		name = strings.ReplaceAll(name, "-", "_") // the kernel treats - and _ alike
		if !cmdlineParameters[name] {
			continue
		}
		if !hasValue {
			value = "set"
		} else if !cmdlineValue.MatchString(value) {
			continue
		}
		if i, ok := index[name]; ok {
			out[i][1] = value
			continue
		}
		index[name] = len(out)
		out = append(out, [2]string{name, value})
	}
	return out
}
