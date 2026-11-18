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
