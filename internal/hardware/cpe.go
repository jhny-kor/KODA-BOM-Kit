package hardware

import (
	"regexp"
	"strings"
)

// CPE names follow the NVD dictionary, checked for each form below
// (for example cpe:2.3:h:intel:xeon_gold_6248, cpe:2.3:o:dell:poweredge_r740_firmware).
// Vendors whose dictionary naming is inconsistent (HPE uses both hp and hpe) and
// BMCs, whose generation IPMI does not report, get no CPE.

var cpeProduct = regexp.MustCompile(`^[a-z][a-z0-9_.-]*[0-9][a-z0-9_.-]*$`)
var cpeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func cpe(part, vendor, product, version string) string {
	if !cpeProduct.MatchString(product) {
		return ""
	}
	if version == "" {
		version = "-"
	} else if !cpeVersion.MatchString(version) {
		return ""
	}
	return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*"
}

// cpuCPE derives a hardware CPE from an x86 model name such as
// "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" (xeon_e5-2680_v4) or
// "AMD EPYC 7763 64-Core Processor" (epyc_7763). Virtual CPU names without a
// model number, such as "Intel Xeon Processor (Cascadelake)", get none.
func cpuCPE(name string) string {
	name, _, _ = strings.Cut(name, "@")
	name = strings.NewReplacer("(R)", " ", "(r)", " ", "(TM)", " ", "(tm)", " ").Replace(name)
	var words []string
	for _, w := range strings.Fields(name) {
		lower := strings.ToLower(w)
		if lower == "cpu" || lower == "processor" || lower == "0" || strings.HasSuffix(lower, "-core") {
			continue
		}
		words = append(words, lower)
	}
	if len(words) < 3 {
		return ""
	}
	vendor, family := words[0], words[1]
	switch {
	case vendor == "intel" && (family == "xeon" || family == "core"):
	case vendor == "amd" && (family == "epyc" || family == "ryzen"):
	default:
		return ""
	}
	return cpe("h", vendor, strings.Join(words[1:], "_"), "")
}

// systemCPEs returns hardware and BIOS firmware CPEs for vendors whose NVD
// naming matches DMI: Dell PowerEdge (firmware versions are BIOS versions) and
// Lenovo ThinkSystem (hardware only; NVD firmware versions use build IDs).
func systemCPEs(sysVendor, productName, biosVersion string) (hardware, firmware string) {
	// Lenovo appends the machine type: "ThinkSystem SR650 -[7X06CTO1WW]-".
	productName, _, _ = strings.Cut(productName, "-[")
	product := strings.ToLower(strings.Join(strings.Fields(productName), "_"))
	switch vendor := strings.ToLower(sysVendor); {
	case strings.HasPrefix(vendor, "dell") && strings.HasPrefix(product, "poweredge_"):
		hardware = cpe("h", "dell", product, "")
		if hardware != "" && biosVersion != "" {
			firmware = cpe("o", "dell", product+"_firmware", biosVersion)
		}
	case vendor == "lenovo" && strings.HasPrefix(product, "thinksystem_"):
		hardware = cpe("h", "lenovo", product, "")
	}
	return hardware, firmware
}
