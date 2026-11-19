package hardware

import (
	"fmt"
	"strconv"
)

// cpuidSignature rebuilds the CPUID leaf 1 EAX value from the decoded family,
// model and stepping that x86 /proc/cpuinfo prints. Intel and AMD microcode
// advisories list processors by this value (for example 00050657) or by the
// family-model-stepping name of the microcode file (06-55-07).
func cpuidSignature(family, model, stepping string) (signature, fms string, ok bool) {
	f, errF := strconv.Atoi(family)
	m, errM := strconv.Atoi(model)
	s, errS := strconv.Atoi(stepping)
	if errF != nil || errM != nil || errS != nil || f < 0 || f > 0xf+0xff || m < 0 || m > 0xff || s < 0 || s > 0xf {
		return "", "", false
	}
	base, extended := f, 0
	if f >= 0xf {
		base, extended = 0xf, f-0xf
	}
	eax := s | (m&0xf)<<4 | base<<8 | (m>>4)<<16 | extended<<20
	return fmt.Sprintf("%08X", eax), fmt.Sprintf("%02x-%02x-%02x", f, m, s), true
}

// armImplementers and armParts follow util-linux lscpu (sys-utils/lscpu-arm.c),
// limited to 64-bit application and server cores, so names match `lscpu`.
var armImplementers = map[int]string{
	0x41: "ARM", 0x42: "Broadcom", 0x43: "Cavium", 0x46: "FUJITSU", 0x48: "HiSilicon",
	0x4e: "NVIDIA", 0x50: "APM", 0x51: "Qualcomm", 0x53: "Samsung", 0x56: "Marvell",
	0x61: "Apple", 0x69: "Intel", 0x6d: "Microsoft", 0x70: "Phytium", 0xc0: "Ampere",
}

var armParts = map[int]map[int]string{
	0x41: {
		0xd01: "Cortex-A32", 0xd02: "Cortex-A34", 0xd03: "Cortex-A53", 0xd04: "Cortex-A35", 0xd05: "Cortex-A55",
		0xd06: "Cortex-A65", 0xd07: "Cortex-A57", 0xd08: "Cortex-A72", 0xd09: "Cortex-A73", 0xd0a: "Cortex-A75",
		0xd0b: "Cortex-A76", 0xd0c: "Neoverse-N1", 0xd0d: "Cortex-A77", 0xd0e: "Cortex-A76AE",
		0xd40: "Neoverse-V1", 0xd41: "Cortex-A78", 0xd42: "Cortex-A78AE", 0xd43: "Cortex-A65AE", 0xd44: "Cortex-X1",
		0xd46: "Cortex-A510", 0xd47: "Cortex-A710", 0xd48: "Cortex-X2", 0xd49: "Neoverse-N2", 0xd4a: "Neoverse-E1",
		0xd4b: "Cortex-A78C", 0xd4c: "Cortex-X1C", 0xd4d: "Cortex-A715", 0xd4e: "Cortex-X3", 0xd4f: "Neoverse-V2",
		0xd80: "Cortex-A520", 0xd81: "Cortex-A720", 0xd82: "Cortex-X4", 0xd83: "Neoverse-V3AE", 0xd84: "Neoverse-V3",
		0xd85: "Cortex-X925", 0xd87: "Cortex-A725", 0xd88: "Cortex-A520AE", 0xd89: "Cortex-A720AE",
		0xd8a: "C1-Nano", 0xd8b: "C1-Pro", 0xd8c: "C1-Ultra", 0xd8e: "Neoverse-N3", 0xd8f: "Cortex-A320", 0xd90: "C1-Premium",
	},
	0x43: {
		0x0a0: "ThunderX", 0x0a1: "ThunderX-88XX", 0x0a2: "ThunderX-81XX", 0x0a3: "ThunderX-83XX", 0x0af: "ThunderX2-99xx",
		0x0b0: "OcteonTX2", 0x0b1: "OcteonTX2-98XX", 0x0b2: "OcteonTX2-96XX", 0x0b3: "OcteonTX2-95XX",
		0x0b4: "OcteonTX2-95XXN", 0x0b5: "OcteonTX2-95XXMM", 0x0b6: "OcteonTX2-95XXO", 0x0b8: "ThunderX3-T110",
	},
	0x46: {0x001: "A64FX", 0x003: "MONAKA"},
	0x48: {0xd01: "Kunpeng-920", 0xd02: "Kunpeng-920", 0xd03: "Kunpeng-920", 0xd06: "Kunpeng-950", 0xd22: "Kunpeng-920", 0xd40: "Cortex-A76", 0xd41: "Cortex-A77"},
	0x4e: {0x000: "Denver", 0x003: "Denver-2", 0x004: "Carmel", 0x010: "Olympus"},
	0x50: {0x000: "X-Gene"},
	0x6d: {0xd49: "Azure-Cobalt-100"},
	0x70: {0x303: "FTC310", 0x660: "FTC660", 0x661: "FTC661", 0x662: "FTC662", 0x663: "FTC663", 0x664: "FTC664", 0x862: "FTC862"},
	0xc0: {0xac3: "Ampere-1", 0xac4: "Ampere-1a"},
}

// armNames decodes the hexadecimal CPU implementer and part of arm64
// /proc/cpuinfo. An unlisted part keeps only the implementer name.
func armNames(implementer, part string) (vendor, model string) {
	impl, err := strconv.ParseInt(implementer, 0, 32)
	if err != nil {
		return "", ""
	}
	vendor = armImplementers[int(impl)]
	if p, err := strconv.ParseInt(part, 0, 32); err == nil {
		model = armParts[int(impl)][int(p)]
	}
	return vendor, model
}
