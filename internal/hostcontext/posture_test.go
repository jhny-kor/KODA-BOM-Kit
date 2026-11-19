package hostcontext

import "testing"

func TestKernelReleaseOrderingAndFlavor(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"5.14.0-503.11.1.el9_5.x86_64", "5.14.0-427.13.1.el9_4.x86_64", 1},
		{"6.8.0-49-generic", "6.8.0-45-generic", 1},
		{"6.8.0-9-generic", "6.8.0-10-generic", -1},
		{"4.18.0-553.el8_10.x86_64", "4.18.0-553.el8_10.x86_64", 0},
	} {
		if got := compareKernelRelease(c.a, c.b); (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("compare(%s, %s) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
	running := "5.15.0-200.131.27.el8uek.x86_64"
	installed := []string{running, "4.18.0-553.22.1.el8_10.x86_64", "5.4.17-2136.el8uek.x86_64"}
	if got := newerKernel(running, installed); got != "" {
		t.Errorf("a newer RHCK must not count as an upgrade of UEK: %q", got)
	}
	installed = append(installed, "5.15.0-300.163.18.el8uek.x86_64")
	if got := newerKernel(running, installed); got != "5.15.0-300.163.18.el8uek.x86_64" {
		t.Errorf("newer UEK not found: %q", got)
	}
	if got := newerKernel("6.8.0-49-generic", []string{"6.8.0-49-generic", "6.8.0-51-aws"}); got != "" {
		t.Errorf("different flavor treated as upgrade: %q", got)
	}
}

func TestPostureParsers(t *testing.T) {
	if got := selectedLockdown("none [integrity] confidentiality"); got != "integrity" {
		t.Errorf("lockdown %q", got)
	}
	if got := selectedLockdown("none integrity"); got != "" {
		t.Errorf("unbracketed lockdown %q", got)
	}
	if got := selinuxConfigMode("# SELINUX=disabled\nSELINUXTYPE=targeted\nSELINUX=\"Enforcing\"\n"); got != "enforcing" {
		t.Errorf("selinux config %q", got)
	}
	if got := selinuxConfigMode("SELINUX=sometimes\n"); got != "unknown" {
		t.Errorf("invalid selinux config %q", got)
	}
}

func TestParseTaintedModules(t *testing.T) {
	data := "nvidia 56823808 1 nvidia_modeset, Live 0xffffffffc0a00000 (POE)\n" +
		"ext4 1056768 2 - Live 0xffffffffc0400000\n" +
		"zfs 6107136 6 - Live 0xffffffffc1200000 (PO)\n" +
		"bad 1 0 - Live 0x0 (oe)\n"
	got := parseTaintedModules(data)
	if len(got) != 2 || got[0] != [2]string{"nvidia", "POE"} || got[1] != [2]string{"zfs", "PO"} {
		t.Fatalf("got %v", got)
	}
}

func TestKernelConfigAndCmdline(t *testing.T) {
	options := parseKernelConfig("#\n# CONFIG_BPF_JIT is not set\nCONFIG_NF_TABLES=m\nCONFIG_USER_NS=y\nCONFIG_HZ=250\nCONFIG_LOCALVERSION=\"\"\nCONFIG_BAD-NAME=y\n")
	if len(options) != 2 || options["CONFIG_NF_TABLES"] != "m" || options["CONFIG_USER_NS"] != "y" {
		t.Errorf("options = %v", options)
	}
	got := cmdlineSettings(`BOOT_IMAGE=/vmlinuz root=UUID=1 rd.iscsi.password=secret mitigations=auto,nosmt nosmt spectre-v2=retpoline mitigations=off lsm="x y"`)
	want := [][2]string{{"mitigations", "off"}, {"nosmt", "set"}, {"spectre_v2", "retpoline"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}
