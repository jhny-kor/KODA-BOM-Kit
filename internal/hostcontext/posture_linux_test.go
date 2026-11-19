//go:build linux

package hostcontext

import (
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestSecurityPostureSettings(t *testing.T) {
	dir := t.TempDir()
	for p, v := range map[string]string{
		"sys/fs/selinux/enforce":                       "0\n",
		"sys/kernel/security/lockdown":                 "none [integrity] confidentiality\n",
		"sys/kernel/security/apparmor/profiles":        "/usr/sbin/cupsd (enforce)\nsnap.lxd.lxc (complain)\n/usr/bin/man (enforce)\n",
		"sys/module/apparmor/parameters/enabled":       "Y\n",
		"run/reboot-required":                          "*** System restart required ***\n",
		"usr/lib/modules/6.8.0-45-generic/modules.dep": "",
		"usr/lib/modules/6.8.0-49-generic/modules.dep": "",
		"usr/lib/modules/6.8.0-31-generic/extra.ko":    "", // leftover without modules.dep
	} {
		p = filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("usr/lib", filepath.Join(dir, "lib")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	out := &model.Context{RunningKernel: "6.8.0-45-generic"}
	collectSecurityPosture(root, out)
	got := map[string]string{}
	for _, s := range out.Settings {
		got[s.Product+"/"+s.Name] = s.Value
	}
	for key, want := range map[string]string{
		"SELinux/mode":                                  "permissive",
		"AppArmor/enabled":                              "true",
		"AppArmor/profiles.enforce":                     "2",
		"AppArmor/profiles.complain":                    "1",
		"Linux kernel/lockdown":                         "integrity",
		"Linux kernel/reboot.required-file":             "true",
		"Linux kernel/kernel.running-modules-installed": "true",
		"Linux kernel/kernel.newer-installed":           "6.8.0-49-generic",
		"Linux kernel/reboot.recommended":               "true",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	if len(out.Issues) != 0 {
		t.Errorf("unexpected issues %+v", out.Issues)
	}

	// No signals: the summary must not claim that no reboot is needed.
	empty, _ := os.OpenRoot(t.TempDir())
	defer empty.Close()
	quiet := &model.Context{RunningKernel: "6.8.0-45-generic"}
	collectSecurityPosture(empty, quiet)
	for _, s := range quiet.Settings {
		if s.Name == "reboot.recommended" && s.Value != "not_observed" {
			t.Errorf("reboot.recommended = %q without evidence", s.Value)
		}
	}
}

func TestKernelConfigSources(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "boot"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "boot/config-6.8.0-49-generic"), []byte("CONFIG_NF_TABLES=m\n# CONFIG_X is not set\n"), 0644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	out := model.Context{RunningKernel: "6.8.0-49-generic"}
	collectKernelConfig(root, &out, nil)
	if out.KernelConfig == nil || out.KernelConfig.Source != "boot/config-6.8.0-49-generic" || out.KernelConfig.Options["CONFIG_NF_TABLES"] != "m" || len(out.Issues) != 0 {
		t.Fatalf("config = %+v issues = %+v", out.KernelConfig, out.Issues)
	}
	out = model.Context{RunningKernel: "6.8.0-49-generic"}
	collectKernelConfig(root, &out, []string{"/boot"})
	if out.KernelConfig != nil {
		t.Fatal("excluded /boot must not be read")
	}
	out = model.Context{RunningKernel: "6.9.0"}
	collectKernelConfig(root, &out, nil)
	if out.KernelConfig != nil || len(out.Issues) != 0 {
		t.Fatalf("missing config must be silent: %+v", out.Issues)
	}
}
