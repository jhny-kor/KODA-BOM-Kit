//go:build linux

package hostcontext

import (
	"context"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"koda.local/security-sbom-linux/internal/model"
)

func kernelRelease() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", err
	}
	b := make([]byte, 0, len(u.Release))
	for _, v := range u.Release {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b), nil
}
func collectRuntime(ctx context.Context, root *os.Root, out *model.Context, denied []string) {
	kernel, err := kernelRelease()
	if err != nil {
		issue(out, "incomplete", "", "running kernel cannot be read")
	} else {
		out.RunningKernel = kernel
		lower := strings.ToLower(kernel)
		switch {
		case strings.Contains(lower, "uek"):
			out.KernelFlavor = "UEK"
		case strings.Contains(lower, ".el"):
			out.KernelFlavor = "RHCK-compatible"
		default:
			out.KernelFlavor = "unknown"
		}
	}
	if data, err := readBounded(root, "proc/modules"); err == nil {
		out.LoadedModules = parseModules(string(data))
	} else {
		issue(out, statusFor(err), "proc/modules", "loaded module list unavailable; built-in kernel features remain unknown")
	}
	collectLivepatch(ctx, root, out)
	for _, name := range []string{"proc/sys/kernel/unprivileged_userns_clone", "proc/sys/user/max_user_namespaces"} {
		data, err := readBounded(root, name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			issue(out, statusFor(err), name, "kernel setting unavailable")
			continue
		}
		value := strings.TrimSpace(string(data))
		if _, err := strconv.ParseUint(value, 10, 64); err == nil {
			out.Settings = append(out.Settings, model.Setting{Product: "Linux kernel", Name: strings.ReplaceAll(strings.TrimPrefix(name, "proc/sys/"), "/", "."), Value: value, Path: name, State: "observed"})
		}
	}
	proc, err := root.Open("proc")
	if err != nil {
		issue(out, statusFor(err), "proc", "process links unavailable")
		return
	}
	defer proc.Close()
	entries, err := proc.ReadDir(maxProcesses + 256)
	if err != nil && err != io.EOF {
		issue(out, statusFor(err), "proc", "process links unavailable")
		return
	}
	if len(entries) == maxProcesses+256 {
		issue(out, "incomplete", "proc", "process directory entry limit reached")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	count := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		count++
		if count > maxProcesses {
			issue(out, "incomplete", "proc", "process link count limit reached")
			break
		}
		prefix := "proc/" + entry.Name()
		exe, err := root.Readlink(prefix + "/exe")
		if err != nil {
			if os.IsPermission(err) {
				issue(out, "permission_denied", prefix+"/exe", "process executable link unavailable")
			}
			continue
		}
		exe = safeRuntimePath(exe)
		if exe == "" || blocked(exe, denied) {
			continue
		}
		link := model.ProcessLink{PID: pid, Executable: exe}
		if data, err := readBounded(root, prefix+"/maps"); err == nil {
			link.Libraries = parseMaps(string(data), denied)
			if len(link.Libraries) >= maxLibraries {
				issue(out, "incomplete", prefix+"/maps", "process shared-library count limit reached")
			}
		} else if !os.IsNotExist(err) {
			issue(out, statusFor(err), prefix+"/maps", "process library links unavailable")
		}
		if data, err := readBounded(root, prefix+"/cmdline"); err == nil {
			link.InstallHints = parseInstallHints(string(data), denied)
		}
		out.ProcessLinks = append(out.ProcessLinks, link)
	}
}
func parseModules(data string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && simpleToken.MatchString(fields[0]) {
			seen[fields[0]] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
func safeRuntimePath(p string) string {
	p = strings.TrimSuffix(p, " (deleted)")
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n") {
		return ""
	}
	return strings.TrimPrefix(path.Clean(p), "/")
}
func parseMaps(data string, denied []string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		p := safeRuntimePath(strings.Join(fields[5:], " "))
		if p == "" || blocked(p, denied) || !strings.Contains(path.Base(p), ".so") {
			continue
		}
		seen[p] = true
		if len(seen) >= maxLibraries {
			break
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func parseInstallHints(data string, denied []string) []string {
	prefixes := []string{"-Dcatalina.base=", "-Dcatalina.home=", "-Djboss.home.dir=", "-Dweblogic.RootDirectory=", "-Djeus.home="}
	seen := map[string]bool{}
	for _, arg := range strings.Split(data, "\x00") {
		for _, prefix := range prefixes {
			if strings.HasPrefix(arg, prefix) {
				p := safeRuntimePath(strings.TrimPrefix(arg, prefix))
				if p != "" && !blocked(p, denied) {
					seen[p] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
