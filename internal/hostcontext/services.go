package hostcontext

import (
	"bufio"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxServices = 2000

// Unit directories in systemd's precedence order. /run holds runtime units
// and is read only on a live host.
var unitDirs = []string{"etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}

var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]{1,200}\.(service|socket|timer)$`)
var scheduleValue = regexp.MustCompile(`^[A-Za-z0-9 _.:,*/~+-]{1,128}$`)
var listenValue = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]/@%-]{1,128}$`)

// collectServices records services and sockets enabled to start at boot
// (linked from a *.wants or *.requires directory). On a live host each
// also gets whether its cgroup currently holds processes; a disabled-looking
// "stopped" socket-activated service still listens through its socket.
// allowed, when not nil, limits unit file reads to the caller's scan plan.
func collectServices(root *os.Root, out *model.Context, live bool, allowed map[string]bool) {
	dirs := unitDirs
	if !live {
		dirs = []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}
	}
	enabled := map[string]map[string]bool{} // unit -> targets
	for _, dir := range dirs {
		f, err := openNoFollow(root, dir)
		if err != nil {
			continue
		}
		entries, _ := f.ReadDir(4096)
		f.Close()
		for _, e := range entries {
			target, ok := strings.CutSuffix(e.Name(), ".wants")
			if !ok {
				target, ok = strings.CutSuffix(e.Name(), ".requires")
			}
			if !ok || !e.IsDir() {
				continue
			}
			links, err := openNoFollow(root, dir+"/"+e.Name())
			if err != nil {
				continue
			}
			names, _ := links.ReadDir(4096)
			links.Close()
			for _, link := range names {
				if !unitName.MatchString(link.Name()) {
					continue
				}
				if enabled[link.Name()] == nil {
					enabled[link.Name()] = map[string]bool{}
				}
				enabled[link.Name()][target] = true
			}
		}
	}
	units := make([]string, 0, len(enabled))
	for unit := range enabled {
		units = append(units, unit)
	}
	sort.Strings(units)
	for _, unit := range units {
		if len(out.EnabledServices) >= maxServices {
			issue(out, "incomplete", "etc/systemd/system", "enabled unit limit reached")
			break
		}
		file, keys, masked := readUnit(root, dirs, unit, allowed)
		if masked {
			continue
		}
		service := model.Service{Unit: unit, UnitFile: file, WantedBy: sortedKeys(enabled[unit])}
		if strings.HasSuffix(unit, ".socket") {
			for _, k := range []string{"ListenStream", "ListenDatagram", "ListenSequentialPacket"} {
				for _, v := range keys[k] {
					if listenValue.MatchString(v) {
						service.Listen = append(service.Listen, k+"="+v)
					}
				}
			}
			activated := strings.TrimSuffix(unit, ".socket") + ".service"
			if values := keys["Accept"]; len(values) > 0 && parseBool(values[len(values)-1]) {
				activated = strings.TrimSuffix(unit, ".socket") + "@.service"
			}
			if values := keys["Service"]; len(values) > 0 && unitName.MatchString(values[len(values)-1]) {
				activated = values[len(values)-1]
			}
			service.Activates = activated
			_, keys, _ = readUnit(root, dirs, activated, allowed)
		}
		if strings.HasSuffix(unit, ".timer") {
			for _, k := range []string{"OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec", "OnUnitActiveSec", "OnUnitInactiveSec"} {
				for _, v := range keys[k] {
					if scheduleValue.MatchString(v) {
						service.Schedule = append(service.Schedule, k+"="+v)
					}
				}
			}
			activated := strings.TrimSuffix(unit, ".timer") + ".service"
			if values := keys["Unit"]; len(values) > 0 && unitName.MatchString(values[len(values)-1]) {
				activated = values[len(values)-1]
			}
			service.Activates = activated
			_, keys, _ = readUnit(root, dirs, activated, allowed)
		}
		service.Executable = execPath(keys["ExecStart"])
		if live {
			service.State = "stopped"
			if serviceRunning(root, unit) || (service.Activates != "" && serviceRunning(root, service.Activates)) {
				service.State = "running"
			}
		}
		out.EnabledServices = append(out.EnabledServices, service)
	}
}

// readUnit returns the unit file used for unit (a template file for an
// instance) and its [Service]/[Socket] keys with drop-ins applied in order.
// An empty assignment resets a list, as systemd does for ExecStart.
func readUnit(root *os.Root, dirs []string, unit string, allowed map[string]bool) (string, map[string][]string, bool) {
	keys := map[string][]string{}
	name := unit
	if at := strings.IndexByte(unit, '@'); at >= 0 {
		name = unit[:at+1] + unit[strings.LastIndexByte(unit, '.'):]
	}
	main := ""
	for _, dir := range dirs {
		for _, candidate := range []string{unit, name} {
			if _, err := root.Lstat(dir + "/" + candidate); err != nil || main != "" {
				continue
			}
			resolved, err := resolveInRoot(root, dir+"/"+candidate)
			if resolved == "dev/null" {
				return "", nil, true // masked
			}
			if err == nil {
				main = resolved
			}
		}
	}
	files := []string{}
	if main != "" {
		files = append(files, main)
	}
	dropins := map[string]string{}
	for i := len(dirs) - 1; i >= 0; i-- { // higher precedence overrides the same drop-in name
		for _, candidate := range []string{name, unit} {
			f, err := openNoFollow(root, dirs[i]+"/"+candidate+".d")
			if err != nil {
				continue
			}
			entries, _ := f.ReadDir(256)
			f.Close()
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") {
					dropins[e.Name()] = dirs[i] + "/" + candidate + ".d/" + e.Name()
				}
			}
		}
	}
	for _, n := range sortedKeys(toSet(dropins)) {
		files = append(files, dropins[n])
	}
	for _, p := range files {
		p, err := resolveInRoot(root, p)
		if err != nil || (allowed != nil && !allowed[p]) {
			continue
		}
		f, _, err := openUnit(root, p)
		if err != nil {
			continue
		}
		section := ""
		scanner := bufio.NewScanner(io.LimitReader(f, maxFileBytes))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "[") {
				section = line
				continue
			}
			if section != "[Service]" && section != "[Socket]" && section != "[Timer]" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if v == "" {
				delete(keys, k)
				continue
			}
			keys[k] = append(keys[k], v)
		}
		f.Close()
	}
	return main, keys, false
}

// resolveInRoot follows symlinks the way the target system would, with
// absolute targets taken inside root (os.Root refuses them). Unit aliases and
// enabled units are commonly absolute links into /usr/lib/systemd/system.
func resolveInRoot(root *os.Root, p string) (string, error) {
	for range 8 {
		st, err := root.Lstat(p)
		if err != nil {
			return p, err
		}
		if st.Mode()&os.ModeSymlink == 0 {
			return p, nil
		}
		target, err := root.Readlink(p)
		if err != nil {
			return p, err
		}
		if path.IsAbs(target) {
			p = path.Clean(target)[1:]
		} else {
			p = path.Join(path.Dir(p), target)
		}
		if p == "dev/null" {
			return p, nil
		}
		if p == ".." || strings.HasPrefix(p, "../") {
			return p, os.ErrInvalid
		}
	}
	return p, os.ErrInvalid
}

// openUnit opens a resolved regular unit file.
func openUnit(root *os.Root, p string) (*os.File, os.FileInfo, error) {
	f, err := root.Open(p)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxFileBytes {
		f.Close()
		return nil, nil, os.ErrInvalid
	}
	return f, st, nil
}

// execPath returns the absolute program of the first ExecStart command,
// without systemd's special prefixes (@, -, :, +, !).
func execPath(values []string) string {
	if len(values) == 0 {
		return ""
	}
	fields := strings.Fields(values[0])
	if len(fields) == 0 {
		return ""
	}
	program := strings.Trim(strings.TrimLeft(fields[0], "@-:+!"), `"'`)
	if !strings.HasPrefix(program, "/") || !safeExecutable.MatchString(program) {
		return ""
	}
	return strings.TrimPrefix(path.Clean(program), "/")
}

var safeExecutable = regexp.MustCompile(`^/[A-Za-z0-9_./+-]{1,255}$`)

// serviceRunning reports whether the unit's cgroup (v2, else v1 named
// hierarchy) under system.slice holds processes.
func serviceRunning(root *os.Root, unit string) bool {
	if strings.HasSuffix(unit, "@.service") {
		return false
	}
	slice := "system.slice/"
	if at := strings.IndexByte(unit, '@'); at >= 0 {
		// Template instances run in system-<prefix>.slice; "-" is escaped.
		slice += "system-" + strings.ReplaceAll(unit[:at], "-", `\x2d`) + ".slice/"
	}
	for _, base := range []string{"sys/fs/cgroup/", "sys/fs/cgroup/systemd/"} {
		if data, err := readBounded(root, base+slice+unit+"/cgroup.procs"); err == nil {
			return strings.TrimSpace(string(data)) != ""
		}
	}
	return false
}

func parseBool(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

func toSet(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
