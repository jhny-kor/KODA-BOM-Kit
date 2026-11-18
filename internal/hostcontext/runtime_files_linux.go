//go:build linux

package hostcontext

import (
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"koda.local/security-sbom-linux/internal/model"
)

// Mapping identity refers to the running process. Disk comparison is allowed only
// when both mount namespace and process root agree with the collector.
func sameProcessFilesystem(root *os.Root, prefix string) bool {
	selfNS, err := root.Readlink("proc/self/ns/mnt")
	if err != nil {
		return false
	}
	processNS, err := root.Readlink(prefix + "/ns/mnt")
	if err != nil || selfNS != processNS {
		return false
	}
	proc, err := root.Open(prefix)
	if err != nil {
		return false
	}
	defer proc.Close()
	// procfs exposes a magic link for the process's / directory. Compare its
	// metadata by directory descriptor without opening paths in that root.
	var processRoot unix.Stat_t
	if err := unix.Fstatat(int(proc.Fd()), "root", &processRoot, 0); err != nil {
		return false
	}
	selfRoot, err := root.Stat(".")
	if err != nil {
		return false
	}
	st, ok := selfRoot.Sys().(*syscall.Stat_t)
	return ok && uint64(processRoot.Dev) == uint64(st.Dev) && processRoot.Ino == st.Ino
}

func runtimeFiles(root *os.Root, data string, denied []string, comparable bool) []model.RuntimeFile {
	files := parseRuntimeFiles(data, denied)
	for i := range files {
		item := &files[i]
		if item.Deleted {
			item.State = "restart_review"
			continue
		}
		if !comparable {
			item.State = "namespace_unknown"
			continue
		}
		f, err := openNoFollow(root, item.Path)
		if err != nil {
			if os.IsPermission(err) {
				item.State = "permission_denied"
			}
			continue
		}
		info, err := f.Stat()
		f.Close()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		item.DiskInode = stat.Ino
		device := strings.Split(item.Device, ":")
		major, e1 := strconv.ParseUint(device[0], 16, 32)
		minor, e2 := strconv.ParseUint(device[1], 16, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		if item.Inode != stat.Ino || uint32(major) != unix.Major(uint64(stat.Dev)) || uint32(minor) != unix.Minor(uint64(stat.Dev)) {
			item.State = "restart_review"
		} else {
			item.State = "observed"
		}
	}
	return files
}

func parseRuntimeFiles(data string, denied []string) []model.RuntimeFile {
	files := []model.RuntimeFile{}
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		raw := strings.Join(fields[5:], " ")
		p := safeRuntimePath(raw)
		if p == "" || blocked(p, denied) || (!strings.Contains(fields[1], "x") && !strings.Contains(path.Base(p), ".so")) {
			continue
		}
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		device := strings.Split(fields[3], ":")
		if err != nil || inode == 0 || len(device) != 2 {
			continue
		}
		if _, err := strconv.ParseUint(device[0], 16, 32); err != nil {
			continue
		}
		if _, err := strconv.ParseUint(device[1], 16, 32); err != nil {
			continue
		}
		key := p + "\x00" + fields[3] + "\x00" + fields[4]
		if seen[key] {
			continue
		}
		seen[key] = true
		files = append(files, model.RuntimeFile{Path: p, Deleted: strings.HasSuffix(raw, " (deleted)"), Device: fields[3], Inode: inode, State: "unknown"})
		if len(files) >= maxLibraries {
			break
		}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].Path == files[j].Path {
			return files[i].Inode < files[j].Inode
		}
		return files[i].Path < files[j].Path
	})
	return files
}
