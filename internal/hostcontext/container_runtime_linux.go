//go:build linux

package hostcontext

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"koda.local/security-sbom-linux/internal/model"
)

// ContainerProcesses observes only the supplied container's current processes.
// Root identity and cgroup membership are rechecked after reading each process
// so recycled PIDs cannot link another container's files to this inventory.
func ContainerProcesses(ctx context.Context, pids []int, rootfs, containerID string) ([]model.ProcessLink, []model.Issue) {
	out := &model.Context{}
	if len(pids) == 0 {
		return nil, nil
	}
	procRoot, err := os.OpenRoot("/")
	if err != nil {
		issue(out, statusFor(err), "proc", "container process root unavailable")
		return nil, out.Issues
	}
	defer procRoot.Close()
	diskRoot, err := os.OpenRoot(rootfs)
	if err != nil {
		issue(out, statusFor(err), "", "container filesystem unavailable for runtime comparison")
		return nil, out.Issues
	}
	defer diskRoot.Close()
	return containerProcesses(ctx, procRoot, diskRoot, pids, containerID, out), out.Issues
}

func containerProcesses(ctx context.Context, procRoot, diskRoot *os.Root, pids []int, containerID string, out *model.Context) []model.ProcessLink {
	var links []model.ProcessLink
	seen := map[int]bool{}
	socketTables := map[string]map[uint64]model.Socket{}
	remainingFDs := maxSocketFDs
	for _, pid := range pids {
		if ctx.Err() != nil {
			issue(out, "incomplete", "proc", "container process observation interrupted")
			break
		}
		if len(seen) >= maxProcesses {
			issue(out, "incomplete", "proc", "container process count limit reached")
			break
		}
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		prefix := "proc/" + strconv.Itoa(pid)
		if !containerProcessMatches(procRoot, diskRoot, prefix, containerID) {
			issue(out, "incomplete", prefix, "container process membership or filesystem identity unavailable")
			continue
		}
		exe, err := procRoot.Readlink(prefix + "/exe")
		if err != nil {
			if !os.IsNotExist(err) {
				issue(out, statusFor(err), prefix+"/exe", "container executable unavailable")
			}
			continue
		}
		link := model.ProcessLink{PID: pid, Executable: safeRuntimePath(exe), ExecutableDeleted: strings.HasSuffix(exe, " (deleted)"), FilesystemComparable: true}
		if link.Executable == "" {
			continue
		}
		if data, err := readBounded(procRoot, prefix+"/maps"); err == nil {
			link.Libraries = parseMaps(string(data), nil)
			link.RuntimeFiles = runtimeFiles(diskRoot, string(data), nil, true)
			if len(link.RuntimeFiles) >= maxLibraries {
				issue(out, "incomplete", prefix+"/maps", "container runtime file limit reached")
			}
		} else if !os.IsNotExist(err) {
			issue(out, statusFor(err), prefix+"/maps", "container process mappings unavailable")
		}
		if !slices.ContainsFunc(link.RuntimeFiles, func(f model.RuntimeFile) bool { return f.Path == link.Executable }) {
			state := "unknown"
			if link.ExecutableDeleted {
				state = "restart_review"
			}
			link.RuntimeFiles = append(link.RuntimeFiles, model.RuntimeFile{Path: link.Executable, Deleted: link.ExecutableDeleted, State: state})
		}
		// A process may have entered another network namespace since discovery.
		// Reading its own table and descriptors keeps socket attribution local.
		networkNamespace, _ := procRoot.Readlink(prefix + "/ns/net")
		namespaceKey := networkNamespace
		if namespaceKey == "" {
			namespaceKey = prefix
		}
		sockets, cached := socketTables[namespaceKey]
		if !cached {
			sockets = listeningSockets(procRoot, out, pid, nil)
			socketTables[namespaceKey] = sockets
		}
		owners := socketOwner{ctx: ctx, root: procRoot, out: out, sockets: sockets, owned: map[uint64]bool{}, budget: remainingFDs}
		link.ListeningSockets, _ = owners.process(prefix)
		remainingFDs = owners.budget
		networkAfter, _ := procRoot.Readlink(prefix + "/ns/net")
		if networkAfter != networkNamespace {
			link.ListeningSockets = nil
			issue(out, "incomplete", prefix+"/ns/net", "process network namespace changed during observation")
		}
		after, err := procRoot.Readlink(prefix + "/exe")
		if err != nil || after != exe || !containerProcessMatches(procRoot, diskRoot, prefix, containerID) {
			issue(out, "incomplete", prefix, "container process changed during observation")
			continue
		}
		links = append(links, link)
	}
	return links
}

func containerProcessMatches(procRoot, diskRoot *os.Root, prefix, containerID string) bool {
	if containerID == "" {
		return false
	}
	data, err := readBounded(procRoot, prefix+"/cgroup")
	if err != nil || !strings.Contains(string(data), containerID) {
		return false
	}
	proc, err := procRoot.Open(prefix)
	if err != nil {
		return false
	}
	defer proc.Close()
	var current unix.Stat_t
	if unix.Fstatat(int(proc.Fd()), "root", &current, 0) != nil {
		return false
	}
	disk, err := diskRoot.Stat(".")
	if err != nil {
		return false
	}
	stat, ok := disk.Sys().(*syscall.Stat_t)
	return ok && uint64(current.Dev) == uint64(stat.Dev) && current.Ino == stat.Ino
}
