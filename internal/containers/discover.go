// Package containers finds running containers from procfs and runtime state
// files and locates each container's root filesystem in the host mount
// namespace. It never contacts a runtime socket or API.
package containers

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const maxProcesses = 65536

// Container is one running container. RootFS is the host path of its root
// filesystem in the collector's mount namespace; empty when not visible there.
type Container struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Runtime      string `json:"runtime,omitempty"`
	Image        string `json:"image,omitempty"`
	ImageID      string `json:"imageId,omitempty"`
	Pod          string `json:"pod,omitempty"`
	PodNamespace string `json:"podNamespace,omitempty"`
	PID          int    `json:"pid,omitempty"`
	// State is running, stopped, or image for an image no container uses.
	State string `json:"state,omitempty"`
	// PIDs are all processes of the container, PID first.
	PIDs    []int  `json:"-"`
	RootFS  string `json:"-"`
	sandbox bool
}

var containerID = regexp.MustCompile(`[0-9a-f]{64}`)

type mount struct{ dev, root, point string }

func unescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

func parseMountinfo(data string) []mount {
	var out []mount
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		out = append(out, mount{dev: fields[2], root: unescape(fields[3]), point: unescape(fields[4])})
	}
	return out
}

// hostPath maps the container's "/" mount to the host mount of the same
// filesystem. A bind of a subdirectory is handled through the mount root field.
func hostPath(container, host []mount) string {
	var top *mount
	for i := range container {
		if container[i].point == "/" {
			top = &container[i] // the last mount on "/" is the visible one
		}
	}
	if top == nil {
		return ""
	}
	best, bestRoot := "", -1
	for _, m := range host {
		if m.dev != top.dev {
			continue
		}
		rel, ok := strings.CutPrefix(top.root, strings.TrimSuffix(m.root, "/"))
		if !ok || (rel != "" && !strings.HasPrefix(rel, "/")) || len(m.root) <= bestRoot {
			continue
		}
		best, bestRoot = path.Join(m.point, rel), len(m.root)
	}
	return best
}

func read(p string, limit int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil
	}
	return data
}

// SelfID returns the ID of the container the collector itself runs in, if any.
func SelfID(root string, self int) string {
	ids := containerID.FindAllString(string(read(filepath.Join(root, "proc", strconv.Itoa(self), "cgroup"), 1<<20)), -1)
	if len(ids) == 0 {
		return ""
	}
	return ids[len(ids)-1]
}

// Discover lists running containers below root ("/" on a live host). self is
// the collector's PID; processes sharing its mount namespace are not containers.
func Discover(ctx context.Context, root string, self int) ([]Container, []model.Issue) {
	var issues []model.Issue
	issue := func(status, p, message string) {
		if len(issues) < 200 {
			issues = append(issues, model.Issue{Collector: "containers", Status: status, Path: p, Message: message})
		}
	}
	proc := filepath.Join(root, "proc")
	selfNS, err := os.Readlink(filepath.Join(proc, strconv.Itoa(self), "ns/mnt"))
	if err != nil {
		issue("incomplete", "proc/self/ns/mnt", "collector mount namespace unreadable; containers not discovered")
		return nil, issues
	}
	hostMounts := parseMountinfo(string(read(filepath.Join(proc, strconv.Itoa(self), "mountinfo"), 16<<20)))
	entries, err := os.ReadDir(proc)
	if err != nil {
		issue("incomplete", "proc", "process list unreadable; containers not discovered")
		return nil, issues
	}
	if len(entries) > maxProcesses {
		entries = entries[:maxProcesses]
		issue("incomplete", "proc", "process limit reached during container discovery")
	}
	seen := map[string]int{} // container ID -> index in found, or -1 for a skipped sandbox
	var found []Container
	denied := false
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		dir := filepath.Join(proc, entry.Name())
		ns, err := os.Readlink(filepath.Join(dir, "ns/mnt"))
		if err != nil {
			denied = denied || os.IsPermission(err)
			continue
		}
		if ns == selfNS {
			continue
		}
		// A private mount namespace alone (systemd PrivateTmp) is not a container.
		ids := containerID.FindAllString(string(read(filepath.Join(dir, "cgroup"), 1<<20)), -1)
		if len(ids) == 0 {
			continue
		}
		id := ids[len(ids)-1]
		if i, ok := seen[id]; ok {
			if i >= 0 {
				found[i].PIDs = append(found[i].PIDs, pid)
			}
			continue
		}
		c := Container{ID: id, PID: pid, PIDs: []int{pid}, State: "running"}
		// The mapped path is in the collector's own mount namespace.
		if p := hostPath(parseMountinfo(string(read(filepath.Join(dir, "mountinfo"), 16<<20))), hostMounts); p != "" && p != "/" {
			c.RootFS = p
		}
		describe(root, &c)
		if c.sandbox {
			seen[id] = -1
			continue // Kubernetes pod sandbox ("pause"), not a workload
		}
		seen[id] = len(found)
		found = append(found, c)
	}
	if denied {
		issue("permission_denied", "proc", "some process namespaces unreadable; run as root to discover all containers")
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Name+found[i].ID < found[j].Name+found[j].ID })
	return found, issues
}

func readJSON(p string, v any) bool {
	data := read(p, 16<<20)
	return data != nil && json.Unmarshal(data, v) == nil
}

// describe fills names from runtime state files: Docker, containerd (including
// Kubernetes and nerdctl) and containers/storage (Podman, CRI-O).
func describe(root string, c *Container) {
	defer func() {
		if c.Name == "" {
			c.Name = c.ID[:12]
		}
	}()
	dockerRoot := "/var/lib/docker"
	var daemon struct {
		DataRoot string `json:"data-root"`
	}
	if readJSON(filepath.Join(root, "etc/docker/daemon.json"), &daemon) && filepath.IsAbs(daemon.DataRoot) {
		dockerRoot = daemon.DataRoot
	}
	var docker struct {
		Name   string
		Image  string
		Config struct{ Image string }
	}
	if readJSON(filepath.Join(root, dockerRoot, "containers", c.ID, "config.v2.json"), &docker) {
		c.Runtime, c.Name, c.Image, c.ImageID = "docker", strings.TrimPrefix(docker.Name, "/"), docker.Config.Image, docker.Image
		return
	}
	var spec struct {
		Annotations map[string]string `json:"annotations"`
	}
	bundles, _ := filepath.Glob(filepath.Join(root, "run/containerd/io.containerd.runtime.v2.task/*", c.ID, "config.json"))
	if len(bundles) > 0 && readJSON(bundles[0], &spec) {
		a := spec.Annotations
		c.Runtime = "containerd"
		c.sandbox = a["io.kubernetes.cri.container-type"] == "sandbox"
		c.Name, c.Image = a["io.kubernetes.cri.container-name"], a["io.kubernetes.cri.image-name"]
		c.Pod, c.PodNamespace = a["io.kubernetes.cri.sandbox-name"], a["io.kubernetes.cri.sandbox-namespace"]
		if c.Name == "" {
			c.Name = a["nerdctl/name"]
		}
		return
	}
	storage := filepath.Join(root, "var/lib/containers/storage/overlay-containers")
	if readJSON(filepath.Join(storage, c.ID, "userdata/config.json"), &spec) {
		a := spec.Annotations
		c.Runtime = "containers-storage"
		c.sandbox = a["io.kubernetes.cri-o.ContainerType"] == "sandbox"
		c.Name, c.Image = a["io.kubernetes.container.name"], a["io.kubernetes.cri-o.ImageName"]
		c.Pod, c.PodNamespace = a["io.kubernetes.pod.name"], a["io.kubernetes.pod.namespace"]
		if c.Name != "" {
			return
		}
	}
	var list []struct {
		ID    string   `json:"id"`
		Names []string `json:"names"`
		Image string   `json:"image"`
	}
	if readJSON(filepath.Join(storage, "containers.json"), &list) {
		for _, item := range list {
			if item.ID == c.ID && len(item.Names) > 0 {
				c.Runtime, c.Name, c.ImageID = "podman", item.Names[0], item.Image
				return
			}
		}
	}
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// FileName returns a directory name for the container's results. Kubernetes
// containers include namespace and pod because container names repeat.
func (c Container) FileName() string {
	name := c.Name
	if c.Pod != "" {
		name = c.PodNamespace + "_" + c.Pod + "_" + c.Name
	}
	name = strings.Trim(unsafeName.ReplaceAllString(name, "_"), "._")
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		name = c.ID[:12]
	}
	return name
}
