package containers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverNamesContainersAndMapsRootFS(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		t.Helper()
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ns := func(pid, target string) {
		t.Helper()
		dir := filepath.Join(root, "proc", pid, "ns")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "mnt")); err != nil {
			t.Fatal(err)
		}
	}
	docker := strings.Repeat("a", 64)
	sandbox := strings.Repeat("b", 64)
	workload := strings.Repeat("c", 64)
	hidden := strings.Repeat("d", 64)
	ns("100", "mnt:[1]")
	put("proc/100/mountinfo", "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"+
		"90 22 0:55 / /var/lib/docker/overlay2/x1/merged rw - overlay overlay rw\n"+
		"91 22 0:66 / /run/containerd/io.containerd.runtime.v2.task/k8s.io/"+workload+"/rootfs rw - overlay overlay rw\n")
	// Docker container: two processes, one entry.
	for _, pid := range []string{"200", "201"} {
		ns(pid, "mnt:[2]")
		put("proc/"+pid+"/cgroup", "0::/system.slice/docker-"+docker+".scope\n")
		put("proc/"+pid+"/mountinfo", "500 400 0:55 / / rw - overlay overlay rw\n")
	}
	put("var/lib/docker/containers/"+docker+"/config.v2.json", `{"Name":"/web","Image":"sha256:1234","Config":{"Image":"nginx:1.27"}}`)
	// systemd service with a private mount namespace: not a container.
	ns("300", "mnt:[3]")
	put("proc/300/cgroup", "0::/system.slice/chronyd.service\n")
	put("proc/300/mountinfo", "600 1 8:1 / / rw - ext4 /dev/sda1 rw\n")
	// Kubernetes pod: sandbox skipped, workload named namespace_pod_container.
	ns("400", "mnt:[4]")
	put("proc/400/cgroup", "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-"+sandbox+".scope\n")
	put("run/containerd/io.containerd.runtime.v2.task/k8s.io/"+sandbox+"/config.json", `{"annotations":{"io.kubernetes.cri.container-type":"sandbox"}}`)
	ns("500", "mnt:[5]")
	put("proc/500/cgroup", "0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-"+workload+".scope\n")
	put("proc/500/mountinfo", "700 600 0:66 / / rw - overlay overlay rw\n")
	put("run/containerd/io.containerd.runtime.v2.task/k8s.io/"+workload+"/config.json", `{"annotations":{"io.kubernetes.cri.container-type":"container","io.kubernetes.cri.container-name":"api","io.kubernetes.cri.sandbox-name":"api-7d9f","io.kubernetes.cri.sandbox-namespace":"prod","io.kubernetes.cri.image-name":"registry.local/api:2.1"}}`)
	// Container whose root filesystem is not mounted in the host namespace.
	ns("600", "mnt:[6]")
	put("proc/600/cgroup", "0::/docker/"+hidden+"\n")
	put("proc/600/mountinfo", "800 700 0:77 / / rw - overlay overlay rw\n")

	found, issues := Discover(context.Background(), root, 100)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues %+v", issues)
	}
	byID := map[string]Container{}
	for _, c := range found {
		byID[c.ID] = c
	}
	if len(found) != 3 {
		t.Fatalf("want docker, k8s workload and hidden container, got %+v", found)
	}
	if c := byID[docker]; c.Name != "web" || c.Runtime != "docker" || c.Image != "nginx:1.27" || c.RootFS != "/var/lib/docker/overlay2/x1/merged" || c.FileName() != "web" {
		t.Errorf("docker container %+v", c)
	}
	if c := byID[workload]; c.FileName() != "prod_api-7d9f_api" || c.Image != "registry.local/api:2.1" || !strings.HasSuffix(c.RootFS, workload+"/rootfs") {
		t.Errorf("kubernetes container %+v (%s)", c, c.FileName())
	}
	if c := byID[hidden]; c.RootFS != "" || c.Name != hidden[:12] {
		t.Errorf("hidden container %+v", c)
	}
}

func TestHostPathHandlesSubdirectoryBinds(t *testing.T) {
	host := []mount{{dev: "253:1", root: "/", point: "/"}, {dev: "253:2", root: "/", point: "/data"}}
	container := []mount{{dev: "253:2", root: "/containers/c1/rootfs", point: "/"}}
	if got := hostPath(container, host); got != "/data/containers/c1/rootfs" {
		t.Fatalf("got %q", got)
	}
}

func TestFileNameIsSafe(t *testing.T) {
	c := Container{ID: strings.Repeat("e", 64), Name: "../../etc/passwd x"}
	if got := c.FileName(); strings.Contains(got, "/") || strings.HasPrefix(got, ".") {
		t.Fatalf("unsafe file name %q", got)
	}
}
