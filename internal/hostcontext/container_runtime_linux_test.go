//go:build linux

package hostcontext

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestContainerProcessWithoutListenerIsRetained(t *testing.T) {
	procPath, diskPath := t.TempDir(), t.TempDir()
	id := strings.Repeat("a", 64)
	prefix := filepath.Join(procPath, "proc/42")
	if err := os.MkdirAll(prefix, 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"cgroup": "0::/docker/" + id + "\n", "maps": ""} {
		if err := os.WriteFile(filepath.Join(prefix, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"exe": "/usr/bin/job", "root": diskPath} {
		if err := os.Symlink(target, filepath.Join(prefix, name)); err != nil {
			t.Fatal(err)
		}
	}
	procRoot, err := os.OpenRoot(procPath)
	if err != nil {
		t.Fatal(err)
	}
	defer procRoot.Close()
	diskRoot, err := os.OpenRoot(diskPath)
	if err != nil {
		t.Fatal(err)
	}
	defer diskRoot.Close()
	out := &model.Context{}
	links := containerProcesses(context.Background(), procRoot, diskRoot, []int{42, 42}, id, out)
	if len(links) != 1 || links[0].Executable != "usr/bin/job" || !links[0].FilesystemComparable || len(links[0].ListeningSockets) != 0 || len(links[0].RuntimeFiles) != 1 {
		t.Fatalf("non-listening executable missing or duplicated: %+v; issues %+v", links, out.Issues)
	}
	if len(out.Issues) != 0 {
		t.Fatalf("unexpected issues %+v", out.Issues)
	}
	if got := containerProcesses(context.Background(), procRoot, diskRoot, []int{42}, strings.Repeat("b", 64), &model.Context{}); len(got) != 0 {
		t.Fatal("other container accepted")
	}
	other, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if got := containerProcesses(context.Background(), procRoot, other, []int{42}, id, &model.Context{}); len(got) != 0 {
		t.Fatal("different filesystem accepted")
	}
	if err := os.Remove(filepath.Join(prefix, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/job (deleted)", filepath.Join(prefix, "exe")); err != nil {
		t.Fatal(err)
	}
	links = containerProcesses(context.Background(), procRoot, diskRoot, []int{42}, id, &model.Context{})
	if len(links) != 1 || !links[0].ExecutableDeleted || links[0].RuntimeFiles[0].State != "restart_review" {
		t.Fatalf("deleted executable evidence lost %+v", links)
	}
}

func TestContainerProcessSocketsExcludeSiblingNamespaceOwners(t *testing.T) {
	procPath, diskPath := t.TempDir(), t.TempDir()
	id := strings.Repeat("c", 64)
	prefix := filepath.Join(procPath, "proc/71")
	for _, dir := range []string{"net", "fd", "ns"} {
		if err := os.MkdirAll(filepath.Join(prefix, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		"cgroup": "0::/docker/" + id + "\n", "maps": "",
		"net/tcp": "0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1001\n1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1002\n",
	} {
		if err := os.WriteFile(filepath.Join(prefix, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"exe": "/usr/bin/server", "root": diskPath, "ns/net": "net:[123]", "fd/3": "socket:[1001]"} {
		if err := os.Symlink(target, filepath.Join(prefix, name)); err != nil {
			t.Fatal(err)
		}
	}
	procRoot, err := os.OpenRoot(procPath)
	if err != nil {
		t.Fatal(err)
	}
	defer procRoot.Close()
	diskRoot, err := os.OpenRoot(diskPath)
	if err != nil {
		t.Fatal(err)
	}
	defer diskRoot.Close()
	out := &model.Context{}
	links := containerProcesses(context.Background(), procRoot, diskRoot, []int{71}, id, out)
	if len(links) != 1 || len(links[0].ListeningSockets) != 1 || links[0].ListeningSockets[0].Port != 443 {
		t.Fatalf("sibling-owned port leaked into process %+v; issues %+v", links, out.Issues)
	}
}
