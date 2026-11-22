//go:build linux

package hostcontext

import (
	"context"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestListeningSocketIsAttributedToOwningProcess(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback TCP unavailable:", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	out := &model.Context{}
	owners := socketOwner{ctx: context.Background(), root: root, out: out, sockets: listeningSockets(root, out, os.Getpid(), nil), owned: map[uint64]bool{}, budget: maxSocketFDs}
	want := model.Socket{Protocol: "tcp", Address: "127.0.0.1", Port: port, BindScope: "loopback"}
	found := false
	listening, _ := owners.process("proc/" + strconv.Itoa(os.Getpid()))
	for _, socket := range listening {
		found = found || socket == want
	}
	if !found {
		t.Fatalf("own listener %+v not attributed; issues %+v", want, out.Issues)
	}
	for _, socket := range owners.unattributed() {
		if socket == want {
			t.Fatal("attributed socket also listed as unattributed")
		}
	}
	exe, _ := os.Executable()
	byExecutable, _ := NamespaceSockets(context.Background(), []int{os.Getpid()})
	if got := byExecutable[strings.TrimPrefix(exe, "/")]; !slices.Contains(got, want) {
		t.Fatalf("NamespaceSockets %v lacks %+v for %s", byExecutable, want, exe)
	}
}
