//go:build linux

package hostcontext

import (
	"context"
	"net"
	"os"
	"strconv"
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
	owners := socketOwner{ctx: context.Background(), root: root, out: out, sockets: listeningSockets(root, out), owned: map[uint64]bool{}, budget: maxSocketFDs}
	want := model.Socket{Protocol: "tcp", Address: "127.0.0.1", Port: port, BindScope: "loopback"}
	found := false
	for _, socket := range owners.process("proc/" + strconv.Itoa(os.Getpid())) {
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
}
