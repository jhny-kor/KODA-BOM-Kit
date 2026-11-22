package hostcontext

import (
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestParseSocketTableKeepsOnlyListeningSockets(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tables := map[string]string{
		"tcp": header +
			"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0\n" +
			"   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0\n" +
			"   2: 0A00000A:01BB 0B00000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 20 4 30 10 -1\n" +
			"   3: 0A00000A:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0 100 0 0 10 0\n",
		"tcp6": header +
			"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0 100 0 0 10 0\n" +
			"   1: 00000000000000000000000001000000:0019 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0 100 0 0 10 0\n",
		"udp": header +
			"  10: 0A00000A:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0 0\n" +
			"  11: 0A00000A:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0 0\n",
	}
	got := map[uint64]model.Socket{}
	for _, protocol := range []string{"tcp", "tcp6", "udp"} {
		if !parseSocketTable(protocol, strings.NewReader(tables[protocol]), got, nil) {
			t.Fatal("unexpected socket limit")
		}
	}
	want := map[uint64]model.Socket{
		1001: {Protocol: "tcp", Address: "0.0.0.0", Port: 443, BindScope: "all-interfaces"},
		1002: {Protocol: "tcp", Address: "127.0.0.1", Port: 5432, BindScope: "loopback"},
		2001: {Protocol: "tcp6", Address: "::", Port: 22, BindScope: "all-interfaces"},
		2002: {Protocol: "tcp6", Address: "::1", Port: 25, BindScope: "loopback"},
		3001: {Protocol: "udp", Address: "10.0.0.10", Port: 53, BindScope: "address"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %+v", len(got), len(want), got)
	}
	for inode, socket := range want {
		if got[inode] != socket {
			t.Errorf("inode %d: got %+v, want %+v", inode, got[inode], socket)
		}
	}
}

func TestSocketInode(t *testing.T) {
	for target, want := range map[string]uint64{"socket:[12345]": 12345, "pipe:[1]": 0, "socket:[]": 0, "socket:[0]": 0, "/dev/null": 0} {
		if got, _ := socketInode(target); got != want {
			t.Errorf("%q: got %d, want %d", target, got, want)
		}
	}
}

func TestOutboundConnectionsExcludeAcceptedSockets(t *testing.T) {
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	table := header +
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0\n" +
		// accepted client on the listening port 443: inbound
		"   1: 0A00000A:01BB 0B00000A:D431 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 20 4 30 10 -1\n" +
		// two sockets from ephemeral ports to 10.0.0.20:5432 and one to 127.0.0.1:6379
		"   2: 0A00000A:9C40 1400000A:1538 01 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 20 4 30 10 -1\n" +
		"   3: 0A00000A:9C41 1400000A:1538 01 00000000:00000000 00:00000000 00000000     0        0 1005 1 0 20 4 30 10 -1\n" +
		"   4: 0100007F:9C42 0100007F:18EB 01 00000000:00000000 00:00000000 00000000     0        0 1006 1 0 20 4 30 10 -1\n" +
		// accepted on port 2049 whose listener has closed: peer uses ephemeral 40000
		"   5: 0A00000A:0801 0B00000A:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1007 1 0 20 4 30 10 -1\n"
	listening := map[uint64]model.Socket{}
	established := map[uint64]establishedSocket{}
	if !parseSocketTable("tcp", strings.NewReader(table), listening, established) {
		t.Fatal("unexpected limit")
	}
	conns := outbound(listening, established, ephemeralRange("32768\t60999\n"))
	if len(listening) != 1 || len(conns) != 3 || conns[1003].RemoteAddress != "" || conns[1007].RemoteAddress != "" {
		t.Fatalf("listening %+v outbound %+v", listening, conns)
	}
	got := aggregateConnections([]model.Connection{conns[1004], conns[1005], conns[1006]})
	want := []model.Connection{
		{Protocol: "tcp", RemoteAddress: "10.0.0.20", RemotePort: 5432, RemoteScope: "private", Count: 2},
		{Protocol: "tcp", RemoteAddress: "127.0.0.1", RemotePort: 6379, RemoteScope: "loopback", Count: 1},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("aggregate %+v", got)
	}
}
