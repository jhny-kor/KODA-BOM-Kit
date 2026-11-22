package deployment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkEvidenceRequiresMatchingIdentityAndUnambiguousSocket(t *testing.T) {
	const raw = `{"schema":"koda-network-observations-1","hostField":"assetTag","hostValue":"fixture","observations":[{"scope":"host","bindAddress":"0.0.0.0","targetAddress":"192.0.2.1","protocol":"tcp","port":443,"vantage":"branch-a","observedAt":"2026-11-20T01:02:03Z","result":"connected"}]}`
	path := filepath.Join(t.TempDir(), "network.json")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := LoadNetworkReports(context.Background(), []string{path, path})
	if err != nil || len(rows) != 1 {
		t.Fatalf("network reports %d: %v", len(rows), err)
	}
	probes := &Evidence{Network: rows}
	host := json.RawMessage(`{"bom-ref":"host","properties":[{"name":"koda:obom:host-identity","value":"{\"assetTag\":\"fixture\"}"}]}`)
	socket := json.RawMessage(`{"bom-ref":"socket","properties":[{"name":"koda:obom:observation","value":"listening-socket"},{"name":"koda:obom:scope","value":"host"},{"name":"koda:obom:protocol","value":"tcp"},{"name":"koda:obom:bind-address","value":"0.0.0.0"},{"name":"koda:obom:port","value":"443"}]}`)
	services := []json.RawMessage{socket}
	matched, unmatched, err := attachNetwork(rows, host, nil, services)
	if err != nil || matched != 1 || unmatched != 0 || !strings.Contains(string(services[0]), "reported-test") {
		t.Fatalf("connection observation %d/%d %v", matched, unmatched, err)
	}
	services = []json.RawMessage{socket, socket}
	matched, unmatched, err = attachNetwork(rows, host, nil, services)
	if err != nil || matched != 0 || unmatched != 1 || strings.Contains(string(services[0]), "reported-test") {
		t.Fatal("an ambiguous endpoint was attributed")
	}
	joined, err := Merge(probes, probes)
	if err != nil || len(joined.Network) != 1 {
		t.Fatal("duplicate observation during replay")
	}
	host = json.RawMessage(`{"bom-ref":"other"}`)
	if _, _, err = attachNetwork(rows, host, nil, services); err == nil {
		t.Fatal("different host accepted")
	}
	for _, bad := range []string{strings.Replace(raw, "0.0.0.0", "127.0.0.1", 1), strings.Replace(raw, "tcp", "udp", 1), strings.Replace(raw, "2026-11-20T01:02:03Z", "yesterday", 1), strings.Replace(raw, `"scope":"host"`, `"scope":"short-id"`, 1), raw + raw} {
		if err = os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadNetworkReports(context.Background(), []string{path}); err == nil {
			t.Fatal("invalid observation accepted")
		}
	}
}
