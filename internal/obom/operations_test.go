package obom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestOutboundJobsTimersAndFirewall(t *testing.T) {
	dir := t.TempDir()
	fixtureJSON(t, dir, "collection.json", collection{Schema: "koda-sbom-collection-v1", Status: "completed", StartedAt: "2026-11-22T01:00:00Z", Host: &model.HostIdentity{MachineIDSHA256: "host"}})
	db := model.Connection{Protocol: "tcp", RemoteAddress: "10.0.0.20", RemotePort: 5432, RemoteScope: "private", Count: 2}
	ctx := model.Context{Mode: "live-host", Status: "completed",
		ProcessLinks: []model.ProcessLink{
			{PID: 10, Executable: "usr/bin/app", ListeningSockets: []model.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, BindScope: "all-interfaces"}, {Protocol: "tcp", Address: "0.0.0.0", Port: 9000, BindScope: "all-interfaces"}, {Protocol: "tcp", Address: "127.0.0.1", Port: 6060, BindScope: "loopback"}}, OutboundConnections: []model.Connection{db}},
			{PID: 11, Executable: "usr/bin/worker", OutboundConnections: []model.Connection{db}},
		},
		EnabledServices: []model.Service{{Unit: "backup.timer", WantedBy: []string{"timers.target"}, Activates: "backup.service", Schedule: []string{"OnCalendar=daily"}, State: "stopped"}},
		ScheduledJobs:   []model.ScheduledJob{{Source: "etc/cron.d/report", Line: 3, Schedule: "0 1 * * *", User: "app", Executable: "opt/app/report"}},
		Firewall:        []model.FirewallDeclaration{{Framework: "nftables", Path: "etc/nftables.conf", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/8000-8100"}}},
	}
	fixtureJSON(t, dir, "context.json", ctx)
	fixtureChecksums(t, dir, "collection.json", "context.json")
	out := t.TempDir()
	if err := Write(context.Background(), dir, out, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "obom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components   []component  `json:"components"`
		Services     []service    `json:"services"`
		Dependencies []dependency `json:"dependencies"`
	}
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	props := func(p []property) map[string]string {
		m := map[string]string{}
		for _, x := range p {
			m[x.Name[len("koda:obom:"):]] = x.Value
		}
		return m
	}
	byName := map[string]map[string]string{}
	refs := map[string]string{}
	for _, s := range doc.Services {
		byName[s.Name] = props(s.Properties)
		refs[s.Name] = s.Ref
	}
	for _, c := range doc.Components {
		refs[c.Name] = c.Ref
	}
	remote := byName["tcp 10.0.0.20:5432"]
	if remote["observation"] != "outbound-connection" || remote["remote-scope"] != "private" {
		t.Fatalf("remote %+v", byName)
	}
	dependents := 0
	for _, d := range doc.Dependencies {
		for _, target := range d.DependsOn {
			if target == refs["tcp 10.0.0.20:5432"] && (d.Ref == refs["process 10"] || d.Ref == refs["process 11"]) {
				dependents++
			}
		}
	}
	if dependents != 2 {
		t.Fatalf("both processes should depend on one remote service, got %d", dependents)
	}
	if byName["tcp 0.0.0.0:8080"]["firewall-declared"] != "accept-declared" || byName["tcp 0.0.0.0:9000"]["firewall-declared"] != "no-accept-declared" || byName["tcp 127.0.0.1:6060"]["firewall-declared"] != "" {
		t.Fatalf("firewall annotations %+v", byName)
	}
	if byName["cron etc/cron.d/report:3"]["executable"] != "opt/app/report" || byName["backup.timer"]["declared-schedule"] != "OnCalendar=daily" {
		t.Fatalf("schedules %+v", byName)
	}
}

func TestFirewallAcceptsOrdering(t *testing.T) {
	tests := []struct {
		d    []model.FirewallDeclaration
		want string
	}{
		{[]model.FirewallDeclaration{{DefaultInputPolicy: "ACCEPT", AllowedInbound: []string{"tcp/5432 restricted"}}}, "policy-accept-declared"},
		{[]model.FirewallDeclaration{{DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/all"}}}, "accept-declared"},
		{[]model.FirewallDeclaration{{DefaultInputPolicy: "DROP", AllowedInbound: []string{"udp/all"}}}, "no-accept-declared"},
		{[]model.FirewallDeclaration{{DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/5432 restricted"}}}, "accept-declared-restricted"},
		{[]model.FirewallDeclaration{{DefaultInputPolicy: "DROP", UnresolvedRules: 1}}, "undetermined"},
		{[]model.FirewallDeclaration{{State: "disabled", DefaultInputPolicy: "DROP"}}, "none-observed"},
		{nil, "none-observed"},
	}
	for _, tt := range tests {
		if got := firewallAccepts(tt.d, "tcp6", 5432); got != tt.want {
			t.Fatalf("%+v: got %q want %q", tt.d, got, tt.want)
		}
	}
}

func TestLocalConnectionLinksToListener(t *testing.T) {
	g := newGraph()
	host := "host"
	g.processes(host, []model.ProcessLink{
		{PID: 30, Executable: "usr/bin/redis-server", ListeningSockets: []model.Socket{{Protocol: "tcp", Address: "127.0.0.1", Port: 6379, BindScope: "loopback"}}},
		{PID: 31, Executable: "usr/bin/postgres", ListeningSockets: []model.Socket{{Protocol: "tcp6", Address: "::", Port: 5432, BindScope: "all-interfaces"}}},
		{PID: 10, Executable: "usr/bin/app", OutboundConnections: []model.Connection{
			{Protocol: "tcp", RemoteAddress: "127.0.0.1", RemotePort: 6379, RemoteScope: "loopback", Count: 1},
			{Protocol: "tcp", RemoteAddress: "127.0.0.1", RemotePort: 5432, RemoteScope: "loopback", Count: 1},
			{Protocol: "tcp", RemoteAddress: "10.0.0.9", RemotePort: 5432, RemoteScope: "private", Count: 1},
		}},
	})
	g.resolveRemotes()
	app := reference(host, "process", "10", "usr/bin/app")
	var outbound []string
	for _, s := range g.services {
		for _, p := range s.Properties {
			if p.Value == "outbound-connection" {
				outbound = append(outbound, s.Name)
			}
		}
	}
	if len(outbound) != 1 || outbound[0] != "tcp 10.0.0.9:5432" {
		t.Fatalf("only the off-host endpoint is a remote service: %v", outbound)
	}
	targets := map[string]bool{}
	for target := range g.edges[app] {
		targets[g.services[target].Name] = true
	}
	if !targets["tcp 127.0.0.1:6379"] || !targets["tcp6 [::]:5432"] || !targets["tcp 10.0.0.9:5432"] || len(targets) != 3 {
		t.Fatalf("app should depend on both local listeners and the remote endpoint: %v", targets)
	}
}

func TestHostAddressAndSelfConnections(t *testing.T) {
	g := newGraph()
	host := "host"
	g.processes(host, []model.ProcessLink{
		{PID: 31, Executable: "usr/bin/postgres", ListeningSockets: []model.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 5432, BindScope: "all-interfaces"}}},
		{PID: 40, Executable: "usr/bin/prometheus", ListeningSockets: []model.Socket{{Protocol: "tcp6", Address: "::", Port: 9090, BindScope: "all-interfaces"}},
			OutboundConnections: []model.Connection{{Protocol: "tcp", RemoteAddress: "127.0.0.1", RemotePort: 9090, RemoteScope: "loopback", Count: 1}}},
		{PID: 10, Executable: "usr/bin/app", OutboundConnections: []model.Connection{{Protocol: "tcp", RemoteAddress: "10.0.0.5", RemotePort: 5432, RemoteScope: "local-host", Count: 1}}},
	})
	g.resolveRemotes()
	prometheus := reference(host, "process", "40", "usr/bin/prometheus")
	for target := range g.edges[prometheus] {
		if s, ok := g.services[target]; ok && g.edges[target][prometheus] {
			t.Fatalf("a process reaching its own listener must not form a cycle via %s", s.Name)
		}
	}
	app := reference(host, "process", "10", "usr/bin/app")
	for target := range g.edges[app] {
		if g.services[target].Name != "tcp 0.0.0.0:5432" {
			t.Fatalf("a connection to this host's own address should reach its listener, got %s", g.services[target].Name)
		}
	}
	for _, s := range g.services {
		for _, p := range s.Properties {
			if p.Value == "outbound-connection" {
				t.Fatalf("no remote service expected: %s", s.Name)
			}
		}
	}
}

func TestContainerSocketsAreNotJudgedByHostFirewall(t *testing.T) {
	g := newGraph()
	g.firewall, g.firewallScope = []model.FirewallDeclaration{{DefaultInputPolicy: "ACCEPT"}}, "host"
	g.processes("host", []model.ProcessLink{{PID: 1, Executable: "usr/sbin/sshd", ListeningSockets: []model.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 22, BindScope: "all-interfaces"}}}})
	// A container's sockets live in its own network namespace; host INPUT rules do not govern them.
	g.processes("container", []model.ProcessLink{{PID: 2, Executable: "usr/sbin/nginx", ListeningSockets: []model.Socket{{Protocol: "tcp", Address: "0.0.0.0", Port: 80, BindScope: "all-interfaces"}}}})
	declared := map[string]string{}
	for _, s := range g.services {
		for _, p := range s.Properties {
			if p.Name == "koda:obom:firewall-declared" {
				declared[s.Name] = p.Value
			}
		}
	}
	if len(declared) != 1 || declared["tcp 0.0.0.0:22"] != "policy-accept-declared" {
		t.Fatalf("only the host socket should carry a firewall verdict: %v", declared)
	}
	// Without an active declaration the host listener says so; loopback stays unannotated.
	g = newGraph()
	g.firewallScope = "host"
	g.processes("host", []model.ProcessLink{{PID: 1, Executable: "usr/sbin/sshd", ListeningSockets: []model.Socket{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22, BindScope: "all-interfaces"}, {Protocol: "tcp", Address: "127.0.0.1", Port: 631, BindScope: "loopback"}}}})
	declared = map[string]string{}
	for _, s := range g.services {
		for _, p := range s.Properties {
			if p.Name == "koda:obom:firewall-declared" {
				declared[s.Name] = p.Value
			}
		}
	}
	if len(declared) != 1 || declared["tcp 0.0.0.0:22"] != "none-observed" {
		t.Fatalf("unfirewalled host listener: %v", declared)
	}
}
