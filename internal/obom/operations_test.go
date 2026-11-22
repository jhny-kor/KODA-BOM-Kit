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
		{[]model.FirewallDeclaration{{State: "disabled", DefaultInputPolicy: "DROP"}}, ""},
	}
	for _, tt := range tests {
		if got := firewallAccepts(tt.d, "tcp6", 5432); got != tt.want {
			t.Fatalf("%+v: got %q want %q", tt.d, got, tt.want)
		}
	}
}
