package hostcontext

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

func writeTree(t *testing.T, files map[string]string, modes map[string]os.FileMode) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for p, v := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		mode := modes[p]
		if mode == 0 {
			mode = 0644
		}
		if err := os.WriteFile(full, []byte(v), mode); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestScheduledJobs(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/crontab":                    "SHELL=/bin/sh\nMAILTO=root\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		"etc/cron.d/backup":              "*/15 2-4 * * 1-5 backup /opt/backup/bin/run --token=SECRET\n@reboot root /usr/local/bin/warmup\n",
		"etc/cron.d/backup.dpkg-old":     "* * * * * root /bin/old\n",
		"var/spool/cron/crontabs/deploy": "0 3 * * * /home/deploy/sync.sh secret-arg\n",
		"etc/cron.daily/logrotate":       "#!/bin/sh\n",
		"etc/cron.daily/.placeholder":    "",
		"etc/cron.daily/README":          "not executable",
	}, map[string]os.FileMode{"etc/cron.daily/logrotate": 0755})
	var out model.Context
	collectScheduledJobs(root, &out, nil)
	want := []model.ScheduledJob{
		{Source: "etc/crontab", Line: 4, Schedule: "17 * * * *", User: "root"},
		{Source: "etc/cron.d/backup", Line: 1, Schedule: "*/15 2-4 * * 1-5", User: "backup", Executable: "opt/backup/bin/run"},
		{Source: "etc/cron.d/backup", Line: 2, Schedule: "@reboot", User: "root", Executable: "usr/local/bin/warmup"},
		{Source: "var/spool/cron/crontabs/deploy", Line: 1, Schedule: "0 3 * * *", User: "deploy", Executable: "home/deploy/sync.sh"},
		{Source: "etc/cron.daily/logrotate", Schedule: "@daily", User: "root", Executable: "etc/cron.daily/logrotate"},
	}
	if !reflect.DeepEqual(out.ScheduledJobs, want) {
		t.Fatalf("got  %+v\nwant %+v", out.ScheduledJobs, want)
	}
	var listed model.Context
	collectScheduledJobs(root, &listed, map[string]bool{"etc/crontab": true})
	if len(listed.ScheduledJobs) != 1 {
		t.Fatalf("files outside the scan plan must not be read: %+v", listed.ScheduledJobs)
	}
}

func TestFirewallDeclarations(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/sysconfig/iptables": "*nat\n-A PREROUTING -p tcp --dport 80 -j ACCEPT\nCOMMIT\n*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n" +
			"-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
			"-A INPUT -s 10.0.0.0/8 -p tcp -m multiport --dports 5432,6000:6010 -j ACCEPT\n-A INPUT -p tcp --dport 23 -j DROP\nCOMMIT\n",
		"etc/firewalld/firewalld.conf":       "DefaultZone=internal\n",
		"etc/firewalld/zones/internal.xml":   `<?xml version="1.0"?><zone target="DROP"><service name="ssh"/><port protocol="udp" port="5353"/><rule family="ipv4"><source address="192.0.2.0/24"/><port protocol="tcp" port="9090"/><accept/></rule></zone>`,
		"usr/lib/firewalld/services/ssh.xml": `<?xml version="1.0"?><service><port protocol="tcp" port="22"/></service>`,
		"etc/sysconfig/nftables.conf":        "include \"/etc/nftables/main.nft\"\n",
		"etc/nftables/main.nft":              "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    tcp dport { 80, 443 } accept\n    ip saddr 10.0.0.0/8 tcp dport 8443 accept\n    udp dport 53 drop\n  }\n  chain forward { type filter hook forward priority 0; policy accept; tcp dport 25 accept; }\n}\n",
		"etc/ufw/user.rules":                 "*filter\n:ufw-user-input - [0:0]\n-A ufw-user-input -p tcp --dport 8080 -j ACCEPT\n-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept\n-A ufw-user-input -p tcp ! --dport 25 -j ACCEPT\nCOMMIT\n",
		"etc/ufw/ufw.conf":                   "ENABLED=no\n",
		"etc/default/ufw":                    "DEFAULT_INPUT_POLICY=\"DROP\"\n",
	}, nil)
	var out model.Context
	collectFirewall(context.Background(), root, &out, false, nil)
	want := []model.FirewallDeclaration{
		{Framework: "iptables", Path: "etc/sysconfig/iptables", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/22", "tcp/5432 restricted", "tcp/6000-6010 restricted"}},
		{Framework: "ufw", Path: "etc/ufw/user.rules", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/8080", "tcp/22"}, State: "disabled", UnresolvedRules: 1},
		{Framework: "firewalld", Path: "etc/firewalld/zones/internal.xml", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/22", "udp/5353", "tcp/9090 restricted"}},
		{Framework: "nftables", Path: "etc/sysconfig/nftables.conf", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/80", "tcp/443", "tcp/8443 restricted"}},
	}
	if !reflect.DeepEqual(out.Firewall, want) {
		t.Fatalf("got  %+v\nwant %+v", out.Firewall, want)
	}
}

func TestFirewallDefaultsAndIncludeLoop(t *testing.T) {
	loop := strings.Repeat("include \"/etc/nftables.conf\"\n", 2000)
	root := writeTree(t, map[string]string{
		// Debian's default: an input base chain without a policy accepts everything.
		"etc/nftables.conf":     loop + "table inet filter {\n  chain input {\n    type filter hook input priority filter;\n    iif lo accept\n  }\n}\n",
		"etc/iptables/rules.v4": "*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT\n-A INPUT -s 10.0.0.0/8 -j ACCEPT\nCOMMIT\n",
	}, nil)
	var out model.Context
	start := time.Now()
	collectFirewall(context.Background(), root, &out, false, nil)
	if time.Since(start) > 5*time.Second {
		t.Fatal("self-including nftables configuration was not bounded")
	}
	want := []model.FirewallDeclaration{
		{Framework: "iptables", Path: "etc/iptables/rules.v4", DefaultInputPolicy: "DROP", AllowedInbound: []string{"all restricted"}},
		{Framework: "nftables", Path: "etc/nftables.conf", DefaultInputPolicy: "ACCEPT"},
	}
	if !reflect.DeepEqual(out.Firewall, want) {
		t.Fatalf("got  %+v\nwant %+v", out.Firewall, want)
	}
}

func TestSystemCrontabRejectsMissingUserField(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/cron.d/dump": "*/5 * * * * PGPASSWORD=s3cr3t /usr/bin/pg_dump db\n"}, nil)
	var out model.Context
	collectScheduledJobs(root, &out, nil)
	if len(out.ScheduledJobs) != 0 {
		t.Fatalf("an invalid user field must not be recorded: %+v", out.ScheduledJobs)
	}
}

func TestFirewallProtocolWideAndStateRules(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/sysconfig/iptables": "*filter\n:INPUT DROP [0:0]\n-A INPUT -p icmp -j ACCEPT\n-A INPUT -p tcp -j ACCEPT\n-A INPUT -m conntrack --ctstate NEW -j ACCEPT\nCOMMIT\n",
		"etc/nftables.conf": "table inet a {\n  chain input { type filter hook input priority 0; policy drop; }\n}\ntable inet b {\n  chain input {\n    type filter hook input priority 10; policy accept;\n" +
			"    ct state { established, related } accept\n    ip protocol icmp accept\n    meta l4proto udp accept\n    ct state new accept\n  }\n}\n" +
			"table ip c { chain input { type filter hook input priority 20; policy accept; tcp dport 2222 accept; } }\n",
	}, nil)
	var out model.Context
	collectFirewall(context.Background(), root, &out, false, nil)
	want := []model.FirewallDeclaration{
		{Framework: "iptables", Path: "etc/sysconfig/iptables", DefaultInputPolicy: "DROP", AllowedInbound: []string{"tcp/all", "all"}},
		{Framework: "nftables", Path: "etc/nftables.conf", DefaultInputPolicy: "DROP", AllowedInbound: []string{"udp/all", "all", "tcp/2222"}},
	}
	if !reflect.DeepEqual(out.Firewall, want) {
		t.Fatalf("got  %+v\nwant %+v", out.Firewall, want)
	}
}

// Stock RHEL enables firewalld and ships nftables.conf with nftables.service
// disabled. A masked unit never loads; without a unit file the declaration stands.
func TestFirewallWhoseUnitIsNotEnabledIsInactive(t *testing.T) {
	root := writeTree(t, map[string]string{
		"etc/firewalld/firewalld.conf":             "DefaultZone=public\n",
		"usr/lib/firewalld/zones/public.xml":       `<?xml version="1.0"?><zone><service name="ssh"/></zone>`,
		"usr/lib/firewalld/services/ssh.xml":       `<?xml version="1.0"?><service><port protocol="tcp" port="22"/></service>`,
		"etc/sysconfig/nftables.conf":              "#include \"/etc/nftables/main.nft\"\n",
		"etc/sysconfig/iptables":                   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		"etc/iptables/rules.v4":                    "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		"usr/lib/systemd/system/firewalld.service": "[Service]\nExecStart=/usr/sbin/firewalld --nofork\n",
		"usr/lib/systemd/system/nftables.service":  "[Service]\nType=oneshot\n",
		"usr/lib/systemd/system/iptables.service":  "[Service]\nType=oneshot\n",
	}, nil)
	for link, target := range map[string]string{
		"etc/systemd/system/multi-user.target.wants/firewalld.service": "/usr/lib/systemd/system/firewalld.service",
		"etc/systemd/system/iptables.service":                          "/dev/null",
	} {
		full := filepath.Join(root.Name(), link)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	var out model.Context
	collectServices(root, &out, false, nil)
	collectFirewall(context.Background(), root, &out, false, nil)
	states := map[string]string{}
	for _, d := range out.Firewall {
		states[d.Path] = d.State
	}
	want := map[string]string{
		"usr/lib/firewalld/zones/public.xml": "",
		"etc/sysconfig/nftables.conf":        "not-enabled",
		"etc/sysconfig/iptables":             "not-enabled",
		"etc/iptables/rules.v4":              "",
	}
	if !reflect.DeepEqual(states, want) {
		t.Fatalf("got %v want %v", states, want)
	}
	// On a live host a unit with running processes counts as loaded even when not enabled.
	running := filepath.Join(root.Name(), "sys/fs/cgroup/system.slice/nftables.service/cgroup.procs")
	if err := os.MkdirAll(filepath.Dir(running), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(running, []byte("4242\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var live model.Context
	collectServices(root, &live, true, nil)
	collectFirewall(context.Background(), root, &live, true, nil)
	for _, d := range live.Firewall {
		if d.Path == "etc/sysconfig/nftables.conf" && d.State != "" {
			t.Fatalf("a running unit is active: %+v", d)
		}
	}
	// Past the enabled-unit limit enablement is unknown, so nothing is marked.
	full := model.Context{EnabledServices: make([]model.Service, maxServices)}
	collectFirewall(context.Background(), root, &full, false, nil)
	for _, d := range full.Firewall {
		if d.State != "" {
			t.Fatalf("enablement unknown past the limit: %+v", d)
		}
	}
}
