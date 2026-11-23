package hostcontext

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

// Firewall configuration is read as a declaration. The loaded kernel ruleset
// would need netlink access; rule order, interfaces and sources are summarized
// only as a "restricted" marker on an allowed port.
var iptablesFiles = map[string]string{
	"etc/sysconfig/iptables": "iptables", "etc/sysconfig/ip6tables": "iptables",
	"etc/iptables/rules.v4": "iptables", "etc/iptables/rules.v6": "iptables",
	"etc/ufw/user.rules": "ufw", "etc/ufw/user6.rules": "ufw",
}

// firewallUnits names the systemd unit that loads an iptables file at boot;
// firewalld, nftables and ufw load through a unit named after the framework.
var firewallUnits = map[string]string{
	"etc/sysconfig/iptables": "iptables.service", "etc/sysconfig/ip6tables": "ip6tables.service",
	"etc/iptables/rules.v4": "netfilter-persistent.service", "etc/iptables/rules.v6": "netfilter-persistent.service",
}

func firewallUnit(d model.FirewallDeclaration) string {
	if unit, ok := firewallUnits[d.Path]; ok {
		return unit
	}
	return d.Framework + ".service"
}

// collectFirewall reads after collectServices, whose enabled units decide
// whether each declaration is loaded at boot.
func collectFirewall(ctx context.Context, root *os.Root, out *model.Context, live bool, allowed map[string]bool) {
	read := func(p string) []byte {
		if allowed != nil && !allowed[p] {
			return nil
		}
		data, err := readBounded(root, p)
		if err != nil && os.IsPermission(err) {
			issue(out, "permission_denied", p, "firewall configuration unreadable")
		}
		return data
	}
	files := make([]string, 0, len(iptablesFiles))
	for p := range iptablesFiles {
		files = append(files, p)
	}
	slices.Sort(files)
	for _, p := range files {
		if data := read(p); data != nil {
			d := parseIptablesSave(data)
			d.Framework, d.Path = iptablesFiles[p], p
			if d.Framework == "ufw" {
				d.DefaultInputPolicy = ufwPolicy(read("etc/default/ufw"))
				if !ufwEnabled(read("etc/ufw/ufw.conf")) {
					d.State = "disabled"
				}
			}
			out.Firewall = append(out.Firewall, d)
		}
	}
	if conf := read("etc/firewalld/firewalld.conf"); conf != nil {
		out.Firewall = append(out.Firewall, firewalldZone(conf, read))
	}
	for _, p := range []string{"etc/nftables.conf", "etc/sysconfig/nftables.conf"} {
		if data := read(p); data != nil {
			d := model.FirewallDeclaration{Framework: "nftables", Path: p}
			parseNftables(ctx, data, read, &d, 0, map[string]bool{p: true})
			out.Firewall = append(out.Firewall, d)
		}
	}
	// A framework whose unit is installed but neither enabled nor running, or
	// is masked, does not load its rules (RHEL ships nftables.conf with the
	// unit disabled next to firewalld). Without the unit file, the declaration
	// stands, as it does when the enabled-unit limit left enablement unknown.
	if len(out.EnabledServices) >= maxServices {
		return
	}
	enabled := map[string]bool{}
	for _, s := range out.EnabledServices {
		enabled[s.Unit] = true
	}
	for i := range out.Firewall {
		d := &out.Firewall[i]
		unit := firewallUnit(*d)
		if d.State != "" || enabled[unit] || live && serviceRunning(root, unit) {
			continue
		}
		if file, _, masked := readUnit(root, serviceDirs(live), unit, allowed); file != "" || masked {
			d.State = "not-enabled"
		}
	}
}

func addEntry(d *model.FirewallDeclaration, entry string) {
	if !slices.Contains(d.AllowedInbound, entry) && len(d.AllowedInbound) < 1024 {
		d.AllowedInbound = append(d.AllowedInbound, entry)
	}
}

func addPort(d *model.FirewallDeclaration, protocol, ports string, restricted bool) {
	if protocol != "tcp" && protocol != "udp" {
		d.UnresolvedRules++
		return
	}
	for _, p := range strings.Split(ports, ",") {
		p = strings.ReplaceAll(strings.TrimSpace(p), ":", "-")
		if !portSpec.MatchString(p) {
			continue
		}
		entry := protocol + "/" + p
		if restricted {
			entry += " restricted"
		}
		addEntry(d, entry)
	}
}

var portSpec = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)

// parseIptablesSave reads the filter table of an iptables-save file. Chains
// named INPUT, or ufw's *-user-input chains, count as inbound.
func parseIptablesSave(data []byte) model.FirewallDeclaration {
	var d model.FirewallDeclaration
	filter := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "*"):
			filter = line == "*filter"
			continue
		case !filter:
			continue
		case strings.HasPrefix(line, ":INPUT "):
			if f := strings.Fields(line); len(f) >= 2 {
				d.DefaultInputPolicy = f[1]
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || !(f[1] == "INPUT" || strings.HasSuffix(f[1], "-user-input")) {
			continue
		}
		protocol, ports, target, restricted, stateful, negated, loopback := "", "", "", false, false, false, false
		for i := 2; i < len(f); i++ {
			next := ""
			if i+1 < len(f) {
				next = f[i+1]
			}
			switch f[i] {
			case "!":
				negated = true
			case "-p", "--protocol":
				protocol = next
			case "--dport", "--dports", "--destination-port":
				ports = next
			case "-j", "--jump":
				target = next
			case "-i", "--in-interface":
				restricted, loopback = true, next == "lo"
			case "-s", "--source", "--src-range":
				restricted = true
			case "--state", "--ctstate":
				stateful = establishedOnly(next)
			}
		}
		// ufw rate-limited rules jump to ufw-user-limit-accept.
		if target != "ACCEPT" && target != "ufw-user-limit-accept" {
			continue
		}
		switch {
		case loopback:
			// Loopback traffic only; no external exposure.
		case negated:
			d.UnresolvedRules++
		case ports != "":
			addPort(&d, protocol, ports, restricted)
		case stateful:
			// Replies to established connections open no listening port.
		case protocol == "tcp" || protocol == "udp":
			addEntry(&d, protocolWide(protocol, restricted))
		case protocol != "" && protocol != "all":
			// Other protocols (icmp, esp, ...) carry no TCP/UDP listening port.
		case restricted:
			addEntry(&d, "all restricted")
		default:
			addEntry(&d, "all")
		}
	}
	return d
}

func ufwEnabled(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ENABLED="); ok {
			return strings.EqualFold(strings.Trim(v, `"'`), "yes")
		}
	}
	return false
}

func ufwPolicy(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "DEFAULT_INPUT_POLICY="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

type firewalldXML struct {
	Target   string `xml:"target,attr"`
	Services []struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		Port     string `xml:"port,attr"`
	} `xml:"port"`
	Rules []struct {
		Source *struct{} `xml:"source"`
		Port   *struct {
			Protocol string `xml:"protocol,attr"`
			Port     string `xml:"port,attr"`
		} `xml:"port"`
		Service *struct {
			Name string `xml:"name,attr"`
		} `xml:"service"`
		Accept *struct{} `xml:"accept"`
	} `xml:"rule"`
}

var firewalldName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// firewalldZone resolves the default zone's services and ports. Interfaces or
// sources bound to other zones are not resolved.
func firewalldZone(conf []byte, read func(string) []byte) model.FirewallDeclaration {
	zone := "public"
	for _, line := range strings.Split(string(conf), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "DefaultZone="); ok && firewalldName.MatchString(v) {
			zone = v
		}
	}
	d := model.FirewallDeclaration{Framework: "firewalld", Path: "etc/firewalld/firewalld.conf"}
	var z firewalldXML
	found := false
	for _, p := range []string{"etc/firewalld/zones/" + zone + ".xml", "usr/lib/firewalld/zones/" + zone + ".xml"} {
		var candidate firewalldXML
		if data := read(p); data != nil && xml.Unmarshal(data, &candidate) == nil {
			z, d.Path, found = candidate, p, true
			break
		}
	}
	if !found {
		d.UnresolvedRules++ // zone definition not readable: policy unknown
		return d
	}
	switch z.Target {
	case "", "default", "%%REJECT%%":
		d.DefaultInputPolicy = "REJECT"
	default:
		d.DefaultInputPolicy = z.Target
	}
	service := func(name string, restricted bool) {
		if !firewalldName.MatchString(name) {
			return
		}
		var s firewalldXML
		for _, p := range []string{"etc/firewalld/services/" + name + ".xml", "usr/lib/firewalld/services/" + name + ".xml"} {
			if data := read(p); data != nil && xml.Unmarshal(data, &s) == nil {
				for _, port := range s.Ports {
					addPort(&d, port.Protocol, port.Port, restricted)
				}
				return
			}
		}
	}
	for _, s := range z.Services {
		service(s.Name, false)
	}
	for _, p := range z.Ports {
		addPort(&d, p.Protocol, p.Port, false)
	}
	for _, r := range z.Rules {
		if r.Accept == nil {
			continue
		}
		if r.Port != nil {
			addPort(&d, r.Port.Protocol, r.Port.Port, r.Source != nil)
		}
		if r.Service != nil {
			service(r.Service.Name, r.Source != nil)
		}
	}
	return d
}

var nftInclude = regexp.MustCompile(`^include\s+"(/[A-Za-z0-9_./-]{1,255})"`)
var nftPorts = regexp.MustCompile(`\b(tcp|udp)\s+dport\s+(\{[^}]*\}|[0-9]+(?:-[0-9]+)?)`)

const maxNftFiles = 64

var nftEstablished = regexp.MustCompile(`ct state\s+(\{\s*)?(established|related)(\s*,\s*(established|related))*(\s*\})?\s+accept`)
var nftProtocol = regexp.MustCompile(`(?:l4proto|ip6? protocol|ip6 nexthdr)\s+(\{[^}]*\}|[a-z0-9-]+)`)

// establishedOnly reports a conntrack state list limited to ESTABLISHED and RELATED.
func establishedOnly(states string) bool {
	for _, s := range strings.Split(strings.ToUpper(states), ",") {
		if s != "ESTABLISHED" && s != "RELATED" {
			return false
		}
	}
	return states != ""
}

// protocolWide is the entry for accepting every port of one protocol.
func protocolWide(protocol string, restricted bool) string {
	if restricted {
		return protocol + "/all restricted"
	}
	return protocol + "/all"
}

var nftLoopback = regexp.MustCompile(`\biif(name)?\s+"?lo"?\s`)

// parseNftables summarizes input-hook chains. Literal includes are followed
// two levels deep, each file once and at most maxNftFiles files; globbed
// includes, named sets, maps and negations are counted as unresolved.
// A base chain without a policy accepts, as nftables does.
func parseNftables(ctx context.Context, data []byte, read func(string) []byte, d *model.FirewallDeclaration, depth int, visited map[string]bool) {
	input, chainDepth, braces, policy := false, 0, 0, ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if m := nftInclude.FindStringSubmatch(line); m != nil {
			name := strings.TrimPrefix(path.Clean(m[1]), "/")
			if depth >= 2 || strings.ContainsAny(m[1], "*?[") || len(visited) >= maxNftFiles {
				d.UnresolvedRules++
			} else if !visited[name] {
				visited[name] = true
				if inc := read(name); inc != nil {
					parseNftables(ctx, inc, read, d, depth+1, visited)
				}
			}
			continue
		}
		// "chain" may follow "table ... {" on the same line.
		if i := strings.Index(line, "chain "); i >= 0 && (i == 0 || strings.HasSuffix(strings.TrimSpace(line[:i]), "{")) {
			input, chainDepth, policy = false, braces+strings.Count(line[:i], "{")-strings.Count(line[:i], "}")+1, ""
		}
		if chainDepth > 0 && strings.Contains(line, "hook input") {
			input = true
		}
		if input {
			// Statements may share a line, e.g. "{ type ... hook input priority 0; policy drop; tcp dport 22 accept; }".
			for _, stmt := range strings.Split(line, ";") {
				stmt = strings.TrimSpace(strings.Trim(strings.TrimSpace(stmt), "{}"))
				if v, ok := strings.CutPrefix(stmt, "policy "); ok {
					policy = strings.ToUpper(strings.TrimSpace(v))
					// A packet must pass every input base chain, so drop wins.
					if d.DefaultInputPolicy != "DROP" {
						d.DefaultInputPolicy = policy
					}
					continue
				}
				if strings.Contains(stmt, "hook ") || !strings.HasSuffix(stmt, "accept") {
					continue
				}
				nftRule(d, stmt)
			}
		}
		braces += strings.Count(line, "{") - strings.Count(line, "}")
		if chainDepth > 0 && braces < chainDepth {
			if input && policy == "" && d.DefaultInputPolicy == "" {
				d.DefaultInputPolicy = "ACCEPT"
			}
			input, chainDepth = false, 0
		}
	}
}

// nftRule classifies one accept statement of an input chain.
func nftRule(d *model.FirewallDeclaration, line string) {
	restricted := strings.Contains(line, "saddr") || strings.Contains(line, "iif")
	matches := nftPorts.FindAllStringSubmatch(line, -1)
	switch {
	case nftLoopback.MatchString(line):
	case strings.Contains(line, "!=") || strings.Contains(line, "@") || strings.Contains(line, "$"):
		d.UnresolvedRules++
	case len(matches) > 0:
		for _, m := range matches {
			addPort(d, m[1], strings.Trim(m[2], "{} "), restricted)
		}
	case strings.Contains(line, "dport"):
		d.UnresolvedRules++
	case nftEstablished.MatchString(line):
		// Replies to established connections open no listening port.
	case nftProtocol.MatchString(line):
		names := strings.FieldsFunc(nftProtocol.FindStringSubmatch(line)[1], func(r rune) bool { return r == '{' || r == '}' || r == ',' || r == ' ' })
		for _, name := range names {
			if name == "tcp" || name == "udp" {
				addEntry(d, protocolWide(name, restricted))
			}
		}
	case strings.Contains(line, "icmp") || strings.Contains(line, "tcp ") || strings.Contains(line, "udp "):
		d.UnresolvedRules++ // e.g. tcp flags without a port
	case restricted:
		addEntry(d, "all restricted")
	default:
		addEntry(d, "all")
	}
}
