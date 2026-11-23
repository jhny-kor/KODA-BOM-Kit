// Package obom projects recorded host observations into a CycloneDX operations BOM.
package obom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type component struct {
	Type       string     `json:"type"`
	Ref        string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Properties []property `json:"properties,omitempty"`
}
type service struct {
	Ref        string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Endpoints  []string   `json:"endpoints,omitempty"`
	Properties []property `json:"properties,omitempty"`
}
type dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}
type graph struct {
	components map[string]component
	services   map[string]service
	edges      map[string]map[string]bool
	// Host firewall declarations used to annotate non-loopback listening sockets
	// of firewallScope. Containers have network namespaces of their own.
	firewall      []model.FirewallDeclaration
	firewallScope string
	// Listening sockets and outbound connections, matched by resolveRemotes.
	listeners []listener
	pending   []pendingRemote
}

type listener struct {
	scope, ref, owner, protocol, address string
	port                                 int
}

type pendingRemote struct {
	scope, owner string
	conn         model.Connection
}

func newGraph() *graph {
	return &graph{components: map[string]component{}, services: map[string]service{}, edges: map[string]map[string]bool{}}
}
func reference(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "koda-obom-" + hex.EncodeToString(h[:16])
}
func prop(name, value string) property { return property{"koda:obom:" + name, value} }
func (g *graph) edge(from, to string) {
	if from == to || from == "" || to == "" {
		return
	}
	if g.edges[from] == nil {
		g.edges[from] = map[string]bool{}
	}
	g.edges[from][to] = true
}
func (g *graph) packageRef(scope string, file model.RuntimeFile) string {
	if file.PURL == "" && file.Package == "" {
		return ""
	}
	identity := file.PURL
	if identity == "" {
		identity = file.Package + "\x00" + file.InstalledVersion
	}
	ref := reference(scope, "package", identity)
	if _, exists := g.components[ref]; exists {
		return ref
	}
	name := file.Package
	if name == "" {
		name = file.PURL
	}
	g.components[ref] = component{Type: "library", Ref: ref, Name: name, Version: file.InstalledVersion, PURL: file.PURL, Properties: []property{prop("scope", scope), prop("version-evidence", "installed-owner")}}
	return ref
}
func (g *graph) processes(scope string, processes []model.ProcessLink) {
	for _, p := range processes {
		ref := reference(scope, "process", strconv.Itoa(p.PID), p.Executable)
		props := []property{prop("scope", scope), prop("pid", strconv.Itoa(p.PID)), prop("executable", p.Executable), prop("filesystem-comparable", strconv.FormatBool(p.FilesystemComparable)), prop("state", "running")}
		if !p.FilesystemComparable {
			props = append(props, prop("visibility", "collector-visible"), prop("membership", "unconfirmed"))
		}
		if p.ExecutableDeleted {
			props = append(props, prop("executable-deleted", "true"))
		}
		for _, m := range p.ModelReferences {
			props = append(props, prop("model-reference", m))
		}
		g.components[ref] = component{Type: "application", Ref: ref, Name: "process " + strconv.Itoa(p.PID), Properties: props}
		g.edge(scope, ref)
		owner := ""
		if p.FilesystemComparable {
			for _, f := range p.RuntimeFiles {
				pkg := g.packageRef(scope, f)
				fileRef := reference(scope, "runtime-file", strconv.Itoa(p.PID), f.Path)
				g.components[fileRef] = component{Type: "file", Ref: fileRef, Name: f.Path, Properties: []property{prop("scope", scope), prop("state", f.State), prop("deleted", strconv.FormatBool(f.Deleted)), prop("device", f.Device), prop("inode", strconv.FormatUint(f.Inode, 10))}}
				g.edge(ref, fileRef)
				g.edge(fileRef, pkg)
				g.edge(ref, pkg)
				if f.Path == p.Executable {
					owner = pkg
				}
			}
		}
		if owner != "" {
			c := g.components[ref]
			c.Properties = append(c.Properties, prop("executable-package", owner))
			g.components[ref] = c
		}
		for _, s := range p.ListeningSockets {
			g.socket(scope, ref, s)
		}
		for _, c := range p.OutboundConnections {
			g.remote(scope, ref, c)
		}
	}
}

// remote queues an endpoint a process was connected to; resolveRemotes links
// it once every listening socket in the scope is known.
func (g *graph) remote(scope, owner string, c model.Connection) {
	g.pending = append(g.pending, pendingRemote{scope, owner, c})
}

// resolveRemotes links a connection to a local listening socket when the
// endpoint is one this host listens on: the same address, or a loopback or
// own-address (local-host) peer of an all-interfaces listener. That listener
// already depends on its owning process, so client and server processes become
// connected; a process reaching its own listener adds no edge. Other endpoints
// become shared remote services.
func (g *graph) resolveRemotes() {
	for _, p := range g.pending {
		remote := net.ParseIP(p.conn.RemoteAddress)
		local := remote != nil && (remote.IsLoopback() || p.conn.RemoteScope == "local-host")
		matched := false
		for _, l := range g.listeners {
			if l.scope != p.scope || l.port != p.conn.RemotePort || !strings.HasPrefix(l.protocol, "tcp") {
				continue
			}
			bind := net.ParseIP(l.address)
			if remote != nil && bind != nil && (bind.Equal(remote) || bind.IsUnspecified() && local) {
				matched = true
				if l.owner != p.owner {
					g.edge(p.owner, l.ref)
				}
			}
		}
		if !matched {
			g.remoteService(p.scope, p.owner, p.conn)
		}
	}
	g.pending = nil
}

// remoteService records an endpoint with no matching local listener;
// processes reaching the same endpoint share one service.
func (g *graph) remoteService(scope, owner string, c model.Connection) {
	label := net.JoinHostPort(c.RemoteAddress, strconv.Itoa(c.RemotePort))
	ref := reference(scope, "remote", c.Protocol, label)
	if _, exists := g.services[ref]; !exists {
		props := []property{prop("scope", scope), prop("observation", "outbound-connection"), prop("remote-address", c.RemoteAddress), prop("remote-port", strconv.Itoa(c.RemotePort)), prop("remote-scope", c.RemoteScope)}
		g.services[ref] = service{Ref: ref, Name: c.Protocol + " " + label, Endpoints: []string{c.Protocol + "://" + label}, Properties: props}
	}
	g.edge(owner, ref)
}

// jobs records declared cron entries and cron directory scripts.
func (g *graph) jobs(scope string, jobs []model.ScheduledJob) {
	for _, j := range jobs {
		at := j.Source
		if j.Line > 0 {
			at += ":" + strconv.Itoa(j.Line)
		}
		ref := reference(scope, "scheduled-job", at)
		props := []property{prop("scope", scope), prop("observation", "scheduled-job"), prop("schedule", j.Schedule), prop("declared-at", at)}
		if j.User != "" {
			props = append(props, prop("user", j.User))
		}
		if j.Executable != "" {
			props = append(props, prop("executable", j.Executable))
		}
		g.services[ref] = service{Ref: ref, Name: "cron " + at, Properties: props}
		g.edge(scope, ref)
	}
}
func (g *graph) socket(scope, owner string, s model.Socket) {
	label := net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
	ref := reference(scope, "socket", owner, s.Protocol, label)
	protocol := strings.TrimSuffix(s.Protocol, "6")
	props := []property{prop("scope", scope), prop("protocol", s.Protocol), prop("bind-address", s.Address), prop("port", strconv.Itoa(s.Port)), prop("bind-scope", s.BindScope), prop("observation", "listening-socket")}
	if s.BindScope != "loopback" && scope == g.firewallScope {
		props = append(props, prop("firewall-declared", firewallAccepts(g.firewall, s.Protocol, s.Port)))
	}
	if owner == "" {
		props = append(props, prop("owner", "unknown"))
	} else {
		g.edge(ref, owner)
	}
	g.services[ref] = service{Ref: ref, Name: s.Protocol + " " + label, Endpoints: []string{protocol + "://" + label}, Properties: props}
	g.edge(scope, ref)
	g.listeners = append(g.listeners, listener{scope: scope, ref: ref, owner: owner, protocol: s.Protocol, address: s.Address, port: s.Port})
}
func (g *graph) units(scope string, units []model.Service) {
	for _, u := range units {
		ref := reference(scope, "systemd", u.Unit)
		props := []property{prop("scope", scope), prop("observation", "enabled-systemd-unit"), prop("state", u.State), prop("executable", u.Executable)}
		for _, listen := range u.Listen {
			props = append(props, prop("declared-listen", listen))
		}
		for _, schedule := range u.Schedule {
			props = append(props, prop("declared-schedule", schedule))
		}
		g.services[ref] = service{Ref: ref, Name: u.Unit, Properties: props}
		g.edge(scope, ref)
		if u.PURL != "" {
			pkg := g.packageRef(scope, model.RuntimeFile{PURL: u.PURL})
			g.edge(ref, pkg)
		}
	}
}
func (g *graph) document(version, timestamp, host string, properties []property) map[string]any {
	components := make([]component, 0, len(g.components))
	for ref, c := range g.components {
		if ref != host {
			components = append(components, c)
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Ref < components[j].Ref })
	services := make([]service, 0, len(g.services))
	for _, s := range g.services {
		services = append(services, s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Ref < services[j].Ref })
	dependencies := make([]dependency, 0, len(g.edges))
	for ref, targets := range g.edges {
		d := dependency{Ref: ref, DependsOn: []string{}}
		for target := range targets {
			d.DependsOn = append(d.DependsOn, target)
		}
		sort.Strings(d.DependsOn)
		dependencies = append(dependencies, d)
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Ref < dependencies[j].Ref })
	metadata := map[string]any{"component": g.components[host], "lifecycles": []map[string]string{{"phase": "operations"}}, "properties": properties}
	if timestamp != "" {
		metadata["timestamp"] = timestamp
	}
	return map[string]any{"bomFormat": "CycloneDX", "specVersion": version, "version": 1, "metadata": metadata, "components": components, "services": services, "dependencies": dependencies, "compositions": []map[string]string{{"aggregate": "incomplete"}}}
}
func parseSocketLabel(label string) (model.Socket, error) {
	protocol, rest, ok := strings.Cut(label, "/")
	if !ok {
		return model.Socket{}, fmt.Errorf("invalid socket observation")
	}
	endpoint, scope, ok := strings.Cut(rest, " (")
	if !ok || !strings.HasSuffix(scope, ")") {
		return model.Socket{}, fmt.Errorf("invalid socket observation")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return model.Socket{}, err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return model.Socket{}, fmt.Errorf("invalid socket port")
	}
	return model.Socket{Protocol: protocol, Address: host, Port: n, BindScope: strings.TrimSuffix(scope, ")")}, nil
}

// firewallAccepts summarizes how active declarations treat an inbound port:
// "accept-declared", "accept-declared-restricted", "policy-accept-declared",
// "no-accept-declared", or "undetermined" when a policy or rule could not be
// resolved. It returns "none-observed" when no active declaration was read:
// none exists, all are disabled, or the files were unreadable.
func firewallAccepts(declarations []model.FirewallDeclaration, protocol string, port int) string {
	protocol = strings.TrimSuffix(protocol, "6")
	active, restricted, policyAccept, unknown := false, false, false, false
	for _, d := range declarations {
		if d.State == "disabled" || d.State == "not-enabled" {
			continue
		}
		active = true
		policyAccept = policyAccept || d.DefaultInputPolicy == "ACCEPT"
		unknown = unknown || d.DefaultInputPolicy == "" || d.UnresolvedRules > 0
		for _, entry := range d.AllowedInbound {
			spec, qualifier, _ := strings.Cut(entry, " ")
			match := spec == "all"
			if proto, ports, ok := strings.Cut(spec, "/"); ok && proto == protocol {
				low, high, isRange := strings.Cut(ports, "-")
				if !isRange {
					high = low
				}
				lo, errL := strconv.Atoi(low)
				hi, errH := strconv.Atoi(high)
				match = ports == "all" || errL == nil && errH == nil && lo <= port && port <= hi
			}
			if match && qualifier == "" {
				return "accept-declared"
			}
			restricted = restricted || match
		}
	}
	switch {
	case !active:
		return "none-observed"
	case policyAccept:
		return "policy-accept-declared"
	case restricted:
		return "accept-declared-restricted"
	case unknown:
		return "undetermined"
	}
	return "no-accept-declared"
}
