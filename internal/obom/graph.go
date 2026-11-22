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
}

func newGraph() *graph {
	return &graph{map[string]component{}, map[string]service{}, map[string]map[string]bool{}}
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
	}
}
func (g *graph) socket(scope, owner string, s model.Socket) {
	label := net.JoinHostPort(s.Address, strconv.Itoa(s.Port))
	ref := reference(scope, "socket", owner, s.Protocol, label)
	protocol := strings.TrimSuffix(s.Protocol, "6")
	props := []property{prop("scope", scope), prop("protocol", s.Protocol), prop("bind-address", s.Address), prop("port", strconv.Itoa(s.Port)), prop("bind-scope", s.BindScope), prop("observation", "listening-socket")}
	if owner == "" {
		props = append(props, prop("owner", "unknown"))
	} else {
		g.edge(ref, owner)
	}
	g.services[ref] = service{Ref: ref, Name: s.Protocol + " " + label, Endpoints: []string{protocol + "://" + label}, Properties: props}
	g.edge(scope, ref)
}
func (g *graph) units(scope string, units []model.Service) {
	for _, u := range units {
		ref := reference(scope, "systemd", u.Unit)
		props := []property{prop("scope", scope), prop("observation", "enabled-systemd-unit"), prop("state", u.State), prop("executable", u.Executable)}
		for _, listen := range u.Listen {
			props = append(props, prop("declared-listen", listen))
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
