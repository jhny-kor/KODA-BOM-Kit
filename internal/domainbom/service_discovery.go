package domainbom

import (
	"context"
	"io"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

// ServiceDiscovery holds backend services declared by local reverse proxies
// and load balancers. Declarations show intended routing; whether a backend
// is reachable or in use needs runtime evidence such as OBOM connections.
type ServiceDiscovery struct {
	Services []map[string]any
	Issues   []model.Issue
}

const (
	maxProxyFiles    = 1000
	maxProxyServices = 2000
	maxProxyBytes    = 1 << 20
)

type declaredBackend struct {
	consumer, name string
	endpoints      map[string]bool
	declaredAt     map[string]bool
}

type proxyScanner struct {
	ctx      context.Context
	plan     localfs.Plan
	scope    string
	backends map[string]*declaredBackend
	// nginx upstream and Apache balancer groups by name, resolved after all files are read.
	groups map[string]map[string]bool
	// Proxy targets that may name a group: consumer, group name, declaration.
	references []struct{ consumer, scheme, name, at string }
	issues     []model.Issue
}

func proxyConsumer(p string) string {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(p, "etc/nginx/") || strings.HasPrefix(p, "usr/local/nginx/conf/") || strings.HasPrefix(p, "usr/local/openresty/nginx/conf/"):
		if strings.HasSuffix(base, ".conf") || strings.Contains(p, "/sites-enabled/") {
			return "nginx"
		}
	case strings.HasPrefix(p, "etc/httpd/") || strings.HasPrefix(p, "etc/apache2/"):
		if strings.HasSuffix(base, ".conf") || strings.Contains(p, "/sites-enabled/") {
			return "apache"
		}
	case p == "etc/haproxy/haproxy.cfg" || strings.HasPrefix(p, "etc/haproxy/conf.d/") && strings.HasSuffix(base, ".cfg"):
		return "haproxy"
	}
	return ""
}

// DiscoverServices reads proxy and load balancer configuration admitted by plan.
func DiscoverServices(ctx context.Context, plan localfs.Plan, scope string) (ServiceDiscovery, error) {
	root, err := plan.OpenRoot()
	if err != nil {
		return ServiceDiscovery{}, err
	}
	defer root.Close()
	s := proxyScanner{ctx: ctx, plan: plan, scope: scope, backends: map[string]*declaredBackend{}, groups: map[string]map[string]bool{}}
	candidates := append(append([]string{}, plan.Paths...), plan.IndexedLinks()...)
	sort.Strings(candidates)
	files := 0
	for _, p := range candidates {
		if err := ctx.Err(); err != nil {
			return ServiceDiscovery{}, err
		}
		consumer := proxyConsumer(p)
		if consumer == "" {
			continue
		}
		if files++; files > maxProxyFiles {
			s.issue(p, "proxy_configuration_limit")
			break
		}
		f, st, err := plan.OpenIndexedRegular(root, p)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxProxyBytes+1))
		f.Close()
		if err != nil || st.Size() > maxProxyBytes || len(data) > maxProxyBytes {
			s.issue(p, "proxy_configuration_unreadable")
			continue
		}
		switch consumer {
		case "nginx":
			s.nginx(p, string(data))
		case "apache":
			s.apache(p, string(data))
		case "haproxy":
			s.haproxy(p, string(data))
		}
	}
	for _, r := range s.references {
		if members, ok := s.groups[r.consumer+"\x00"+r.name]; ok {
			for m := range members {
				if !strings.Contains(m, "://") {
					m = endpoint(r.scheme, m) // nginx upstream servers take the proxy_pass scheme
				}
				s.add(r.consumer, r.name, m, r.at)
			}
			if len(members) == 0 {
				s.add(r.consumer, r.name, "", r.at)
			}
		} else {
			s.add(r.consumer, r.name, endpoint(r.scheme, r.name), r.at)
		}
	}
	return ServiceDiscovery{Services: s.objects(), Issues: s.issues}, nil
}

func (s *proxyScanner) issue(p, code string) {
	if len(s.issues) < 100 {
		s.issues = append(s.issues, model.Issue{Collector: "service-discovery", Target: s.scope, Status: "incomplete", Code: code, Path: p, Message: "proxy configuration could not be inspected completely"})
	}
}

func (s *proxyScanner) location(p string, line int) string {
	at := p + ":" + strconv.Itoa(line)
	if s.scope != "" {
		at = s.scope + "/" + at
	}
	return at
}

func (s *proxyScanner) add(consumer, name, ep, at string) {
	key := consumer + "\x00" + name
	b := s.backends[key]
	if b == nil {
		if len(s.backends) >= maxProxyServices {
			return
		}
		b = &declaredBackend{consumer: consumer, name: name, endpoints: map[string]bool{}, declaredAt: map[string]bool{}}
		s.backends[key] = b
	}
	if ep != "" {
		b.endpoints[ep] = true
	}
	b.declaredAt[at] = true
}

func (s *proxyScanner) member(consumer, group, hostport string) {
	key := consumer + "\x00" + group
	if s.groups[key] == nil {
		s.groups[key] = map[string]bool{}
	}
	if hostport != "" {
		s.groups[key][hostport] = true
	}
}

// target splits a proxy URL into scheme and host[:port]. Paths, queries and
// credentials are dropped; variables and unix sockets are unresolved.
func target(raw, defaultScheme string) (scheme, hostport string, ok bool) {
	if strings.ContainsAny(raw, "$%{}") {
		return "", "", false
	}
	if !strings.Contains(raw, "://") {
		raw = defaultScheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || strings.HasPrefix(u.Host, "unix:") || !textOK(u.Host, true) {
		return "", "", false
	}
	return strings.ToLower(u.Scheme), strings.ToLower(u.Host), true
}

func endpoint(scheme, hostport string) string { return scheme + "://" + hostport }

// statements splits nginx configuration into ';', '{' and '}' terminated
// statements with the line each starts on. Quoted strings are kept literal.
func statements(data string, visit func(words []string, term byte, line int)) {
	var words []string
	var token strings.Builder
	var quote byte
	line, start := 1, 1
	flush := func() {
		if token.Len() > 0 {
			if len(words) == 0 {
				start = line
			}
			words = append(words, token.String())
			token.Reset()
		}
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '\n' {
			line++
		}
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				token.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			flush()
			for i < len(data) && data[i] != '\n' {
				i++
			}
			line++
		case c == ';' || c == '{' || c == '}':
			flush()
			visit(words, c, start)
			words = nil
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			token.WriteByte(c)
		}
	}
}

func (s *proxyScanner) nginx(p, data string) {
	var stack []string
	statements(data, func(words []string, term byte, line int) {
		switch term {
		case '{':
			name := ""
			if len(words) == 2 && words[0] == "upstream" {
				name = strings.ToLower(words[1]) // nginx matches upstream names case-insensitively
				s.member("nginx", name, "")
			}
			stack = append(stack, name)
			return
		case '}':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return
		}
		if len(words) < 2 {
			return
		}
		upstream := ""
		if len(stack) > 0 {
			upstream = stack[len(stack)-1]
		}
		switch {
		case upstream != "" && words[0] == "server":
			if _, hostport, ok := target(words[1], "tcp"); ok {
				s.member("nginx", upstream, hostport)
			}
		case words[0] == "proxy_pass" || words[0] == "grpc_pass":
			defaultScheme := "http"
			if words[0] == "grpc_pass" {
				defaultScheme = "grpc"
			}
			scheme, hostport, ok := target(words[1], defaultScheme)
			if !ok {
				s.issue(p, "proxy_target_unresolved")
				return
			}
			s.references = append(s.references, struct{ consumer, scheme, name, at string }{"nginx", scheme, hostport, s.location(p, line)})
		}
	})
}

func (s *proxyScanner) apache(p, data string) {
	balancer := ""
	for i, raw := range strings.Split(data, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		directive := strings.ToLower(strings.Trim(fields[0], "<>"))
		if directive == "proxy" && len(fields) >= 2 && strings.HasPrefix(fields[0], "<") {
			if _, name, ok := target(strings.Trim(strings.TrimSuffix(fields[1], ">"), `"`), "http"); ok && strings.HasPrefix(strings.ToLower(strings.Trim(fields[1], `"`)), "balancer://") {
				balancer = name
				s.member("apache", name, "")
			}
			continue
		}
		if strings.HasPrefix(fields[0], "</") && strings.EqualFold(fields[0], "</Proxy>") {
			balancer = ""
			continue
		}
		switch directive {
		case "balancermember":
			if balancer != "" && len(fields) >= 2 {
				if scheme, hostport, ok := target(strings.Trim(fields[1], `"`), "http"); ok {
					s.member("apache", balancer, endpoint(scheme, hostport))
				}
			}
		case "proxypass", "proxypassmatch":
			for _, f := range fields[1:] {
				f = strings.Trim(f, `"`)
				if !strings.Contains(f, "://") {
					continue
				}
				scheme, hostport, ok := target(f, "http")
				if !ok {
					s.issue(p, "proxy_target_unresolved")
					break
				}
				if scheme == "balancer" {
					s.references = append(s.references, struct{ consumer, scheme, name, at string }{"apache", "http", hostport, s.location(p, i+1)})
				} else {
					s.add("apache", hostport, endpoint(scheme, hostport), s.location(p, i+1))
				}
				break
			}
		}
	}
}

func (s *proxyScanner) haproxy(p, data string) {
	section := ""
	for i, raw := range strings.Split(data, "\n") {
		line, _, _ := strings.Cut(raw, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "backend", "listen", "frontend", "defaults", "global", "resolvers", "peers", "userlist", "cache", "program", "mailers", "ring", "log-forward", "http-errors", "crt-store", "traces":
			section = ""
			if (fields[0] == "backend" || fields[0] == "listen") && len(fields) >= 2 {
				section = fields[1]
			}
			continue
		}
		if section == "" || fields[0] != "server" || len(fields) < 3 {
			continue
		}
		addr := fields[2]
		if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "unix@") || strings.HasPrefix(addr, "abns@") {
			continue
		}
		addr = strings.TrimPrefix(strings.TrimPrefix(addr, "ipv4@"), "ipv6@")
		if host, port, err := net.SplitHostPort(addr); err == nil && port == "" {
			addr = host
		}
		if _, hostport, ok := target(addr, "tcp"); ok {
			s.add("haproxy", section, endpoint("tcp", hostport), s.location(p, i+1))
		}
	}
}

func (s *proxyScanner) objects() []object {
	keys := make([]string, 0, len(s.backends))
	for k := range s.backends {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []object
	for _, k := range keys {
		b := s.backends[k]
		props := []property{prop("observation", "declared-proxy-backend"), prop("consumer", b.consumer), prop("runtime-state", "not-observed")}
		for _, at := range sortedSet(b.declaredAt) {
			props = append(props, prop("declared-at", at))
		}
		item := object{"bom-ref": ref("proxy-backend", s.scope, b.consumer, b.name), "name": b.name, "properties": props}
		if eps := sortedSet(b.endpoints); len(eps) > 0 {
			item["endpoints"] = eps
		}
		out = append(out, item)
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
