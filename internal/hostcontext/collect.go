// Package hostcontext collects a deliberately small, read-only set of declared
// configuration and live-host facts. It never executes target software.
package hostcontext

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const (
	maxFileBytes   = 1 << 20
	maxWalkEntries = 50000
	maxConfigFiles = 2000
	maxProcesses   = 4096
	maxLibraries   = 512
)

var simpleToken = regexp.MustCompile(`^[A-Za-z0-9_.+-]{1,128}$`)
var settingProducts = map[string]string{"session.upload_progress.enabled": "PHP", "session.serialize_handler": "PHP"}

// Collect returns static declared settings for any directory. Only the actual
// Linux root may contribute live kernel/process data; an extracted image never
// inherits the collecting machine's runtime facts.
func Collect(ctx context.Context, root string, live bool) model.Context {
	return collect(ctx, root, live, nil, false)
}

// CollectWithPaths parses declared settings only in the caller's preflighted
// regular-file list, so user exclusions and mount boundaries apply identically
// to package and context collection. An empty list means no static files.
func CollectWithPaths(ctx context.Context, root string, live bool, paths []string) model.Context {
	return collect(ctx, root, live, paths, true)
}

func collect(ctx context.Context, root string, live bool, paths []string, listed bool) model.Context {
	out := model.Context{Mode: "filesystem", Status: "completed", Settings: []model.Setting{}, Issues: []model.Issue{}}
	absolute, err := filepath.Abs(root)
	if err != nil {
		issue(&out, "failed", "", "invalid target root")
		return out
	}
	live = live && filepath.Clean(absolute) == string(filepath.Separator) && runtime.GOOS == "linux"
	if live {
		out.Mode = "live-host"
	}
	confined, err := os.OpenRoot(absolute)
	if err != nil {
		issue(&out, "failed", "", "cannot open target root")
		return out
	}
	defer confined.Close()
	denied := []string{"proc", "sys", "dev", "run", "var/lib/docker", "var/lib/containerd", "var/lib/containers"}
	if live {
		if data, err := readBounded(confined, "proc/"+strconv.Itoa(os.Getpid())+"/mountinfo"); err == nil {
			denied = append(denied, excludedMounts(string(data))...)
		} else {
			issue(&out, statusFor(err), "proc/self/mountinfo", "mount exclusions could not be read")
			return out
		}
	}
	collector := configCollector{ctx: ctx, root: confined, out: &out, denied: denied, seen: map[string]bool{}}
	// Descend only selected configuration/install trees on a host. An application
	// directory is scanned as a bounded tree, which also finds app-root server.xml.
	if listed {
		for _, p := range paths {
			if ctx.Err() != nil || collector.limited {
				break
			}
			clean := path.Clean(filepath.ToSlash(p))
			if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || blocked(clean, denied) {
				continue
			}
			collector.file(clean)
		}
	} else if filepath.Clean(absolute) == string(filepath.Separator) {
		for _, dir := range []string{"etc", "opt", "usr/local", "srv"} {
			collector.walk(dir, 0)
		}
	} else {
		collector.walk(".", 0)
	}
	var allowed map[string]bool
	if listed {
		allowed = make(map[string]bool, len(paths))
		for _, p := range paths {
			allowed[path.Clean(filepath.ToSlash(p))] = true
		}
	}
	collectServices(confined, &out, live, allowed)
	collectScheduledJobs(confined, &out, allowed)
	collectFirewall(ctx, confined, &out, allowed)
	if live {
		collectRuntime(ctx, confined, &out, denied)
	}
	if ctx.Err() != nil {
		issue(&out, "incomplete", "", "context collection cancelled or timed out")
	}
	sort.Slice(out.Settings, func(i, j int) bool {
		a, b := out.Settings[i], out.Settings[j]
		return a.Path+"\x00"+a.Name < b.Path+"\x00"+b.Name
	})
	return out
}

func issue(out *model.Context, status, p, message string) {
	if len(out.Issues) < 200 {
		out.Issues = append(out.Issues, model.Issue{Collector: "host-context", Status: status, Path: p, Message: message})
	}
	if status == "failed" {
		out.Status = "failed"
	} else if out.Status != "failed" {
		out.Status = "partial"
	}
}
func statusFor(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission_denied"
	}
	return "incomplete"
}
func readBounded(root *os.Root, p string) ([]byte, error) {
	f, err := openNoFollow(root, p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, errors.New("file read limit exceeded")
	}
	return b, nil
}
func blocked(p string, denied []string) bool {
	p = strings.TrimPrefix(path.Clean(filepath.ToSlash(p)), "/")
	for _, dir := range denied {
		dir = strings.Trim(dir, "/")
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}
func excludedMounts(data string) []string {
	remote := map[string]bool{"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "9p": true, "ceph": true, "glusterfs": true, "afs": true, "autofs": true, "proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "securityfs": true, "debugfs": true, "tracefs": true, "configfs": true, "mqueue": true, "hugetlbfs": true, "cgroup": true, "cgroup2": true}
	var out []string
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 1 {
			continue
		}
		kind := right[0]
		if remote[kind] || strings.HasPrefix(kind, "fuse") {
			mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(left[4])
			if mount != "/" {
				out = append(out, strings.TrimPrefix(mount, "/"))
			}
		}
	}
	return out
}

type configCollector struct {
	ctx            context.Context
	root           *os.Root
	out            *model.Context
	denied         []string
	seen           map[string]bool
	entries, files int
	limited        bool
}

func (c *configCollector) walk(p string, depth int) {
	if c.ctx.Err() != nil || c.limited || blocked(p, c.denied) {
		return
	}
	if depth > 20 {
		issue(c.out, "incomplete", p, "configuration directory depth limit reached")
		return
	}
	info, err := c.root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		issue(c.out, statusFor(err), p, "configuration path cannot be inspected")
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return
	}
	c.entries++
	if c.entries > maxWalkEntries {
		c.limited = true
		issue(c.out, "incomplete", p, "configuration discovery entry limit reached")
		return
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() {
			c.file(p)
		}
		return
	}
	if p != "." {
		switch path.Base(filepath.ToSlash(p)) {
		case "node_modules", "site-packages", "dist-packages", ".git", ".ssh", ".gnupg", ".cache", "vendor", "reports", "sbom-output":
			return
		}
	}
	f, err := openNoFollow(c.root, p)
	if err != nil {
		issue(c.out, statusFor(err), p, "configuration directory cannot be read")
		return
	}
	defer f.Close()
	entries, err := f.ReadDir(maxWalkEntries + 1)
	if err != nil && err != io.EOF {
		issue(c.out, statusFor(err), p, "configuration directory cannot be read")
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if c.ctx.Err() != nil || c.limited {
			return
		}
		c.walk(path.Join(filepath.ToSlash(p), entry.Name()), depth+1)
	}
}
func (c *configCollector) file(p string) {
	name := strings.ToLower(path.Base(p))
	low := strings.ToLower(p)
	isPHP := name == "php.ini" || (strings.HasSuffix(name, ".ini") && strings.Contains(low, "php"))
	isApache := (strings.HasSuffix(name, ".conf") || name == "httpd.conf") && (strings.Contains(low, "apache") || strings.Contains(low, "httpd"))
	isNginx := (strings.HasSuffix(name, ".conf") || name == "nginx.conf") && strings.Contains(low, "nginx")
	isTomcat := name == "server.xml"
	isSELinux := p == "etc/selinux/config"
	isSSHD := p == "etc/ssh/sshd_config" || (strings.HasPrefix(p, "etc/ssh/sshd_config.d/") && strings.HasSuffix(name, ".conf"))
	if !isPHP && !isApache && !isNginx && !isTomcat && !isSELinux && !isSSHD {
		return
	}
	if c.seen[p] {
		return
	}
	c.seen[p] = true
	c.files++
	if c.files > maxConfigFiles {
		c.limited = true
		issue(c.out, "incomplete", p, "configuration file count limit reached")
		return
	}
	data, err := readBounded(c.root, p)
	if err != nil {
		issue(c.out, statusFor(err), p, "configuration file cannot be read within limits")
		return
	}
	if isPHP {
		c.php(p, string(data))
	}
	if isApache {
		c.apache(p, string(data))
	}
	if isNginx {
		c.nginx(p, string(data))
	}
	if isTomcat {
		c.tomcat(p, data)
	}
	if isSSHD {
		c.sshd(p, string(data))
	}
	if isSELinux {
		// Persisted mode for the next boot; the running mode is observed separately.
		if mode := selinuxConfigMode(string(data)); mode != "" {
			c.add("SELinux", "config.SELINUX", mode, p)
		}
	}
}
func (c *configCollector) add(product, name, value, p string) {
	c.out.Settings = append(c.out.Settings, model.Setting{Product: product, Name: name, Value: value, Path: p, State: "declared"})
}
func (c *configCollector) php(p, data string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || settingProducts[key] == "" {
			continue
		}
		value = strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
		value = strings.Trim(value, `"' `)
		switch key {
		case "session.upload_progress.enabled":
			v := strings.ToLower(value)
			if v == "0" || v == "off" || v == "false" || v == "no" {
				value = "false"
			} else if v == "1" || v == "on" || v == "true" || v == "yes" {
				value = "true"
			} else {
				value = "unknown"
			}
		case "session.serialize_handler":
			if value != "php" && value != "php_binary" && value != "php_serialize" {
				value = "unknown"
			}
		}
		c.add("PHP", key, value, p)
	}
}
func (c *configCollector) apache(p, data string) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	modules := map[string]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "LoadModule") && simpleToken.MatchString(fields[1]) && strings.HasSuffix(fields[1], "_module") {
			modules[fields[1]] = true
		}
	}
	names := make([]string, 0, len(modules))
	for module := range modules {
		names = append(names, module)
	}
	sort.Strings(names)
	for _, module := range names {
		c.add("Apache HTTP Server", "LoadModule."+module, "true", p)
	}
}

// sshd settings that change exposure, for example LoginGraceTime 0, which
// mitigates CVE-2024-6387. Like the nginx reader this is a per-file declaration:
// sshd keeps the first value it reads, so Include order decides the effective one.
var sshdKeywords = map[string]string{
	"permitrootlogin": "PermitRootLogin", "passwordauthentication": "PasswordAuthentication",
	"permitemptypasswords": "PermitEmptyPasswords", "kbdinteractiveauthentication": "KbdInteractiveAuthentication",
	"logingracetime": "LoginGraceTime", "maxstartups": "MaxStartups", "x11forwarding": "X11Forwarding",
	"allowtcpforwarding": "AllowTcpForwarding",
}
var sshdValue = regexp.MustCompile(`^[A-Za-z0-9_.:+-]{1,64}$`)

func (c *configCollector) sshd(p, data string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value, _ := strings.Cut(strings.Replace(line, "=", " ", 1), " ")
		if strings.EqualFold(keyword, "Match") {
			break // later lines apply only to matching connections
		}
		name := sshdKeywords[strings.ToLower(keyword)]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if !sshdValue.MatchString(value) {
			value = "unknown"
		}
		c.add("OpenSSH", "sshd."+name, value, p)
	}
}

func (c *configCollector) nginx(p, data string) {
	// This is a lexical declaration observation, not effective configuration or an
	// interpretation of includes, variables, locations or request routing.
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileBytes)
	for scanner.Scan() {
		line := strings.SplitN(scanner.Text(), "#", 2)[0]
		for _, piece := range strings.FieldsFunc(line, func(r rune) bool { return r == '{' || r == '}' || r == ';' }) {
			fields := strings.Fields(piece)
			if len(fields) > 0 && (fields[0] == "alias" || fields[0] == "rewrite") {
				seen[fields[0]] = true
			}
		}
	}
	for _, name := range []string{"alias", "rewrite"} {
		if seen[name] {
			c.add("nginx", "directive."+name, "true", p)
		}
	}
}
func (c *configCollector) tomcat(p string, data []byte) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	ajp, http2 := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			issue(c.out, "incomplete", p, "server XML could not be parsed")
			return
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "Connector" {
			for _, attr := range start.Attr {
				if attr.Name.Local == "protocol" && strings.Contains(strings.ToLower(attr.Value), "ajp") {
					ajp = true
				}
			}
		}
		if start.Name.Local == "UpgradeProtocol" {
			for _, attr := range start.Attr {
				if attr.Name.Local == "className" && strings.Contains(attr.Value, "Http2Protocol") {
					http2 = true
				}
			}
		}
	}
	c.add("Tomcat", "connector.ajp", strconv.FormatBool(ajp), p)
	c.add("Tomcat", "upgrade.http2", strconv.FormatBool(http2), p)
}
