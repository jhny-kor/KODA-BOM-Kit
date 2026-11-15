// Package products discovers product metadata without running installed software.
package products

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const (
	maxMetadata = 512 << 10
	maxNative   = 32 << 20
	maxArchive  = 128 << 20
	maxProducts = 20000
)

var numericVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:[_+.-][A-Za-z0-9]+)*$`)
var tomcatInfo = regexp.MustCompile(`^Apache Tomcat/([0-9]+(?:\.[0-9]+)*(?:[-.][A-Za-z0-9]+)*)$`)
var weblogicVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){3,6}$`)
var phpBasename = regexp.MustCompile(`^php(?:-fpm|-cgi)?(?:[0-9]+(?:\.[0-9]+)*)?$`)
var patchID = regexp.MustCompile(`^[0-9]{5,12}$`)
var printable = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+()/@,:;=-]{0,199}$`)

type collector struct {
	root     *os.Root
	products []model.Product
	issues   []model.Issue
}

// Collect considers only the supplied root-relative regular file paths. It does
// not traverse the filesystem, invoke programs, or access remote services.
func Collect(ctx context.Context, root string, paths []string) ([]model.Product, []model.Issue) {
	c := &collector{products: []model.Product{}, issues: []model.Issue{}}
	fs, err := os.OpenRoot(root)
	if err != nil {
		c.issue("failed", "", "cannot open product metadata root")
		return c.products, c.issues
	}
	defer fs.Close()
	c.root = fs
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	seen := map[string]bool{}
	for _, raw := range paths {
		if ctx.Err() != nil {
			c.issue("incomplete", "", "product metadata collection cancelled")
			break
		}
		rel, ok := cleanPath(raw)
		if !ok {
			c.issue("incomplete", "", "rejected non-relative product evidence path")
			continue
		}
		// Patch caches contain old inventories and must never be promoted to
		// current product installations or proof of applied patches.
		if strings.Contains("/"+strings.ToLower(rel)+"/", "/.patch_storage/") {
			continue
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		base := strings.ToLower(path.Base(rel))
		switch {
		case base == "release":
			c.jdk(rel)
		case base == "catalina.jar":
			c.tomcat(rel)
		case base == "weblogic.jar":
			c.weblogic(rel)
		case base == "comps.xml" && strings.HasSuffix(strings.ToLower(rel), "inventory/contentsxml/comps.xml"):
			c.oracleInventory(rel)
		case base == "manifest.mf" && strings.Contains(strings.ToLower(rel), "org/jboss/as/product/"):
			c.jboss(rel)
		case nativeKind(base) != "":
			c.native(rel, base)
		case strings.Contains(strings.ToLower(rel), "jeus") && (base == "version.txt" || base == "jeus.properties" || base == "jeus.jar"):
			c.issue("not_supported", rel, "JEUS product and patch metadata are not qualified; library archive inventory remains separate")
		}
		if len(c.products) >= maxProducts {
			c.issue("incomplete", "", "product metadata limit reached")
			break
		}
	}
	c.mergeInventory()
	return c.products, c.issues
}

func cleanPath(value string) (string, bool) {
	value = filepath.ToSlash(value)
	if value == "" || path.IsAbs(value) || strings.ContainsRune(value, 0) {
		return "", false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", false
		}
	}
	value = path.Clean(value)
	if value == "." {
		return "", false
	}
	return value, true
}
func (c *collector) issue(status, p, msg string) {
	c.issues = append(c.issues, model.Issue{Collector: "products", Status: status, Path: p, Message: msg})
}
func (c *collector) open(rel string, limit int64) (*os.File, os.FileInfo, error) {
	f, err := c.root.Open(rel)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		f.Close()
		return nil, nil, fmt.Errorf("not a bounded regular metadata file")
	}
	return f, st, nil
}
func (c *collector) read(rel string, limit int64) ([]byte, error) {
	f, _, err := c.open(rel, limit)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("metadata read limit exceeded")
	}
	return b, err
}
func (c *collector) readIssue(rel string, limit int64) ([]byte, bool) {
	b, err := c.read(rel, limit)
	if err == nil {
		return b, true
	}
	state := "incomplete"
	if errors.Is(err, os.ErrPermission) {
		state = "permission_denied"
	}
	c.issue(state, rel, "cannot read bounded product metadata")
	return nil, false
}
func evidence(rel, field, value string) model.Evidence {
	return model.Evidence{Path: rel, Field: field, Value: value}
}
func product(name, version, vendor, kind, install, confidence string, ev []model.Evidence) model.Product {
	sum := sha256.Sum256([]byte(name + "\x00" + version + "\x00" + install))
	return model.Product{ID: "product-" + hex.EncodeToString(sum[:12]), Name: name, Version: version, Vendor: vendor, Kind: kind, InstallPath: install, Evidence: ev, PatchState: "unknown", Confidence: confidence}
}
func validVersion(s string) bool { return len(s) <= 100 && numericVersion.MatchString(s) }
func metadataMap(data []byte, separator string) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxMetadata)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		key, value, ok := strings.Cut(line, separator)
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		out[key] = value
	}
	return out
}
func manifestMap(data []byte) map[string]string {
	// JAR manifests wrap continuation lines with one leading space.
	unfolded := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n ", "")
	return metadataMap([]byte(unfolded), ":")
}
func (c *collector) jdk(rel string) {
	data, ok := c.readIssue(rel, maxMetadata)
	if !ok {
		return
	}
	m := metadataMap(data, "=")
	version := m["JAVA_VERSION"]
	if !validVersion(version) {
		return
	}
	ev := []model.Evidence{evidence(rel, "JAVA_VERSION", version)}
	confidence := "metadata"
	if runtimeVersion := m["JAVA_RUNTIME_VERSION"]; validVersion(runtimeVersion) {
		ev = append(ev, evidence(rel, "JAVA_RUNTIME_VERSION", runtimeVersion))
		if !strings.HasPrefix(runtimeVersion, version+"+") && !strings.HasPrefix(runtimeVersion, version+"-") && runtimeVersion != version {
			version = ""
			confidence = "conflicting"
			c.issue("incomplete", rel, "Java runtime version metadata conflicts")
		} else {
			version = runtimeVersion
		}
	}
	vendor := m["IMPLEMENTOR"]
	if !printable.MatchString(vendor) {
		vendor = ""
	} else {
		ev = append(ev, evidence(rel, "IMPLEMENTOR", vendor))
	}
	for _, key := range []string{"IMPLEMENTOR_VERSION", "OS_ARCH", "JAVA_VERSION_DATE"} {
		if printable.MatchString(m[key]) {
			ev = append(ev, evidence(rel, key, m[key]))
		}
	}
	c.products = append(c.products, product("Java", version, vendor, "runtime", path.Dir(rel), confidence, ev))
}
func (c *collector) zipEntries(rel string, names ...string) (map[string][]byte, bool) {
	f, st, err := c.open(rel, maxArchive)
	if err != nil {
		c.issue("incomplete", rel, "cannot open bounded product archive")
		return nil, false
	}
	defer f.Close()
	z, err := zip.NewReader(f, st.Size())
	if err != nil {
		c.issue("incomplete", rel, "invalid product archive")
		return nil, false
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	out := map[string][]byte{}
	for _, entry := range z.File {
		if !wanted[entry.Name] {
			continue
		}
		if _, exists := out[entry.Name]; exists {
			c.issue("incomplete", rel, "duplicate product archive metadata entry")
			return nil, false
		}
		if entry.Mode()&os.ModeSymlink != 0 || entry.UncompressedSize64 > maxMetadata {
			c.issue("incomplete", rel, "unsafe or oversized product archive metadata")
			return nil, false
		}
		r, err := entry.Open()
		if err != nil {
			c.issue("incomplete", rel, "unreadable product archive metadata")
			return nil, false
		}
		b, readErr := io.ReadAll(io.LimitReader(r, maxMetadata+1))
		r.Close()
		if readErr != nil || len(b) > maxMetadata {
			c.issue("incomplete", rel, "invalid or oversized product archive metadata")
			return nil, false
		}
		out[entry.Name] = b
	}
	return out, true
}
func (c *collector) tomcat(rel string) {
	const info = "org/apache/catalina/util/ServerInfo.properties"
	const manifest = "META-INF/MANIFEST.MF"
	entries, ok := c.zipEntries(rel, info, manifest)
	if !ok {
		return
	}
	props := metadataMap(entries[info], "=")
	mf := manifestMap(entries[manifest])
	version := ""
	ev := []model.Evidence{}
	if match := tomcatInfo.FindStringSubmatch(props["server.info"]); len(match) == 2 {
		version = match[1]
		ev = append(ev, evidence(rel+"!/"+info, "server.info", props["server.info"]))
	}
	impl := mf["Implementation-Version"]
	if version == "" && validVersion(impl) && strings.Contains(strings.ToLower(mf["Implementation-Title"]), "tomcat") {
		version = impl
	}
	if version == "" {
		return
	}
	conflict := false
	corroborated := false
	if validVersion(impl) {
		ev = append(ev, evidence(rel+"!/"+manifest, "Implementation-Version", impl))
		if impl != version {
			conflict = true
		} else {
			corroborated = true
		}
	}
	if number := props["server.number"]; validVersion(number) {
		ev = append(ev, evidence(rel+"!/"+info, "server.number", number))
		core := strings.SplitN(version, "-", 2)[0]
		if number != core && number != core+".0" {
			conflict = true
		} else {
			corroborated = true
		}
	}
	confidence := "metadata"
	if corroborated {
		confidence = "corroborated"
	}
	if conflict {
		version = ""
		confidence = "conflicting"
		c.issue("incomplete", rel, "Tomcat product version metadata conflicts")
	}
	install := path.Dir(rel)
	if path.Base(install) == "lib" {
		install = path.Dir(install)
	}
	c.products = append(c.products, product("Apache Tomcat", version, "Apache Software Foundation", "server", install, confidence, ev))
}
func (c *collector) weblogic(rel string) {
	const name = "META-INF/MANIFEST.MF"
	entries, ok := c.zipEntries(rel, name)
	if !ok {
		return
	}
	m := manifestMap(entries[name])
	title := m["Implementation-Title"] + " " + m["Specification-Title"]
	if !strings.Contains(strings.ToLower(title), "weblogic") {
		return
	}
	version := m["Implementation-Version"]
	if !weblogicVersion.MatchString(version) {
		version = m["Specification-Version"]
	}
	if !weblogicVersion.MatchString(version) {
		version = ""
	}
	ev := []model.Evidence{evidence(rel+"!/"+name, "product", "Oracle WebLogic Server")}
	if version != "" {
		ev = append(ev, evidence(rel+"!/"+name, "Implementation-Version", version))
	}
	install := path.Dir(rel)
	if suffix := "/wlserver/server/lib"; strings.HasSuffix("/"+install, suffix) {
		install = strings.TrimSuffix(install, strings.TrimPrefix(suffix, "/"))
		install = strings.TrimSuffix(install, "/")
		if install == "" {
			install = "."
		}
	}
	p := product("Oracle WebLogic Server", version, "Oracle", "server", install, "metadata", ev)
	if version == "" {
		p.Confidence = "unknown"
		c.issue("incomplete", rel, "WebLogic product found but version metadata is unavailable")
	}
	c.products = append(c.products, p)
}
func (c *collector) jboss(rel string) {
	data, ok := c.readIssue(rel, maxMetadata)
	if !ok {
		return
	}
	m := manifestMap(data)
	name := m["JBoss-Product-Release-Name"]
	version := m["JBoss-Product-Release-Version"]
	if name == "" {
		name = m["JBoss-Project-Release-Name"]
		version = m["JBoss-Project-Release-Version"]
	}
	lowered := strings.ToLower(name)
	if !strings.Contains(lowered, "wildfly") && !strings.Contains(lowered, "jboss") {
		return
	}
	if !printable.MatchString(name) {
		return
	}
	if !validVersion(version) {
		c.issue("incomplete", rel, "JBoss/WildFly product version metadata is unavailable")
		version = ""
	}
	prefix, _, _ := strings.Cut(rel, "modules/")
	install := strings.TrimSuffix(prefix, "/")
	if install == "" {
		install = "."
	}
	canonical := "JBoss EAP"
	if strings.Contains(lowered, "wildfly") {
		canonical = "WildFly"
	}
	ev := []model.Evidence{evidence(rel, "product-release-name", name)}
	if version != "" {
		ev = append(ev, evidence(rel, "product-release-version", version))
	}
	c.products = append(c.products, product(canonical, version, "Red Hat", "server", install, "metadata", ev))
}

// Oracle inventory parsers retain component identity and observed patch IDs.
// A PATCH or .patch_storage entry is NOT proof that the running installation has
// a patch applied. PatchState remains unknown pending a qualified vendor parser.
func (c *collector) oracleInventory(rel string) {
	data, ok := c.readIssue(rel, maxMetadata)
	if !ok {
		return
	}
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	depth := 0
	type comp struct {
		name, version string
		patches       []string
	}
	var current *comp
	var items []comp
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.issue("incomplete", rel, "invalid Oracle component inventory XML")
			return
		}
		switch t := tok.(type) {
		case xml.Directive:
			c.issue("incomplete", rel, "XML directives are not allowed in product inventory")
			return
		case xml.StartElement:
			depth++
			if depth > 32 {
				c.issue("incomplete", rel, "Oracle inventory nesting limit exceeded")
				return
			}
			attrs := map[string]string{}
			for _, a := range t.Attr {
				attrs[strings.ToUpper(a.Name.Local)] = a.Value
			}
			if strings.EqualFold(t.Name.Local, "COMP") {
				if current != nil {
					items = append(items, *current)
				}
				current = nil
				n := attrs["NAME"]
				v := attrs["VER"]
				if (n == "oracle.wls" || strings.HasPrefix(n, "oracle.wls.")) && validVersion(v) {
					current = &comp{name: n, version: v}
				}
			}
			if current != nil && (strings.EqualFold(t.Name.Local, "PATCH") || strings.EqualFold(t.Name.Local, "ONEOFF")) {
				id := attrs["ID"]
				if id == "" {
					id = attrs["PATCH_ID"]
				}
				if patchID.MatchString(id) {
					current.patches = append(current.patches, id)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "COMP") && current != nil {
				items = append(items, *current)
				current = nil
			}
			depth--
		}
	}
	if current != nil {
		items = append(items, *current)
	}
	install := strings.TrimSuffix(rel, "inventory/ContentsXML/comps.xml")
	install = strings.TrimSuffix(install, "/")
	if install == "" {
		install = "."
	}
	for _, item := range items {
		ev := []model.Evidence{evidence(rel, "inventory-component", item.name), evidence(rel, "inventory-version", item.version)}
		for _, id := range item.patches {
			ev = append(ev, evidence(rel, "observed-patch-id-not-application-proof", id))
		}
		c.products = append(c.products, product("Oracle WebLogic Server", item.version, "Oracle", "server", install, "inventory-metadata", ev))
	}
}
func (c *collector) mergeInventory() {
	// A product home with contradictory vendor metadata is one unknown
	// installation, not two confidently identified versions. Native artifacts
	// retain their own identity because two shared libraries may share a directory.
	out := []model.Product{}
	index := map[string]int{}
	for _, p := range c.products {
		key := p.ID
		if p.Name == "Oracle WebLogic Server" || p.Name == "JBoss EAP" || p.Name == "WildFly" {
			key = p.Name + "\x00" + p.InstallPath
		}
		if i, ok := index[key]; ok {
			out[i].Evidence = append(out[i].Evidence, p.Evidence...)
			if out[i].Version != p.Version {
				out[i].Version = ""
				out[i].Confidence = "conflicting"
				out[i].ID = product(p.Name, "", p.Vendor, p.Kind, p.InstallPath, "conflicting", nil).ID
				c.issue("incomplete", p.InstallPath, "server product manifest and inventory version evidence conflicts")
			}
		} else {
			index[key] = len(out)
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].InstallPath != out[j].InstallPath {
			return out[i].InstallPath < out[j].InstallPath
		}
		return out[i].ID < out[j].ID
	})
	c.products = out
}
func nativeKind(base string) string {
	switch {
	case base == "sshd" || base == "ssh":
		return "OpenSSH"
	case base == "openssl" || strings.HasPrefix(base, "libssl.so") || strings.HasPrefix(base, "libcrypto.so"):
		return "OpenSSL"
	case phpBasename.MatchString(base) || strings.HasPrefix(base, "libphp") && strings.Contains(base, ".so"):
		return "PHP"
	case base == "node" || base == "nodejs":
		return "Node.js"
	}
	return ""
}

var nativePatterns = map[string]*regexp.Regexp{
	"OpenSSH": regexp.MustCompile(`OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)`),
	"OpenSSL": regexp.MustCompile(`OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?(?:[-+][A-Za-z0-9.]+)?)`),
	"PHP":     regexp.MustCompile(`PHP[ /]([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?)`),
	"Node.js": regexp.MustCompile(`(?:node(?:\.js)?/v?|https://nodejs\.org/(?:download/release|docs)/v)([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?)`),
}

func (c *collector) native(rel, base string) {
	kind := nativeKind(base)
	data, ok := c.readIssue(rel, maxNative)
	if !ok {
		return
	}
	if len(data) < 4 || string(data[:4]) != "\x7fELF" {
		return
	}
	matches := nativePatterns[kind].FindAllSubmatch(data, 256)
	if len(matches) == 256 {
		c.issue("incomplete", rel, "embedded product evidence match limit reached")
		return
	}
	versions := map[string]bool{}
	for _, m := range matches {
		if len(m[1]) > 100 {
			c.issue("incomplete", rel, "embedded product version exceeds evidence limit")
			return
		}
		versions[string(m[1])] = true
	}
	if len(versions) == 0 {
		return
	}
	ev := []model.Evidence{}
	keys := []string{}
	for v := range versions {
		keys = append(keys, v)
	}
	sort.Strings(keys)
	for _, v := range keys {
		ev = append(ev, evidence(rel, "embedded-product-version", v))
	}
	digest := sha256.Sum256(data)
	ev = append(ev, evidence(rel, "sha256", hex.EncodeToString(digest[:])))
	version := ""
	confidence := "embedded-version"
	if len(keys) == 1 {
		version = keys[0]
	} else {
		confidence = "conflicting"
		c.issue("incomplete", rel, "conflicting embedded product version evidence")
	}
	install := path.Dir(rel)
	role := "native"
	if base == "sshd" {
		role = "server"
	} else if base == "ssh" {
		role = "client"
	} else if strings.HasPrefix(base, "lib") {
		role = "native-library"
	} else if kind == "PHP" || kind == "Node.js" {
		role = "runtime"
	}
	ev = append(ev, evidence(rel, "artifact-role", role))
	p := product(kind, version, "", role, install, confidence, ev)
	// A CLI and a shared library with identical version are separate artifacts.
	sum := sha256.Sum256([]byte(p.ID + "\x00" + rel))
	p.ID = "product-" + hex.EncodeToString(sum[:12])
	c.products = append(c.products, p)
}
