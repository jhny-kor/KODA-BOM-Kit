package collect

import (
	"net/url"
	"path"
	"reflect"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// ScrubMetadata removes personal contacts, credentials in metadata URLs, raw
// configuration/content, and source-root absolute paths before any encoder runs.
// Package IDs are deliberately retained so the dependency graph remains valid.
// Collection.Package returns a copy; rebuilding the collection is required to
// persist edited metadata rather than modifying an ephemeral package copy.
func ScrubMetadata(s *sbom.SBOM) {
	if s == nil {
		return
	}
	root := ""
	switch m := s.Source.Metadata.(type) {
	case source.DirectoryMetadata:
		root = m.Path
		s.Source.Metadata = source.DirectoryMetadata{Path: "."}
	case *source.DirectoryMetadata:
		if m != nil {
			root = m.Path
		}
		s.Source.Metadata = source.DirectoryMetadata{Path: "."}
	case source.FileMetadata:
		root = path.Dir(m.Path)
		m.Path = path.Base(m.Path)
		s.Source.Metadata = m
	case source.ImageMetadata:
		m.UserInput = "local-image-archive"
		m.RawConfig = nil
		m.RawManifest = nil
		m.Labels = nil
		m.Annotations = nil
		m.Tags = privacyStrings(m.Tags, "url", root)
		m.RepoDigests = privacyStrings(m.RepoDigests, "url", root)
		s.Source.Metadata = m
	}
	if strings.HasPrefix(s.Source.Name, "/") || strings.Contains(s.Source.Name, "://") {
		s.Source.Name = "local-filesystem"
	}
	s.Artifacts.FileContents = nil
	s.Descriptor.Configuration = privacyMetadata(s.Descriptor.Configuration, root)
	if s.Artifacts.Packages != nil {
		clean := pkg.NewCollection()
		byID := map[artifact.ID]pkg.Package{}
		for _, p := range s.Artifacts.Packages.Sorted() {
			// Keep only product identities assigned by the explicit AIX evidence mapper.
			cpes := p.CPEs
			p.CPEs = nil
			if p.FoundBy == AIXOracleCollector {
				for _, candidate := range cpes {
					if candidate.Source == oracleInventoryCPESource {
						p.CPEs = append(p.CPEs, candidate)
					}
				}
			}
			p.PURL = privacyPURL(p.PURL)
			p.Locations = privacyLocations(p.Locations, root)
			p.Metadata = privacyMetadata(p.Metadata, root)
			licenses := []pkg.License{}
			for _, license := range p.Licenses.ToSlice() {
				license.Contents = ""
				license.URLs = privacyStrings(license.URLs, "url", root)
				license.Locations = privacyLocations(license.Locations, root)
				licenses = append(licenses, license)
			}
			p.Licenses = pkg.NewLicenseSet(licenses...)
			clean.Add(p)
			byID[p.ID()] = p
		}
		s.Artifacts.Packages = clean
		for i := range s.Relationships {
			r := &s.Relationships[i]
			if r.From != nil {
				if p, ok := byID[r.From.ID()]; ok {
					r.From = p
				} else if c, ok := r.From.(file.Coordinates); ok {
					c.RealPath = privacyPath(c.RealPath, root)
					r.From = c
				}
			}
			if r.To != nil {
				if p, ok := byID[r.To.ID()]; ok {
					r.To = p
				} else if c, ok := r.To.(file.Coordinates); ok {
					c.RealPath = privacyPath(c.RealPath, root)
					r.To = c
				}
			}
			r.Data = privacyMetadata(r.Data, root)
		}
	}
	if s.Artifacts.FileMetadata != nil {
		mapped := make(map[file.Coordinates]file.Metadata, len(s.Artifacts.FileMetadata))
		for c, m := range s.Artifacts.FileMetadata {
			c.RealPath = privacyPath(c.RealPath, root)
			m.Path = privacyPath(m.Path, root)
			m.LinkDestination = privacyPath(m.LinkDestination, root)
			mapped[c] = m
		}
		s.Artifacts.FileMetadata = mapped
	}
	if s.Artifacts.FileDigests != nil {
		mapped := make(map[file.Coordinates][]file.Digest, len(s.Artifacts.FileDigests))
		for c, v := range s.Artifacts.FileDigests {
			c.RealPath = privacyPath(c.RealPath, root)
			mapped[c] = v
		}
		s.Artifacts.FileDigests = mapped
	}
	if s.Artifacts.Executables != nil {
		mapped := make(map[file.Coordinates]file.Executable, len(s.Artifacts.Executables))
		for c, v := range s.Artifacts.Executables {
			c.RealPath = privacyPath(c.RealPath, root)
			v.ImportedLibraries = privacyStrings(v.ImportedLibraries, "path", root)
			mapped[c] = v
		}
		s.Artifacts.Executables = mapped
	}
	// No arbitrary file content or free-form file-license evidence is exported.
	s.Artifacts.FileLicenses = nil
	if s.Artifacts.Unknowns != nil {
		mapped := make(map[file.Coordinates][]string, len(s.Artifacts.Unknowns))
		for c, v := range s.Artifacts.Unknowns {
			c.RealPath = privacyPath(c.RealPath, root)
			mapped[c] = privacyStrings(v, "path", root)
		}
		s.Artifacts.Unknowns = mapped
	}
}

func privacyMetadata(value any, root string) any {
	if value == nil {
		return nil
	}
	switch m := value.(type) {
	case pkg.GolangBinaryBuildinfoEntry:
		// Keep identity evidence and omit free-form build settings and symbols.
		return pkg.GolangBinaryBuildinfoEntry{
			GoCompiledVersion: m.GoCompiledVersion, Architecture: m.Architecture,
			H1Digest: m.H1Digest, MainModule: privacyText(m.MainModule, "modulePath", root),
		}
	case pkg.DotnetDepsEntry:
		return pkg.DotnetDepsEntry{Name: m.Name, Version: m.Version, Type: m.Type}
	case pkg.DotnetPortableExecutableEntry:
		return pkg.DotnetPortableExecutableEntry{
			AssemblyVersion: m.AssemblyVersion, ProductVersion: m.ProductVersion, ProductName: m.ProductName,
		}
	case pkg.RubyGemspec:
		return pkg.RubyGemspec{Name: m.Name, Version: m.Version, Homepage: privacyURL(m.Homepage)}
	case pkg.JavaArchive:
		m.VirtualPath = privacyPath(m.VirtualPath, root)
		m.Parent = nil
		if m.Manifest != nil {
			main := pkg.KeyValues{}
			for _, kv := range m.Manifest.Main {
				switch strings.ToLower(kv.Key) {
				case "manifest-version", "implementation-title", "implementation-version", "implementation-vendor", "specification-title", "specification-version", "specification-vendor", "bundle-name", "bundle-symbolicname", "bundle-version", "bundle-vendor", "automatic-module-name":
					kv.Value = privacyText(kv.Value, kv.Key, root)
					main = append(main, kv)
				}
			}
			m.Manifest = &pkg.JavaManifest{Main: main}
		}
		if m.PomProperties != nil {
			p := *m.PomProperties
			p.Extra = nil
			p.Path = privacyPath(p.Path, root)
			m.PomProperties = &p
		}
		if m.PomProject != nil {
			p := *m.PomProject
			p.Description = ""
			p.URL = privacyURL(p.URL)
			p.Path = privacyPath(p.Path, root)
			m.PomProject = &p
		}
		return m
	case *pkg.JavaArchive:
		if m == nil {
			return (*pkg.JavaArchive)(nil)
		}
		clean := privacyMetadata(*m, root).(pkg.JavaArchive)
		return &clean
	}
	v := privacyClone(reflect.ValueOf(value), "", root, 0)
	if !v.IsValid() {
		return nil
	}
	return v.Interface()
}
func privacyName(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, name)
}
func privacyDrop(name string) bool {
	n := privacyName(name)
	switch n {
	case "author", "authors", "authoremail", "maintainer", "maintainers", "contributor", "contributors", "email", "emails", "contact", "contacts", "packager", "username", "groupname", "builduser", "buildhost", "buildinfo", "description", "summary", "copyright", "rawconfig", "rawmanifest", "environment", "env", "credentials", "credential", "password", "passwd", "secret", "token", "apikey", "accesskey", "privatekey", "authorization", "cookie", "annotations", "labels":
		return true
	}
	return strings.Contains(n, "password") || strings.Contains(n, "secret") || strings.Contains(n, "token") || strings.Contains(n, "credential")
}
func privacyClone(v reflect.Value, field, root string, depth int) reflect.Value {
	if !v.IsValid() {
		return v
	}
	if depth > 16 {
		return reflect.Zero(v.Type())
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		inner := privacyClone(v.Elem(), field, root, depth+1)
		out := reflect.New(v.Type()).Elem()
		if inner.IsValid() {
			out.Set(inner)
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(privacyClone(v.Elem(), field, root, depth+1))
		return out
	case reflect.Struct:
		// Preserve structs with unexported representation (e.g. time.Time) as values.
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if f.PkgPath != "" || !out.Field(i).CanSet() {
				continue
			}
			if privacyDrop(f.Name) {
				out.Field(i).Set(reflect.Zero(f.Type))
				continue
			}
			out.Field(i).Set(privacyClone(v.Field(i), f.Name, root, depth+1))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(privacyClone(v.Index(i), field, root, depth+1))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(privacyClone(v.Index(i), field, root, depth+1))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			k := iter.Key()
			name := field
			if k.Kind() == reflect.String {
				name = k.String()
				if privacyDrop(name) {
					continue
				}
			}
			out.SetMapIndex(k, privacyClone(iter.Value(), name, root, depth+1))
		}
		return out
	case reflect.String:
		out := reflect.New(v.Type()).Elem()
		out.SetString(privacyText(v.String(), field, root))
		return out
	default:
		return v
	}
}
func privacyText(value, field, root string) string {
	n := privacyName(field)
	if n == "purl" {
		return privacyPURL(value)
	}
	if strings.Contains(n, "path") || n == "files" || n == "bindirectory" || n == "directory" {
		return privacyPath(value, root)
	}
	isURL := strings.Contains(n, "url") || strings.Contains(n, "uri") || n == "homepage" || n == "resolved" || n == "repository" || strings.HasSuffix(n, "repo")
	if isURL || strings.Contains(value, "://") || strings.HasPrefix(value, "git@") {
		return privacyURL(value)
	}
	return value
}
func privacyStrings(values []string, field, root string) []string {
	if values == nil {
		return nil
	}
	out := []string{}
	for _, v := range values {
		v = privacyText(v, field, root)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func privacyPath(value, root string) string {
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	root = strings.TrimSuffix(strings.ReplaceAll(root, "\\", "/"), "/")
	if root != "" && root != "." && (value == root || strings.HasPrefix(value, root+"/")) {
		value = strings.TrimPrefix(value, root)
		value = strings.TrimPrefix(value, "/")
	}
	value = strings.TrimPrefix(value, "/")
	value = path.Clean(value)
	if value == ".." || strings.HasPrefix(value, "../") {
		return "outside-root"
	}
	return value
}
func privacyLocations(in file.LocationSet, root string) file.LocationSet {
	out := file.NewLocationSet()
	for _, l := range in.ToSlice() {
		l.RealPath = privacyPath(l.RealPath, root)
		l.AccessPath = privacyPath(l.AccessPath, root)
		l.FullPath = privacyPath(l.FullPath, root)
		l.Annotations = nil
		out.Add(l)
	}
	return out
}
func privacyURL(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "git@") {
		if host, p, ok := strings.Cut(strings.TrimPrefix(raw, "git@"), ":"); ok {
			raw = "ssh://" + host + "/" + p
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ssh", "git", "git+https", "git+ssh", "ftp", "ftps":
	default:
		return ""
	}
	if u.Host == "" || u.Opaque != "" {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}
func privacyPURL(raw string) string {
	if raw == "" {
		return ""
	}
	p, err := packageurl.FromString(raw)
	if err != nil {
		return ""
	}
	qualifiers := packageurl.Qualifiers{}
	for _, q := range p.Qualifiers {
		if privacyDrop(q.Key) {
			continue
		}
		switch strings.ToLower(q.Key) {
		case "repository_url", "download_url", "vcs_url":
			q.Value = privacyURL(q.Value)
			if q.Value == "" {
				continue
			}
		case "arch", "epoch", "distro", "distro_id", "distro_version_id", "upstream", "os", "libc", "type", "classifier", "extension":
		default:
			continue // Do not carry arbitrary registry tokens or personal qualifiers.
		}
		qualifiers = append(qualifiers, q)
	}
	p.Qualifiers = qualifiers
	p.Subpath = privacyPath(p.Subpath, "")
	if p.Subpath == "." {
		p.Subpath = ""
	}
	return p.ToString()
}
