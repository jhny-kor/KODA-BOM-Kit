package collect

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/staticjs"
)

const (
	javaArchiveCataloger = "java-archive-cataloger"
	javaDeploymentSource = "java-deployment-evidence"
	javaSPDXIDPrefix     = "SPDXRef-KODA-Java-"
	javaArchiveDepth     = 4
	javaNestedSize       = 64 << 20
	javaInflationBudget  = 256 << 20
	javaHashBudget       = 256 << 20
	javaIndexBudget      = 12_000
	javaMetadataBudget   = 96 << 20
	javaDirectoryBudget  = 300_000
)

type javaOccurrence struct {
	item           pkg.Package
	dependencies   []javaDependency
	parent         string
	onClasspath    bool
	confirmedMaven bool
}

type javaClasspathPackage struct {
	item      pkg.Package
	version   string
	confirmed bool
}

type javaDeployment struct {
	ctx              context.Context
	bom              *sbom.SBOM
	byPath           map[string][]pkg.Package
	updated          map[artifact.ID]pkg.Package
	observed         map[string]javaOccurrence
	inflation        int64
	metadataBytes    int64
	hashBytes        int64
	indexes          int
	directoryEntries int
	limitHit         bool
}

//go:embed java_deployment_fingerprints.tsv
var javaFingerprintEntries string

var javaFingerprints = func() map[int64]map[string]string {
	out := map[int64]map[string]string{}
	for line := range strings.Lines(javaFingerprintEntries) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			panic("invalid Java deployment fingerprint")
		}
		size, err := strconv.ParseInt(fields[0], 10, 64)
		_, digestErr := hex.DecodeString(fields[1])
		purl, purlErr := packageurl.FromString(fields[2])
		if err != nil || size <= 0 || digestErr != nil || len(fields[1]) != 64 ||
			purlErr != nil || purl.Type != packageurl.TypeMaven || purl.Namespace == "" || purl.Version == "" {
			panic("invalid Java deployment fingerprint")
		}
		if out[size] == nil {
			out[size] = map[string]string{}
		}
		if _, exists := out[size][fields[1]]; exists {
			panic("duplicate Java deployment fingerprint")
		}
		out[size][fields[1]] = fields[2]
	}
	return out
}()

func collectJavaDeployments(ctx context.Context, bom *sbom.SBOM, plan localfs.Plan) {
	collector := javaDeployment{
		ctx: ctx, bom: bom, byPath: map[string][]pkg.Package{},
		updated: map[artifact.ID]pkg.Package{}, observed: map[string]javaOccurrence{},
	}
	for _, item := range bom.Artifacts.Packages.Sorted(pkg.JavaPkg, pkg.JenkinsPluginPkg) {
		if item.FoundBy != javaArchiveCataloger {
			continue
		}
		locations := file.NewLocationSet()
		oldID := item.ID()
		for _, loc := range item.Locations.ToSlice() {
			occurrence := javaLocationPath(loc)
			loc.RealPath, loc.FullPath = privacyPath(loc.RealPath, plan.Root), ""
			loc.AccessPath = privacyPath(occurrence, plan.Root)
			if loc.AccessPath != loc.RealPath {
				loc.FullPath = loc.AccessPath
			}
			locations.Add(loc)
		}
		item.Locations = locations
		item.OverrideID(artifact.ID(javaSPDXIDPrefix + string(oldID)))
		collector.updated[oldID] = item
		for _, loc := range item.Locations.ToSlice() {
			collector.byPath[loc.FullNestedPath()] = append(collector.byPath[loc.FullNestedPath()], item)
		}
	}

	var root *os.Root
	for _, rel := range plan.Paths {
		if ctx.Err() != nil || collector.limitHit {
			break
		}
		switch kind := strings.ToLower(path.Ext(rel)); kind {
		case ".war", ".ear", ".jar":
			if root == nil {
				var err error
				root, err = plan.OpenRoot()
				if err != nil {
					collector.issue(rel, "Java evidence root could not be opened")
					break
				}
				defer root.Close()
			}
			collector.scanRoot(root, plan, rel, kind)
		}
	}
	collector.finish()
}

// javaLocationPath recognizes both Syft 1.57's legacy colon chain and its
// structured nested ZIP locations. Cut the exact outer path first.
func javaLocationPath(loc file.Location) string {
	outer := strings.TrimPrefix(loc.RealPath, "/")
	if loc.FullPath != "" {
		return strings.TrimPrefix(loc.FullPath, "/")
	}
	chain, found := strings.CutPrefix(strings.TrimPrefix(loc.AccessPath, "/"), outer+":")
	if !found {
		return outer
	}
	entries := strings.Split(chain, ":")
	for i := range entries {
		entries[i] = strings.NewReplacer("%3A", ":", "%25", "%").Replace(entries[i])
		if !safeJavaArchivePath(entries[i]) {
			return outer
		}
	}
	return outer + "!/" + strings.Join(entries, "!/")
}

type javaContextReader struct {
	context.Context
	io.ReaderAt
}

func (r javaContextReader) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.ReaderAt.ReadAt(p, offset)
}

func (c *javaDeployment) scanRoot(root *os.Root, plan localfs.Plan, name, kind string) {
	f, info, err := plan.OpenIndexedRegular(root, name)
	if err != nil {
		c.issue(name, "Java archive could not be opened")
		return
	}
	defer f.Close()
	c.scan(f, info.Size(), name, kind, "", false, 1)
}

func (c *javaDeployment) scan(r io.ReaderAt, size int64, name, kind, parent string, classpath bool, depth int) {
	if c.ctx.Err() != nil || c.limitHit {
		return
	}
	if c.indexes >= javaIndexBudget || c.inflation >= javaInflationBudget {
		c.limitHit = true
		c.issue(name, "Java deployment archive inspection reached its total resource limit")
		return
	}
	if depth > javaArchiveDepth {
		c.issue(name, "Java deployment archive nesting exceeds the inspection limit")
		return
	}
	c.indexes++
	r = javaContextReader{c.ctx, r}
	z, err := staticjs.ReadDeploymentZIP(c.ctx, r, size)
	if err != nil {
		c.issue(name, "Java archive ZIP directory could not be read within collection limits")
		return
	}
	c.directoryEntries += len(z.File)
	if c.directoryEntries > javaDirectoryBudget {
		c.limitHit = true
		c.issue(name, "Java archive inspection reached its total directory entry limit")
		return
	}
	entries := make(map[string]*zip.File)
	for _, entry := range z.File {
		if !entry.Mode().IsRegular() {
			continue
		}
		if !safeJavaArchivePath(entry.Name) {
			c.issue(name, "Java archive contains an unsafe entry path")
			return
		}
		if !javaMetadataEntry(entry.Name) && !isJavaPackageEntry(kind, entry.Name) {
			continue
		}
		if _, exists := entries[entry.Name]; exists {
			c.issue(name, "Java archive contains an ambiguous duplicate entry")
			return
		}
		entries[entry.Name] = entry
	}
	var fingerprint, sha string
	if matches := javaFingerprints[size]; kind == ".jar" && len(matches) > 0 {
		sha = c.archiveDigest(r, size)
		fingerprint = matches[sha]
	}
	pom := c.readJavaMetadata(entries, name)
	libraries := make([]string, 0)
	for entry := range entries {
		if kind == ".ear" && strings.EqualFold(path.Ext(entry), ".war") ||
			isJavaDeploymentLibrary(kind, entry, pom.earLib) {
			libraries = append(libraries, entry)
		}
	}
	slices.Sort(libraries)
	// Simple WAR/EARs with no libraries or identity don't need a graph node.
	if kind == ".jar" || parent != "" || len(libraries) > 0 || pom.identity.purl() != "" {
		c.observe(name, parent, classpath, pom, fingerprint, sha, r, size)
	}
	for _, nested := range libraries {
		if c.ctx.Err() != nil || c.limitHit {
			return
		}
		entry := entries[nested]
		fullName := name + "!/" + nested
		if len(fullName) > 4096 || entry.UncompressedSize64 > javaNestedSize {
			c.issue(fullName, "nested Java archive exceeds the inspection limit")
			continue
		}
		reader, err := c.nestedReader(r, size, entry)
		if err != nil {
			c.issue(fullName, "nested Java archive could not be read within collection limits")
			continue
		}
		c.scan(reader, int64(entry.UncompressedSize64), fullName, strings.ToLower(path.Ext(nested)), name, true, depth+1)
	}
}

func (c *javaDeployment) archiveDigest(reader io.ReaderAt, size int64) string {
	if size > javaHashBudget-c.hashBytes {
		return ""
	}
	hasher := sha256.New()
	section := io.NewSectionReader(reader, 0, size)
	var buffer [32 << 10]byte
	for c.ctx.Err() == nil {
		n, err := section.Read(buffer[:])
		c.hashBytes += int64(n)
		hasher.Write(buffer[:n])
		if err == io.EOF {
			return hex.EncodeToString(hasher.Sum(nil))
		}
		if err != nil {
			break
		}
	}
	return ""
}

func (c *javaDeployment) nestedReader(parent io.ReaderAt, size int64, entry *zip.File) (io.ReaderAt, error) {
	length := int64(entry.UncompressedSize64)
	if entry.Method == zip.Store {
		offset, err := entry.DataOffset()
		if err != nil || offset < 0 || offset > size || length > size-offset ||
			entry.CompressedSize64 != entry.UncompressedSize64 {
			return nil, zip.ErrFormat
		}
		return io.NewSectionReader(parent, offset, length), nil
	}
	if length >= javaInflationBudget-c.inflation {
		c.limitHit = true
		return nil, fmt.Errorf("Java archive inflation limit")
	}
	data, err := readJavaZIPEntry(entry, length)
	c.inflation += int64(len(data))
	if err != nil || int64(len(data)) != length {
		return nil, zip.ErrFormat
	}
	return bytes.NewReader(data), nil
}

func isJavaPackageEntry(kind, name string) bool {
	ext := strings.ToLower(path.Ext(name))
	if kind == ".ear" {
		return ext == ".jar" || ext == ".war"
	}
	return isJavaDeploymentLibrary(kind, name, "")
}

func isJavaDeploymentLibrary(kind, name, earLib string) bool {
	if !strings.EqualFold(path.Ext(name), ".jar") {
		return false
	}
	switch kind {
	case ".war":
		return path.Dir(name) == "WEB-INF/lib" || path.Dir(name) == "WEB-INF/lib-provided"
	case ".jar":
		return path.Dir(name) == "BOOT-INF/lib"
	case ".ear":
		return earLib != "" && path.Dir(name) == earLib
	}
	return false
}

func safeJavaArchivePath(name string) bool {
	return len(name) <= 4096 && name != "" && name != "." && name != ".." &&
		!path.IsAbs(name) && path.Clean(name) == name && !strings.HasPrefix(name, "../") &&
		utf8.ValidString(name) && !strings.Contains(name, "!/") && !strings.ContainsRune(name, '\\') &&
		strings.IndexFunc(name, unicode.IsControl) < 0
}

func (c *javaDeployment) issue(path, message string) {
	if c.bom.Artifacts.Unknowns == nil {
		c.bom.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}
	coord := file.NewCoordinates(path, "")
	c.bom.Artifacts.Unknowns[coord] = append(c.bom.Artifacts.Unknowns[coord], javaDeploymentSource+": "+message)
}

func (c *javaDeployment) observe(name, parent string, classpath bool, metadata javaMetadata, fingerprint, digest string, r io.ReaderAt, size int64) {
	var preferred pkg.Package
	original := c.byPath[name]

	for _, item := range original {
		m, _ := item.Metadata.(pkg.JavaArchive)
		if m.Manifest != nil || len(m.ArchiveDigests) > 0 {
			preferred = item
			break
		}
	}
	if preferred.ID() == "" && len(original) > 0 {
		preferred = original[0]
	}
	identity := metadata.identity.purl()
	if fingerprint != "" {
		identity = fingerprint
	}
	if identity != "" {
		for _, item := range original {
			if item.PURL == identity {
				preferred = item
				break
			}
		}
	}
	if preferred.ID() == "" {
		outer, _, _ := strings.Cut(name, "!/")
		loc := file.NewLocation(outer)
		if name != outer {
			loc.FullPath, loc.AccessPath = name, name
		}
		preferred = pkg.Package{
			Name: path.Base(name), Type: pkg.JavaPkg, Language: pkg.Java,
			FoundBy: javaArchiveCataloger, Locations: file.NewLocationSet(loc),
		}
		preferred.SetID()
		preferred.OverrideID(artifact.ID(javaSPDXIDPrefix + string(preferred.ID())))
	}
	preferredMeta, _ := preferred.Metadata.(pkg.JavaArchive)
	preferredMeta.VirtualPath = name
	if digest == "" && len(preferredMeta.ArchiveDigests) == 0 {
		digest = c.archiveDigest(r, size)
	}
	if digest != "" {
		preferredMeta.ArchiveDigests = append(slices.Clone(preferredMeta.ArchiveDigests),
			file.Digest{Algorithm: "sha256", Value: digest})
	}
	if identity != "" {
		id, _ := packageurl.FromString(identity)
		preferred.Name, preferred.Version, preferred.PURL = id.Name, id.Version, identity
	} else if metadata.version != "" && metadata.version != preferred.Version {
		// A build version in the archive wins over a renamed filename.
		preferred.Version, preferred.PURL = metadata.version, ""
	} else if preferred.Version == "" {
		preferred.PURL = ""
	}
	preferred.Metadata = preferredMeta

	// One embedded identity can replace a filename-only duplicate. Preserve
	// separately identified shaded components when more than one is present.
	for _, item := range original {
		oldID := artifact.ID(strings.TrimPrefix(string(item.ID()), javaSPDXIDPrefix))
		if item.ID() == preferred.ID() {
			c.updated[oldID] = preferred
		} else if identity != "" && metadata.unique {
			oldMeta, _ := item.Metadata.(pkg.JavaArchive)
			if item.PURL == identity || oldMeta.PomProperties == nil && oldMeta.PomProject == nil {
				c.updated[oldID] = preferred
			}
		}
	}
	c.observed[name] = javaOccurrence{
		item: preferred, dependencies: metadata.dependencies, parent: parent,
		onClasspath: classpath, confirmedMaven: identity != "",
	}
}

func (c *javaDeployment) finish() {
	if len(c.updated) == 0 && len(c.observed) == 0 {
		return
	}
	packages := pkg.NewCollection()
	for _, item := range c.bom.Artifacts.Packages.Sorted() {
		if updated, ok := c.updated[item.ID()]; ok {
			item = updated
		}
		packages.Add(item)
	}
	paths := make([]string, 0, len(c.observed))
	for name := range c.observed {
		paths = append(paths, name)
	}
	slices.Sort(paths)
	for _, name := range paths {
		packages.Add(c.observed[name].item)
	}
	c.bom.Artifacts.Packages = packages

	relationships := c.bom.Relationships[:0]
	seen := map[directoryEdge]bool{}
	add := func(edge artifact.Relationship) {
		if edge.From == nil || edge.To == nil || edge.From.ID() == edge.To.ID() {
			return
		}
		key := directoryEdge{from: edge.From.ID(), to: edge.To.ID(), kind: edge.Type}
		if !seen[key] {
			relationships = append(relationships, edge)
			seen[key] = true
		}
	}
	for _, edge := range c.bom.Relationships {
		if edge.From == nil || edge.To == nil {
			continue
		}
		if item, ok := c.updated[edge.From.ID()]; ok {
			edge.From = item
		}
		if item, ok := c.updated[edge.To.ID()]; ok {
			edge.To = item
		}
		add(edge)
	}

	// Resolve POM declarations against physically packaged sibling JARs.
	classpaths := map[string]map[[2]string][]javaClasspathPackage{}
	for _, name := range paths {
		child := c.observed[name]
		parent, ok := c.observed[child.parent]
		if !ok || !child.onClasspath {
			continue
		}
		add(artifact.Relationship{From: child.item, To: parent.item, Type: artifact.DependencyOfRelationship})
		add(artifact.Relationship{From: parent.item, To: child.item, Type: artifact.ContainsRelationship})
		if !strings.EqualFold(path.Ext(name), ".jar") || child.item.PURL == "" {
			continue
		}
		purl, err := packageurl.FromString(child.item.PURL)
		if err != nil || purl.Type != packageurl.TypeMaven || purl.Version == "" {
			continue
		}
		index := classpaths[child.parent]
		if index == nil {
			index = map[[2]string][]javaClasspathPackage{}
			classpaths[child.parent] = index
		}
		key := [2]string{purl.Namespace, purl.Name}
		index[key] = append(index[key], javaClasspathPackage{child.item, purl.Version, child.confirmedMaven})
	}
	for _, name := range paths {
		owner := c.observed[name]
		for _, dependency := range owner.dependencies {
			key := [2]string{dependency.coordinate.Group, dependency.coordinate.Artifact}
			if target := dependency.uniqueTarget(classpaths[owner.parent][key]); target != nil {
				add(artifact.Relationship{From: *target, To: owner.item, Type: artifact.DependencyOfRelationship})
			}
		}
	}
	// Preserve original relationship semantics and add only deduplicated ones.
	c.bom.Relationships = relationships
}
