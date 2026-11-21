package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

const (
	npmPackageCataloger = "javascript-package-cataloger"
	npmDependencySource = "npm-installed-dependencies"
	maxNPMPackageJSON   = 2 << 20
)

var npmDependencyName = regexp.MustCompile(`^(?:@[A-Za-z0-9_~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]*$`)

type npmManifest struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	Optional     map[string]string `json:"optionalDependencies"`
	Peers        map[string]string `json:"peerDependencies"`
	PeerMeta     map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
}

type npmObservation struct {
	item     pkg.Package
	location file.Location
}

func addInstalledNPMDependencies(ctx context.Context, bom *sbom.SBOM, resolver file.Resolver, plan localfs.Plan) error {
	installed := make(map[string]npmObservation)
	var manifests []string
	for _, item := range bom.Artifacts.Packages.Sorted(pkg.NpmPkg) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if item.FoundBy != npmPackageCataloger || item.Name == "" || item.Version == "" {
			continue
		}
		for _, loc := range item.Locations.ToSlice() {
			if loc.FullPath != "" || path.Base(loc.RealPath) != "package.json" ||
				loc.Annotations[pkg.EvidenceAnnotationKey] != pkg.PrimaryEvidenceAnnotation {
				continue
			}
			name := strings.TrimPrefix(loc.RealPath, "/")
			if _, exists := slices.BinarySearch(plan.Paths, name); !exists {
				// Only the canonical regular files admitted by preflight can
				// establish endpoints, even if Syft saw an additional alias.
				continue
			}
			if previous, ok := installed[name]; ok {
				if previous.item.ID() != item.ID() {
					// Different observations from one manifest are ambiguous.
					installed[name] = npmObservation{}
				}
				continue
			}
			installed[name] = npmObservation{item, loc}
			manifests = append(manifests, name)
		}
	}
	if len(manifests) == 0 {
		return ctx.Err()
	}

	// Revalidate both endpoints against the indexed manifest before adding an edge.
	// Keep invalid paths in the index so a nearer unverified copy blocks fallback.
	root, err := plan.OpenRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	layouts := readPNPMLayouts(ctx, root, plan)
	diagnostics := npmDependencyDiagnostics{bom: bom}
	declarations := make(map[string]npmManifest, len(manifests))
	for _, name := range manifests {
		if err := ctx.Err(); err != nil {
			return err
		}
		observation := installed[name]
		if observation.item.ID() == "" {
			continue
		}
		manifest, ok := readNPMManifest(root, plan, name, observation.item)
		if !ok {
			diagnostics.add(observation.location.Coordinates, npmManifestUnreadable, "")
			installed[name] = npmObservation{}
			continue
		}
		if len(manifest.Dependencies) > 0 || len(manifest.Optional) > 0 || len(manifest.Peers) > 0 {
			declarations[name] = manifest
		}
	}

	seen := make(map[[2]artifact.ID]bool)
	for _, edge := range bom.Relationships {
		if edge.Type == artifact.DependencyOfRelationship && edge.From != nil && edge.To != nil {
			seen[[2]artifact.ID{edge.From.ID(), edge.To.ID()}] = true
		}
	}
	for _, name := range manifests {
		manifest, ok := declarations[name]
		if !ok {
			continue
		}
		observation := installed[name]
		item := observation.item
		injectedSource := layouts.isInjectedSource(name, installed)
		dependencies := manifest.installedDependencies()
		for _, nameOfDependency := range slices.Sorted(maps.Keys(dependencies)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !npmDependencyName.MatchString(nameOfDependency) || len(nameOfDependency) > 214 {
				continue
			}
			declaration := dependencies[nameOfDependency]
			var dependency *pkg.Package
			var reason string
			if declaration.peer && injectedSource {
				// A workspace source listed as injected is separate from its
				// copies. Only its own direct providers can establish its peers.
				localModules := path.Join(path.Dir(name), "node_modules", nameOfDependency)
				dependency, reason = npmDependencyAt(resolver, plan, layouts, installed, localModules, nameOfDependency, declaration)
				if reason == npmDependencyMissing {
					continue
				}
			} else {
				dependency, reason = installedNPMDependency(resolver, plan, layouts, installed, name, item, nameOfDependency, declaration)
			}
			if dependency == nil {
				if !declaration.optional || reason != npmDependencyMissing {
					diagnostics.add(observation.location.Coordinates, reason, nameOfDependency)
				}
				continue
			}
			if dependency.ID() == item.ID() {
				continue
			}
			key := [2]artifact.ID{dependency.ID(), item.ID()}
			if !seen[key] {
				seen[key] = true
				bom.Relationships = append(bom.Relationships, artifact.Relationship{
					From: *dependency, To: item, Type: artifact.DependencyOfRelationship,
				})
			}
		}
	}
	diagnostics.finish()
	return ctx.Err()
}

type npmDependency struct {
	spec     string
	peer     bool
	optional bool
}

func (manifest npmManifest) installedDependencies() map[string]npmDependency {
	dependencies := make(map[string]npmDependency, len(manifest.Peers)+len(manifest.Dependencies)+len(manifest.Optional))
	for name, spec := range manifest.Peers {
		dependencies[name] = npmDependency{spec: spec, peer: true, optional: manifest.PeerMeta[name].Optional}
	}
	for name, spec := range manifest.Dependencies {
		dependencies[name] = npmDependency{spec: spec}
	}
	// npm gives optionalDependencies precedence when a name is also a direct dependency.
	for name, spec := range manifest.Optional {
		dependencies[name] = npmDependency{spec: spec, optional: true}
	}
	return dependencies
}

func readNPMManifest(root *os.Root, plan localfs.Plan, name string, item pkg.Package) (manifest npmManifest, ok bool) {
	reader, _, err := plan.OpenIndexedRegular(root, name)
	if err != nil {
		return manifest, false
	}
	defer reader.Close()
	bounded := &io.LimitedReader{R: reader, N: maxNPMPackageJSON + 1}
	decoder := json.NewDecoder(bounded)
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, false
	}
	var extra json.RawMessage
	return manifest, errors.Is(decoder.Decode(&extra), io.EOF) && bounded.N > 0 &&
		manifest.Name == item.Name && manifest.Version == item.Version
}

func installedNPMDependency(resolver file.Resolver, plan localfs.Plan, layouts pnpmLayouts, installed map[string]npmObservation, manifestPath string, consumer pkg.Package, name string, decl npmDependency) (*pkg.Package, string) {
	dir := path.Dir(manifestPath)
	var instanceModules string
	var installedConsumer bool
	var boundVersion string
	if decl.peer {
		instanceModules = layouts.instanceModules(manifestPath, consumer.Name)
		installedConsumer = strings.Contains("/"+manifestPath, "/node_modules/")
		if id, known := layouts.hoisted[manifestPath]; known {
			boundVersion = hoistedPeerVersion(id, consumer.Name, consumer.Version, name)
			if boundVersion == "" {
				return nil, npmDependencyMissing
			}
		}
	}
	for current := dir; ; current = path.Dir(current) {
		if path.Base(current) != "node_modules" {
			modules := path.Join(current, "node_modules")
			dependency, reason := npmDependencyAt(resolver, plan, layouts, installed, path.Join(modules, name), name, decl)
			occupied := dependency != nil || reason != npmDependencyMissing
			if occupied && (installedConsumer && current == dir || instanceModules != "" && modules != instanceModules) {
				// A nearer private copy can shadow a peer provider without being one.
				if dependency != nil {
					reason = npmDependencyPeerShadowed
				}
				return nil, reason
			}
			if occupied || modules == instanceModules {
				// In pnpm's virtual store the explicit sibling proves the binding;
				// farther hoisted packages do not fill an empty peer slot.
				if dependency != nil && boundVersion != "" && dependency.Version != boundVersion {
					return nil, npmDependencyVersionMismatch
				}
				return dependency, reason
			}
		}
		if current == "." {
			return nil, npmDependencyMissing
		}
	}
}

// A candidate other than a missing one shadows higher copies even if it
// cannot establish an edge.
func npmDependencyAt(resolver file.Resolver, plan localfs.Plan, layouts pnpmLayouts, installed map[string]npmObservation, packageDir, name string, decl npmDependency) (*pkg.Package, string) {
	if plan.ExcludesPath(path.Join(packageDir, "package.json")) {
		return nil, npmDependencyScopeBlocked
	}
	dir, leafLink, err := plan.ResolveIndexedPath(packageDir)
	if err != nil {
		return nil, npmDependencyScopeBlocked
	}
	canonical, manifestLink, err := plan.ResolveIndexedPath(path.Join(dir, "package.json"))
	if err != nil {
		return nil, npmDependencyScopeBlocked
	}
	if found, ok := installed[canonical]; ok {
		if found.item.ID() == "" {
			return nil, npmManifestUnreadable
		}
		if found.item.Name != name {
			return nil, npmDependencyIdentityMismatch
		}
		if matchesInstalledNPMVersion(decl.spec, found.item.Version) || !decl.peer &&
			layouts.matchesDeployFile(decl.spec, name, canonical, leafLink) {
			return &found.item, ""
		}
		if !supportedNPMVersion(decl.spec) {
			return nil, npmDependencyUnsupported
		}
		return nil, npmDependencyVersionMismatch
	}
	if leafLink || manifestLink || resolver.HasPath("/"+dir) {
		return nil, npmManifestUnreadable
	}
	return nil, npmDependencyMissing
}

// Use the physical location as pnpm's instance identity, including when the
// directory name for a peer context is shortened or hashed.
func (layouts pnpmLayouts) instanceModules(manifestPath, name string) string {
	instance, ok := strings.CutSuffix(strings.TrimPrefix(manifestPath, "/"), "/node_modules/"+name+"/package.json")
	store := path.Dir(instance)
	if !ok || !(layouts.stores[store] || path.Base(store) == ".pnpm") {
		return ""
	}
	return path.Join(instance, "node_modules")
}

// pnpm deploy may write name@file:///original/checkout for an injected
// workspace package. The live link and copied manifest are the evidence.
// The original checkout URI is never used to locate or read any file.
func (layouts pnpmLayouts) matchesDeployFile(spec, name, canonical string, leafLink bool) bool {
	spec = strings.TrimSpace(spec)
	ref, ok := strings.CutPrefix(spec, name+"@")
	if !ok || len(ref) > 8192 || !strings.HasPrefix(ref, "file:///") {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || !path.IsAbs(u.Path) || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	if layouts.hoisted[canonical] == spec {
		return true
	}
	modules := layouts.instanceModules(canonical, name)
	instance := path.Dir(modules)
	store := path.Dir(instance)
	return leafLink && modules != "" && (layouts.stores[store] || path.Base(path.Dir(store)) == "node_modules") &&
		strings.HasPrefix(path.Base(instance), strings.ReplaceAll(name, "/", "+")+"@file+")
}

func supportedNPMVersion(spec string) bool {
	spec = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(spec), "workspace:"))
	if spec == "^" || spec == "~" {
		return true
	}
	if len(spec) == 0 || len(spec) > 256 || strings.ContainsAny(spec, "!,") {
		return false
	}
	_, err := semver.NewConstraint(spec)
	return err == nil
}

// pnpm deploy can preserve workspace selectors even when it materializes the
// package under its own node_modules. Only an already resolved package can
// satisfy the workspace wildcard and shorthand selectors.
func matchesInstalledNPMVersion(spec, installed string) bool {
	if workspace, ok := strings.CutPrefix(strings.TrimSpace(spec), "workspace:"); ok {
		switch workspace {
		case "*", "^", "~":
			_, err := semver.StrictNewVersion(installed)
			return err == nil
		default:
			spec = workspace
		}
	}
	return matchesNPMVersion(spec, installed)
}

func matchesNPMVersion(spec, installed string) bool {
	version, err := semver.StrictNewVersion(installed)
	if err != nil {
		return false
	}
	spec = strings.TrimSpace(spec)
	if len(spec) == 0 || len(spec) > 256 {
		return false
	}
	if exact, err := semver.StrictNewVersion(strings.TrimPrefix(spec, "=")); err == nil {
		return version.Equal(exact)
	}
	// Keep the supported range syntax to npm's ordinary stable SemVer ranges.
	// Tags, aliases, URLs and local paths lack proof here. Prereleases
	// require an exact declaration.
	if version.Prerelease() != "" || strings.ContainsAny(spec, "!,") {
		return false
	}
	constraint, err := semver.NewConstraint(spec)
	return err == nil && constraint.Check(version)
}
