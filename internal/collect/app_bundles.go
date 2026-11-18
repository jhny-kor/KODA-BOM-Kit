package collect

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

// appBundleCollector records the identity of snap and flatpak installations.
// Syft's snap cataloger lists the Debian packages staged inside a snap, but not
// the snap itself; Syft has no flatpak cataloger.
const appBundleCollector = "koda-app-bundle"

var (
	snapMetaPath    = regexp.MustCompile(`^snap/([a-z0-9][a-z0-9-]{0,63})/([0-9x][0-9]*)/meta/snap\.yaml$`)
	flatpakMetaPath = regexp.MustCompile(`^(.*/)?flatpak/(app|runtime)/([A-Za-z0-9._-]{1,255})/([A-Za-z0-9_-]{1,64})/([A-Za-z0-9._-]{1,128})/([0-9a-f]{64})/metadata$`)
	bundleVersion   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
)

func collectAppBundles(ctx context.Context, inventory *sbom.SBOM, plan localfs.Plan) error {
	root, err := os.OpenRoot(plan.Root)
	if err != nil {
		return nil
	}
	defer root.Close()
	for _, name := range plan.Paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		var entry pkg.Package
		var ok bool
		if m := snapMetaPath.FindStringSubmatch(name); m != nil {
			entry, ok = snapPackage(inventory, root, name, m[1], m[2])
		} else if m := flatpakMetaPath.FindStringSubmatch(name); m != nil {
			entry, ok = flatpakPackage(root, name, m)
		} else {
			continue
		}
		if ok {
			entry.SetID()
			inventory.Artifacts.Packages.Add(entry)
		}
	}
	return nil
}

func readEvidence(root *os.Root, name string) ([]byte, bool) {
	f, _, err := localfs.OpenRegularEvidence(root, name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	return data, err == nil && len(data) <= 1<<20
}

// snapPackage reports the revision that snap/<name>/current selects. Older
// revisions stay mounted for rollback but are not the active software.
func snapPackage(inventory *sbom.SBOM, root *os.Root, name, snap, revision string) (pkg.Package, bool) {
	if current, err := root.Readlink("snap/" + snap + "/current"); err == nil && path.Base(current) != revision {
		return pkg.Package{}, false
	}
	data, ok := readEvidence(root, name)
	if !ok {
		recordAppBundleIssue(inventory, name)
		return pkg.Package{}, false
	}
	fields := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue // only top-level scalar keys
		}
		k, v, found := strings.Cut(line, ":")
		if found {
			fields[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	if fields["name"] != snap || !bundleVersion.MatchString(fields["version"]) {
		return pkg.Package{}, false
	}
	return pkg.Package{
		Name: snap, Version: fields["version"], Type: pkg.BinaryPkg, FoundBy: appBundleCollector,
		PURL:      packageurl.NewPackageURL(packageurl.TypeGeneric, "snap", snap, fields["version"], nil, "").ToString(),
		Locations: file.NewLocationSet(file.NewLocation("/" + name)),
	}, true
}

// flatpakPackage reports the deployment that the branch's "active" link selects.
// The version comes from the AppStream release list when the bundle ships one.
func flatpakPackage(root *os.Root, name string, m []string) (pkg.Package, bool) {
	kind, id, arch, branch, commit := m[2], m[3], m[4], m[5], m[6]
	dir := path.Dir(name)
	if active, err := root.Readlink(path.Join(path.Dir(dir), "active")); err != nil || path.Base(active) != commit {
		return pkg.Package{}, false
	}
	version := ""
	for _, meta := range []string{"files/share/metainfo/" + id + ".metainfo.xml", "files/share/metainfo/" + id + ".appdata.xml", "files/share/appdata/" + id + ".appdata.xml"} {
		if data, ok := readEvidence(root, path.Join(dir, meta)); ok {
			version = appstreamVersion(data)
			break
		}
	}
	qualifiers := packageurl.Qualifiers{{Key: "arch", Value: arch}, {Key: "branch", Value: branch}, {Key: "type", Value: kind}}
	return pkg.Package{
		Name: id, Version: version, Type: pkg.BinaryPkg, FoundBy: appBundleCollector,
		PURL:      packageurl.NewPackageURL(packageurl.TypeGeneric, "flatpak", id, version, qualifiers, "").ToString(),
		Locations: file.NewLocationSet(file.NewLocation("/" + name)),
	}, true
}

// appstreamVersion returns the first <release version="..."> entry, which
// AppStream orders newest first.
func appstreamVersion(data []byte) string {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "release" {
			for _, attr := range start.Attr {
				if attr.Name.Local == "version" && bundleVersion.MatchString(attr.Value) {
					return attr.Value
				}
			}
			return ""
		}
	}
}

func recordAppBundleIssue(inventory *sbom.SBOM, name string) {
	if inventory.Artifacts.Unknowns == nil {
		inventory.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}
	coordinate := file.NewCoordinates(name, "")
	inventory.Artifacts.Unknowns[coordinate] = append(inventory.Artifacts.Unknowns[coordinate], appBundleCollector+": bundle metadata unreadable")
}

// addCondaPURLs fills the PURL that Syft leaves empty for conda-meta packages.
// The package ID is kept so existing relationships stay valid. Only the channel
// name is used: a mirror URL may carry credentials or an internal host name.
func addCondaPURLs(inventory *sbom.SBOM) {
	for _, item := range inventory.Artifacts.Packages.Sorted() {
		meta, ok := item.Metadata.(pkg.CondaMetaPackage)
		if item.Type != pkg.CondaPkg || item.PURL != "" || !ok || item.Version == "" {
			continue
		}
		var qualifiers packageurl.Qualifiers
		for _, q := range [][2]string{{"build", meta.Build}, {"channel", path.Base(strings.TrimRight(meta.Channel, "/"))}, {"subdir", meta.Subdir}} {
			if q[1] != "" && q[1] != "." && bundleVersion.MatchString(q[1]) {
				qualifiers = append(qualifiers, packageurl.Qualifier{Key: q[0], Value: q[1]})
			}
		}
		inventory.Artifacts.Packages.Delete(item.ID())
		item.PURL = packageurl.NewPackageURL("conda", "", item.Name, item.Version, qualifiers, "").ToString()
		inventory.Artifacts.Packages.Add(item)
	}
}
