package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

const directoryPackageIDPrefix = "SPDXRef-KODA-Directory-"

type directoryEdge struct {
	from, to artifact.ID
	kind     artifact.RelationshipType
}

// DirectoryInventory combines scrubbed observations from independently scanned
// directories. The component key must represent the same versioned package on
// both sides. Unidentified components retain a separate ID per directory.
type DirectoryInventory struct {
	bom   *sbom.SBOM
	edges map[directoryEdge]bool
}

// MergeableDirectoryPackages identifies coordinates before Scrub can remove
// PURL details. A coordinate that needs filtering cannot identify a duplicate.
func MergeableDirectoryPackages(ctx context.Context, inventory *sbom.SBOM, plan localfs.Plan) map[artifact.ID]string {
	var layouts pnpmLayouts
	if root, err := os.OpenRoot(plan.Root); err == nil {
		layouts = readPNPMLayouts(ctx, root, plan)
		root.Close()
	}
	npmGraph := map[artifact.ID]bool{}
	for _, edge := range inventory.Relationships {
		if edge.Type != artifact.DependencyOfRelationship {
			continue
		}
		from, fromPackage := edge.From.(pkg.Package)
		to, toPackage := edge.To.(pkg.Package)
		if fromPackage && toPackage && from.FoundBy == npmPackageCataloger && to.FoundBy == npmPackageCataloger {
			npmGraph[from.ID()] = true
			npmGraph[to.ID()] = true
		}
	}
	identities := map[artifact.ID]string{}
	for _, item := range inventory.Artifacts.Packages.Sorted() {
		if npmGraph[item.ID()] || layouts.isInstalledPackage(item) {
			// These IDs describe an installation, while a PURL identifies
			// the package release shared by potentially different installations.
			continue
		}
		purl, err := packageurl.FromString(item.PURL)
		if err != nil || item.Version == "" || purl.Version != item.Version {
			continue
		}
		canonical := purl.ToString()
		if privacyPURL(item.PURL) == canonical {
			// Keep the supplied spelling as well. Normalization must not
			// merge historically case-sensitive npm coordinates or hide details.
			identities[item.ID()] = string(item.Type) + "\x00" + item.PURL
		}
	}
	return identities
}

func (layouts pnpmLayouts) isInstalledPackage(item pkg.Package) bool {
	if item.FoundBy != npmPackageCataloger {
		return false
	}
	for _, location := range item.Locations.ToSlice() {
		_, hoisted := layouts.hoisted[strings.TrimPrefix(location.RealPath, "/")]
		if hoisted || layouts.instanceModules(location.RealPath, item.Name) != "" {
			return true
		}
	}
	return false
}

func (m *DirectoryInventory) Add(target string, inventory *sbom.SBOM, identities map[artifact.ID]string) {
	if m.bom == nil {
		m.bom = &sbom.SBOM{
			Source: inventory.Source, Descriptor: inventory.Descriptor,
			Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()},
		}
		m.edges = map[directoryEdge]bool{}
	}
	byOldID := map[artifact.ID]pkg.Package{}
	for _, item := range inventory.Artifacts.Packages.Sorted() {
		oldID := item.ID()
		key := identities[oldID]
		if key == "" {
			key = "observation\x00" + target + "\x00" + string(oldID)
		}
		sum := sha256.Sum256([]byte(key))
		item.OverrideID(artifact.ID(directoryPackageIDPrefix + hex.EncodeToString(sum[:16])))
		item.Locations = scopeLocations(item.Locations, target)
		if product, ok := item.Metadata.(model.Product); ok {
			item.Metadata = ScopeProduct(product, target)
		}
		licenses := item.Licenses.ToSlice()
		for i := range licenses {
			licenses[i].Locations = scopeLocations(licenses[i].Locations, target)
		}
		item.Licenses = pkg.NewLicenseSet(licenses...)
		m.bom.Artifacts.Packages.Add(item)
		byOldID[oldID] = item
	}
	for _, edge := range inventory.Relationships {
		from := scopedNode(edge.From, byOldID, target)
		to := scopedNode(edge.To, byOldID, target)
		if from == nil || to == nil || from.ID() == to.ID() {
			continue
		}
		key := directoryEdge{from: from.ID(), to: to.ID(), kind: edge.Type}
		if m.edges[key] {
			continue
		}
		m.edges[key] = true
		edge.From, edge.To = from, to
		m.bom.Relationships = append(m.bom.Relationships, edge)
	}
}

func (m *DirectoryInventory) BOM() *sbom.SBOM { return m.bom }

func ScopeProduct(product model.Product, target string) model.Product {
	if target == "" {
		return product
	}
	product.ID = target + "-" + product.ID
	product.InstallPath = scopedLocation(target, product.InstallPath)
	product.Evidence = slices.Clone(product.Evidence)
	for i := range product.Evidence {
		product.Evidence[i].Path = scopedLocation(target, product.Evidence[i].Path)
	}
	return product
}

func scopedNode(node artifact.Identifiable, packages map[artifact.ID]pkg.Package, target string) artifact.Identifiable {
	switch item := node.(type) {
	case pkg.Package:
		if replacement, ok := packages[item.ID()]; ok {
			return replacement
		}
	case file.Coordinates:
		item.RealPath = scopedLocation(target, item.RealPath)
		return item
	}
	return nil
}

func scopeLocations(locations file.LocationSet, target string) file.LocationSet {
	out := file.NewLocationSet()
	for _, location := range locations.ToSlice() {
		location.RealPath = scopedLocation(target, location.RealPath)
		location.AccessPath = scopedLocation(target, location.AccessPath)
		location.FullPath = scopedLocation(target, location.FullPath)
		out.Add(location)
	}
	return out
}

func scopedLocation(target, name string) string {
	if name == "" {
		return ""
	}
	return target + "/" + strings.TrimPrefix(name, "/")
}
