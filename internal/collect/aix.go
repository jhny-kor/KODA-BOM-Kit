package collect

import (
	"crypto/sha256"
	"fmt"
	"path"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"koda.local/security-sbom-linux/internal/aixevidence"
)

const (
	AIXFilesetsCollector      = "koda-aix-filesets"
	AIXOracleCollector        = "koda-aix-oracle-inventory"
	oracleInventoryCPESource  = cpe.Source("koda-oracle-inventory")
	oracleSPDXIDPrefix        = "SPDXRef-KODA-Oracle-"
	maxExportedOraclePatchIDs = 2048
)

type oracleInventoryMetadata struct {
	HomeID                           string   `json:"homeId,omitempty" cyclonedx:"homeId"`
	Release                          string   `json:"release,omitempty" cyclonedx:"release"`
	PatchIDs                         []string `json:"opatchInventoryPatchIds,omitempty" cyclonedx:"opatchInventoryPatchIds"`
	PatchIDsTruncated                bool     `json:"opatchInventoryPatchIdsTruncated,omitempty" cyclonedx:"opatchInventoryPatchIdsTruncated"`
	Observation                      string   `json:"observation" cyclonedx:"observation"`
	VersionSource                    string   `json:"versionSource,omitempty" cyclonedx:"versionSource"`
	InventoryStatus                  string   `json:"inventoryStatus,omitempty" cyclonedx:"inventoryStatus"`
	ListenerExecutableObserved       bool     `json:"listenerExecutableObserved,omitempty" cyclonedx:"listenerExecutableObserved"`
	ListenerReleaseBasis             string   `json:"listenerReleaseBasis,omitempty" cyclonedx:"listenerReleaseBasis"`
	ListenerReleasePatchIDs          []string `json:"listenerReleasePatchIds,omitempty" cyclonedx:"listenerReleasePatchIds"`
	ListenerReleasePatchIDsTruncated bool     `json:"listenerReleasePatchIdsTruncated,omitempty" cyclonedx:"listenerReleasePatchIdsTruncated"`
	OPatchEvidenceSHA256             string   `json:"opatchEvidenceSha256,omitempty" cyclonedx:"opatchEvidenceSha256"`
	ListenerEvidenceSHA256           string   `json:"listenerEvidenceSha256,omitempty" cyclonedx:"listenerEvidenceSha256"`
}

func AIXSBOM(inventory aixevidence.Inventory, version string) (*sbom.SBOM, error) {
	out := &sbom.SBOM{
		Source:     source.Description{Name: "IBM AIX evidence", Metadata: source.DirectoryMetadata{Path: "."}},
		Descriptor: sbom.Descriptor{Name: "koda-bom", Version: version},
		Artifacts:  sbom.Artifacts{Packages: pkg.NewCollection()},
	}
	for _, fileset := range inventory.Filesets {
		entry := pkg.Package{
			Name: fileset.Name, Version: fileset.Version, Type: pkg.UnknownPkg,
			FoundBy: AIXFilesetsCollector, Locations: file.NewLocationSet(file.NewLocation("lslpp.txt")),
			Metadata: map[string]string{
				"platform": "aix", "filesetState": fileset.State, "filesetType": fileset.Type,
				"fixState": fileset.FixState, "ptf": fileset.PTF,
			},
		}
		entry.SetID()
		out.Artifacts.Packages.Add(entry)
	}
	for _, home := range inventory.OracleHomes {
		patches, patchesTruncated := boundedOraclePatchIDs(home.PatchIDs)
		for _, product := range []struct{ name, cpeProduct, version, release, location string }{
			{"Oracle Database Server", "database_server", home.DatabaseVersion, home.DatabaseRelease, "opatch.txt"},
			{"Oracle Grid Infrastructure", "", home.GridVersion, home.GridRelease, "opatch.txt"},
			{"Oracle RDBMS Listener", "rdbms_listener", home.ListenerVersion, home.ReleaseUpdate, "listener.txt"},
		} {
			isListener := product.cpeProduct == "rdbms_listener"
			if (isListener && !home.ListenerInstalled) || (!isListener && product.version == "") {
				continue
			}
			locations := file.NewLocationSet(file.NewLocation(path.Join(home.EvidencePrefix, product.location)))
			opatchPath := path.Join(home.EvidencePrefix, "opatch.txt")
			metadata := oracleInventoryMetadata{
				HomeID: home.Path, Release: product.release, PatchIDs: patches, PatchIDsTruncated: patchesTruncated, Observation: "installed inventory",
			}
			if isListener {
				listenerPath := path.Join(home.EvidencePrefix, "listener.txt")
				locations.Add(file.NewLocation(opatchPath))
				metadata.VersionSource = home.ListenerVersionSource
				metadata.InventoryStatus = "completed"
				metadata.ListenerExecutableObserved = true
				metadata.ListenerReleaseBasis = home.ListenerReleaseBasis
				metadata.ListenerReleasePatchIDs, metadata.ListenerReleasePatchIDsTruncated = boundedOraclePatchIDs(home.ListenerReleasePatchIDs)
				metadata.OPatchEvidenceSHA256 = inventory.EvidenceSHA256[opatchPath]
				metadata.ListenerEvidenceSHA256 = inventory.EvidenceSHA256[listenerPath]
				if product.version == "" {
					metadata.Release = ""
					metadata.Observation = "listener executable observed; version unconfirmed"
				}
			}
			entry := pkg.Package{
				Name: product.name, Version: product.version, Type: pkg.BinaryPkg, FoundBy: AIXOracleCollector,
				Locations: locations, Metadata: metadata,
			}
			if product.cpeProduct != "" && product.version != "" {
				id, err := cpe.New("cpe:2.3:a:oracle:"+product.cpeProduct+":"+product.version+":*:*:*:*:*:*:*", oracleInventoryCPESource)
				if err != nil {
					return nil, err
				}
				entry.CPEs = []cpe.CPE{id}
			}
			id := sha256.Sum256([]byte(home.Path + "\x00" + product.name + "\x00" + product.version))
			entry.OverrideID(artifact.ID(fmt.Sprintf("%s%x", oracleSPDXIDPrefix, id)))
			out.Artifacts.Packages.Add(entry)
		}
	}
	Scrub(out)
	return out, nil
}

func boundedOraclePatchIDs(ids []string) ([]string, bool) {
	if len(ids) > maxExportedOraclePatchIDs {
		return ids[:maxExportedOraclePatchIDs], true
	}
	return ids, false
}
