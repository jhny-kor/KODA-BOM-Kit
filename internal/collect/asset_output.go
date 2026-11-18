package collect

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

const AssetPropertyPrefix = "koda:asset:"

func assetSPDXID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return fmt.Sprintf("SPDXRef-KodaAsset-%x", sum[:16])
}

type assetProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type assetReference struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func addAssetComponents(raw []byte, format string, assets []model.Asset) ([]byte, error) {
	if len(assets) == 0 {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if format == "sbom.spdx.json" {
		if err := addSPDXAssets(doc, assets); err != nil {
			return nil, err
		}
	} else if err := addCycloneDXAssets(doc, assets); err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

func appendRecords[T any](doc map[string]json.RawMessage, field string, values []T) error {
	var rows []json.RawMessage
	if existing := doc[field]; len(existing) > 0 {
		if err := json.Unmarshal(existing, &rows); err != nil {
			return err
		}
	}
	for _, v := range values {
		row, err := json.Marshal(v)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}
	var err error
	doc[field], err = json.Marshal(rows)
	return err
}

func addCycloneDXAssets(doc map[string]json.RawMessage, assets []model.Asset) error {
	rows := make([]map[string]any, 0, len(assets))
	drivers := map[string][]string{}
	for _, asset := range assets {
		values := map[string]string{
			"source": asset.Source, "observed-at": asset.ObservedAt,
			"model": asset.Model, "revision": asset.Revision, "parent-id": asset.ParentID,
		}
		for k, v := range asset.Properties {
			values["evidence:"+k] = v
		}
		props := make([]assetProperty, 0, len(values))
		for _, k := range slices.Sorted(maps.Keys(values)) {
			if values[k] != "" {
				props = append(props, assetProperty{Name: AssetPropertyPrefix + k, Value: values[k]})
			}
		}
		row := map[string]any{"type": asset.Kind, "name": asset.Name, "bom-ref": asset.ID, "properties": props}
		for k, v := range map[string]string{"manufacturer": asset.Vendor, "version": asset.Version, "cpe": asset.CPE, "purl": asset.PURL} {
			if v == "" {
				continue
			}
			if k == "manufacturer" {
				row[k] = map[string]string{"name": v}
			} else {
				row[k] = v
			}
		}
		if asset.SHA256 != "" {
			row["hashes"] = []map[string]string{{"alg": "SHA-256", "content": asset.SHA256}}
		}
		rows = append(rows, row)
		if asset.Kind == "device-driver" && asset.ParentID != "" {
			drivers[asset.ParentID] = append(drivers[asset.ParentID], asset.ID)
		}
	}
	if err := appendRecords(doc, "components", rows); err != nil {
		return err
	}
	var dependencies []map[string]any
	for _, parent := range slices.Sorted(maps.Keys(drivers)) {
		dependencies = append(dependencies, map[string]any{"ref": parent, "dependsOn": drivers[parent]})
	}
	if len(dependencies) > 0 {
		return appendRecords(doc, "dependencies", dependencies)
	}
	return nil
}

func addSPDXAssets(doc map[string]json.RawMessage, assets []model.Asset) error {
	rows := make([]map[string]any, 0, len(assets))
	relationships := make([]map[string]string, 0, len(assets))
	defaultParent, defaultRelation := "SPDXRef-DOCUMENT", "DESCRIBES"
	if raw := doc["relationships"]; len(raw) > 0 {
		var existing []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &existing); err != nil {
			return err
		}
		for _, relation := range existing {
			var source, kind, target string
			_ = json.Unmarshal(relation["spdxElementId"], &source)
			_ = json.Unmarshal(relation["relationshipType"], &kind)
			_ = json.Unmarshal(relation["relatedSpdxElement"], &target)
			if source == "SPDXRef-DOCUMENT" && kind == "DESCRIBES" && strings.HasPrefix(target, "SPDXRef-DocumentRoot-") {
				defaultParent, defaultRelation = target, "CONTAINS"
				break
			}
		}
	}
	for _, asset := range assets {
		id := assetSPDXID(asset.ID)
		purpose := strings.ToUpper(asset.Kind)
		switch asset.Kind {
		case "device-driver":
			purpose = "OTHER"
		case "operating-system":
			purpose = "OPERATING_SYSTEM"
		}
		evidence, err := json.Marshal(asset)
		if err != nil {
			return err
		}
		row := map[string]any{"SPDXID": id, "name": asset.Name, "downloadLocation": "NOASSERTION",
			"filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
			"copyrightText": "NOASSERTION", "primaryPackagePurpose": purpose, "comment": AssetPropertyPrefix + string(evidence)}
		if asset.Version != "" {
			row["versionInfo"] = asset.Version
		}
		var refs []assetReference
		if asset.CPE != "" {
			refs = append(refs, assetReference{"SECURITY", "cpe23Type", asset.CPE})
		}
		if asset.PURL != "" {
			refs = append(refs, assetReference{"PACKAGE-MANAGER", "purl", asset.PURL})
		}
		if len(refs) > 0 {
			row["externalRefs"] = refs
		}
		if asset.SHA256 != "" {
			row["checksums"] = []map[string]string{{"algorithm": "SHA256", "checksumValue": asset.SHA256}}
		}
		rows = append(rows, row)
		parent, rel := defaultParent, defaultRelation
		if asset.ParentID != "" {
			parent, rel = assetSPDXID(asset.ParentID), "CONTAINS"
			if asset.Kind == "device-driver" {
				rel = "DEPENDS_ON"
			}
		}
		relationships = append(relationships, map[string]string{"spdxElementId": parent, "relationshipType": rel, "relatedSpdxElement": id})
	}
	if err := appendRecords(doc, "packages", rows); err != nil {
		return err
	}
	return appendRecords(doc, "relationships", relationships)
}
