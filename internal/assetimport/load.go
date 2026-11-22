// Package assetimport reads bounded offline device inventory exports.
package assetimport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"sort"
	"strings"
	"time"

	packageurl "github.com/anchore/packageurl-go"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/model"
)

const maxBytes = 8 << 20
const maxAssets = 4096

// Load imports evidence only. Imported versions and states are supplier reports.
func Load(ctx context.Context, filename string) ([]model.Asset, []model.Issue, error) {
	f, err := evidencefile.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, errors.New("inventory must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxBytes {
		return nil, nil, errors.New("inventory exceeds 8 MiB")
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, errors.New("invalid inventory JSON object")
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var records []map[string]json.RawMessage
	format := ""
	switch {
	case doc["schema"] != nil:
		if str(doc, "schema") != "koda-assets-1" {
			return nil, nil, errors.New("unsupported inventory schema")
		}
		format = "generic"
		err = json.Unmarshal(doc["assets"], &records)
	case doc["info"] != nil:
		format = "devlink"
		var entries map[string]map[string]json.RawMessage
		err = json.Unmarshal(doc["info"], &entries)
		keys := []string{}
		for key := range entries {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			r := entries[key]
			if r == nil {
				continue
			}
			r["Name"], _ = json.Marshal(key)
			records = append(records, r)
		}
	case doc["Devices"] != nil:
		format = "fwupd"
		err = json.Unmarshal(doc["Devices"], &records)
	case doc["PowerSupplies"] != nil || doc["Fans"] != nil:
		format = "redfish"
		records, err = redfishParts(doc)
	case doc["Members"] != nil:
		format = "redfish"
		err = json.Unmarshal(doc["Members"], &records)
	case doc["@odata.type"] != nil:
		format = "redfish"
		records = []map[string]json.RawMessage{doc}
	default:
		return nil, nil, errors.New("unsupported inventory format")
	}
	if err != nil || len(records) == 0 || len(records) > maxAssets {
		return nil, nil, errors.New("inventory must contain 1 to 4096 objects")
	}
	redfishIDs := map[string]bool{}
	if format == "redfish" {
		for _, r := range records {
			typ := str(r, "@odata.type")
			if id := str(r, "@odata.id"); id != "" && (redfishDevice(typ) || strings.Contains(typ, "ComputerSystem.") || strings.Contains(typ, "Manager.") || strings.Contains(typ, "SoftwareInventory.")) {
				redfishIDs[id] = true
			}
		}
	}
	assets := []model.Asset{}
	issues := []model.Issue{}
	seen := map[string]bool{}
	observed := str(doc, "observedAt")
	if observed != "" {
		if _, err = time.Parse(time.RFC3339, observed); err != nil {
			return nil, nil, errors.New("invalid observedAt timestamp")
		}
	}
	for i, r := range records {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		a := model.Asset{Kind: "firmware", Source: "import:" + format, ObservedAt: observed, Properties: map[string]string{"evidenceSHA256": digest, "evidenceKind": "administrator-export", "applicationState": "unknown"}}
		switch format {
		case "generic":
			a.ID = str(r, "id")
			a.Kind = str(r, "kind")
			a.Name = str(r, "name")
			a.Vendor = str(r, "vendor")
			a.Version = str(r, "version")
			a.Model = str(r, "model")
			a.Revision = str(r, "revision")
			a.ParentID = str(r, "parentId")
			a.PURL = str(r, "purl")
			if a.PURL != "" {
				parsed, err := packageurl.FromString(a.PURL)
				if err != nil || parsed.Name == "" || (parsed.Version != "" && parsed.Version != a.Version) {
					return nil, nil, errors.New("invalid or conflicting package URL")
				}
				for _, q := range parsed.Qualifiers {
					if q.Key != "arch" && q.Key != "distro" && q.Key != "epoch" && q.Key != "type" && q.Key != "classifier" {
						return nil, nil, errors.New("unsupported package URL qualifier")
					}
				}
				a.PURL = parsed.ToString()
			}
			a.SHA256 = strings.ToLower(str(r, "sha256"))
			if a.SHA256 != "" {
				decoded, err := hex.DecodeString(a.SHA256)
				if err != nil || len(decoded) != 32 {
					return nil, nil, errors.New("invalid component SHA256")
				}
			}
			if a.Kind != "device" && a.Kind != "firmware" && a.Kind != "device-driver" && a.Kind != "library" && a.Kind != "application" && a.Kind != "operating-system" && a.Kind != "container" && a.Kind != "cryptographic-asset" {
				return nil, nil, errors.New("invalid asset kind")
			}
			var properties map[string]string
			if r["properties"] != nil {
				if json.Unmarshal(r["properties"], &properties) != nil {
					return nil, nil, errors.New("invalid asset properties")
				}
			}
			for _, key := range []string{"runningVersion", "storedVersion", "versionFormat", "rawVersion", "applicationState", "platform", "productCode", "pciVendor", "pciDevice", "pciSubsystem", "updateState", "partNumber", "supplier", "supportEndsAt", "manufacturedAt", "location", "deviceType", "capacityMiB", "powerCapacityWatts", "storageType", "keyAlias", "consumer", "consumerPurl", "configurationPath", "observationState", "trustState", "serialSHA256", "sparePartNumber", "endpoint", "transport", "sessionObservedAt", "negotiatedCipherSuite", "certificateSHA256", "keyAliasSHA256", "keystoreIntegrity"} {
				if val := clean(properties[key]); val != "" {
					a.Properties[key] = val
				}
			}
			if err := validateCryptoObservation(a.Properties); err != nil {
				return nil, nil, err
			}
			for _, key := range []string{"supportEndsAt", "manufacturedAt"} {
				if value := a.Properties[key]; value != "" {
					if _, err := time.Parse("2006-01-02", value); err != nil {
						return nil, nil, errors.New("invalid hardware lifecycle date")
					}
				}
			}
			if hash := a.Properties["serialSHA256"]; hash != "" {
				if bytes, err := hex.DecodeString(hash); err != nil || len(bytes) != 32 {
					return nil, nil, errors.New("invalid serial digest")
				}
			}
			if r["dependsOn"] != nil && json.Unmarshal(r["dependsOn"], &a.DependsOn) != nil {
				return nil, nil, errors.New("invalid asset dependencies")
			}
			if len(a.DependsOn) > 128 {
				return nil, nil, errors.New("too many asset dependencies")
			}
			if a.Kind == "cryptographic-asset" {
				a.Crypto, err = importCrypto(r["cryptoProperties"], digest)
				if err != nil {
					return nil, nil, err
				}
				if err := validateSessionCrypto(a); err != nil {
					return nil, nil, err
				}
			}
		case "devlink":
			a.Name = str(r, "Name")
			a.Kind = "firmware"
			a.Properties["driver"] = str(r, "driver")
			var versions map[string]map[string]string
			if json.Unmarshal(r["versions"], &versions) != nil {
				return nil, nil, errors.New("invalid devlink versions")
			}
			for _, group := range []string{"fixed", "running", "stored"} {
				if len(versions[group]) > 64 {
					return nil, nil, errors.New("too many devlink version fields")
				}
				for key, value := range versions[group] {
					if clean(key) != "" && clean(value) != "" {
						a.Properties[group+"."+clean(key)] = clean(value)
					}
				}
			}
			a.Version = clean(versions["running"]["fw"])
			a.Model = clean(versions["fixed"]["board.id"])
			a.Revision = clean(versions["fixed"]["board.rev"])
		case "fwupd":
			a.Name = str(r, "Name")
			a.Vendor = str(r, "Vendor")
			a.Version = str(r, "Version")
			a.Properties["versionFormat"] = str(r, "VersionFormat")
			a.Properties["rawVersion"] = scalar(r, "VersionRaw")
			a.Properties["updateState"] = scalar(r, "UpdateState")
		case "redfish":
			typ := str(r, "@odata.type")
			switch {
			case strings.Contains(typ, "SoftwareInventory."):
				a.Version = str(r, "Version")
			case strings.Contains(typ, "Manager."):
				a.Version = str(r, "FirmwareVersion")
			case strings.Contains(typ, "ComputerSystem."):
				a.Kind = "device"
				a.Properties["biosVersion"] = str(r, "BiosVersion")
			case redfishDevice(typ):
				a.Kind = "device"
			default:
				issues = append(issues, model.Issue{Collector: "asset-import", Status: "incomplete", Code: "unexpanded_redfish_member", Message: "Redfish member requires a supported expanded hardware or firmware object"})
				continue
			}
			a.Name = str(r, "Name")
			a.Vendor = str(r, "Manufacturer")
			a.Model = str(r, "Model")
			a.Revision = str(r, "HardwareRevision")
			redfishProperties(&a, r)
			a.ParentID = redfishParent(a.ID, r, redfishIDs)
			a.Properties["applicationState"] = "unknown"
			if state := str(r, "ImageState"); state != "" {
				a.Properties["applicationState"] = state
			}
		}
		if a.Name == "" {
			return nil, nil, errors.New("asset name is required")
		}
		originalID := a.ID
		if originalID == "" {
			originalID = fmt.Sprintf("%d", i)
		}
		identity := sha256.Sum256([]byte(digest + "\x00" + originalID))
		a.ID = "import-" + hex.EncodeToString(identity[:12])
		if seen[a.ID] {
			return nil, nil, errors.New("duplicate asset identifier")
		}
		seen[a.ID] = true
		if a.ParentID != "" {
			p := sha256.Sum256([]byte(digest + "\x00" + a.ParentID))
			a.ParentID = "import-" + hex.EncodeToString(p[:12])
		}
		for j, ref := range a.DependsOn {
			if clean(ref) == "" {
				return nil, nil, errors.New("empty asset dependency")
			}
			a.DependsOn[j] = importedID(digest, ref)
		}
		a.DependsOn = append(a.DependsOn, cryptoReferences(a.Crypto)...)
		if a.Version == "" && a.Kind != "device" && a.Kind != "cryptographic-asset" {
			issues = append(issues, model.Issue{Collector: "asset-import", Status: "incomplete", Code: "version_unknown", Message: "Imported component version is unavailable"})
		}
		assets = append(assets, a)
	}
	linkSessionCertificates(assets)
	for _, a := range assets {
		refs := append(append([]string{}, a.DependsOn...), cryptoReferences(a.Crypto)...)
		for _, ref := range refs {
			if !seen[ref] || ref == a.ID {
				return nil, nil, errors.New("invalid asset dependency reference")
			}
		}
		if a.ParentID != "" && (!seen[a.ParentID] || a.ParentID == a.ID) {
			return nil, nil, errors.New("invalid asset parent reference")
		}
	}
	parents := map[string]string{}
	for _, a := range assets {
		parents[a.ID] = a.ParentID
	}
	for _, a := range assets {
		chain := map[string]bool{}
		for id := a.ID; id != ""; id = parents[id] {
			if chain[id] {
				return nil, nil, errors.New("cyclic asset parent reference")
			}
			chain[id] = true
		}
	}
	if err := validateCryptoTargets(assets); err != nil {
		return nil, nil, err
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	return assets, issues, nil
}
func clean(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 || strings.ContainsAny(s, "\x00\r\n") {
		return ""
	}
	return s
}
func str(r map[string]json.RawMessage, key string) string {
	var s string
	if json.Unmarshal(r[key], &s) != nil {
		return ""
	}
	return clean(s)
}
func scalar(r map[string]json.RawMessage, key string) string {
	if s := str(r, key); s != "" {
		return s
	}
	var n json.Number
	if json.Unmarshal(r[key], &n) == nil {
		return clean(n.String())
	}
	return ""
}
