package assetimport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

// Older Redfish Power and Thermal exports embed parts without @odata.type.
func redfishParts(doc map[string]json.RawMessage) ([]map[string]json.RawMessage, error) {
	var records []map[string]json.RawMessage
	for _, group := range []struct{ field, kind string }{{"PowerSupplies", "PowerSupply"}, {"Fans", "Fan"}} {
		if doc[group.field] == nil {
			continue
		}
		var parts []map[string]json.RawMessage
		if err := json.Unmarshal(doc[group.field], &parts); err != nil {
			return nil, err
		}
		for _, part := range parts {
			if part["@odata.type"] == nil {
				part["@odata.type"], _ = json.Marshal("#" + group.kind + ".v1_0_0." + group.kind)
			}
			records = append(records, part)
		}
	}
	return records, nil
}

func redfishDevice(typ string) bool {
	for _, kind := range []string{"Chassis", "Memory", "Processor", "PowerSupply", "Fan", "Drive", "NetworkAdapter", "NetworkDeviceFunction", "PCIeDevice", "StorageController", "Assembly"} {
		if strings.HasPrefix(typ, "#"+kind+".") {
			return true
		}
	}
	return false
}

func redfishProperties(a *model.Asset, record map[string]json.RawMessage) {
	for source, target := range map[string]string{"PartNumber": "partNumber", "SparePartNumber": "sparePartNumber", "CapacityMiB": "capacityMiB", "PowerCapacityWatts": "powerCapacityWatts", "MemoryDeviceType": "memoryDeviceType", "DeviceLocator": "location", "ProductionDate": "manufacturedAt"} {
		if value := scalar(record, source); value != "" {
			a.Properties[target] = value
		}
	}
	if serial := str(record, "SerialNumber"); serial != "" {
		sum := sha256.Sum256([]byte(serial))
		a.Properties["serialSHA256"] = hex.EncodeToString(sum[:])
	}
	var status map[string]json.RawMessage
	if json.Unmarshal(record["Status"], &status) == nil {
		for _, key := range []string{"State", "Health"} {
			if value := str(status, key); value != "" {
				a.Properties["reported"+key] = value
			}
		}
	}
	// Stable local @odata identifiers relate only objects included in this export.
	// External URI-only members remain reported incomplete by Load.
	if id := str(record, "@odata.id"); id != "" {
		a.ID = id
	}
}

// Resolve only relationships whose destination was included in the same export.
func redfishParent(id string, record map[string]json.RawMessage, ids map[string]bool) string {
	var links map[string]json.RawMessage
	_ = json.Unmarshal(record["Links"], &links)
	for _, key := range []string{"Chassis", "ComputerSystems"} {
		var targets []map[string]json.RawMessage
		if json.Unmarshal(links[key], &targets) != nil {
			continue
		}
		if len(targets) == 1 {
			if target := str(targets[0], "@odata.id"); target != id && ids[target] {
				return target
			}
		}
	}
	// Expanded part resources commonly omit a parent link. Their resource path
	// identifies the containing System or Chassis when that object is supplied.
	parent := ""
	for candidate := range ids {
		if candidate != id && strings.HasPrefix(id, strings.TrimSuffix(candidate, "/")+"/") && len(candidate) > len(parent) {
			parent = candidate
		}
	}
	return parent
}
