package certs

import (
	"encoding/json"

	"koda.local/security-sbom-linux/internal/model"
)

// ScopeAssets qualifies all cryptographic identities and references when a
// multi-directory scan combines otherwise independent filesystem roots.
func ScopeAssets(assets []model.Asset, scope string) []model.Asset {
	if scope == "" {
		return assets
	}
	ids := map[string]string{}
	for _, a := range assets {
		ids[a.ID] = assetID("scope", scope, a.ID)
	}
	for i := range assets {
		a := &assets[i]
		a.ID = ids[a.ID]
		if a.ParentID != "" {
			a.ParentID = ids[a.ParentID]
		}
		for j, ref := range a.DependsOn {
			a.DependsOn[j] = ids[ref]
		}
		if a.Source != "x509" {
			a.Source = scope + "/" + a.Source
		}
		for _, key := range []string{"path", "configurationPath"} {
			if a.Properties[key] != "" {
				a.Properties[key] = scope + "/" + a.Properties[key]
			}
		}
		var crypto map[string]json.RawMessage
		if json.Unmarshal(a.Crypto, &crypto) != nil {
			continue
		}
		for _, group := range []string{"certificateProperties", "relatedCryptoMaterialProperties", "protocolProperties"} {
			if crypto[group] == nil {
				continue
			}
			var props map[string]json.RawMessage
			if json.Unmarshal(crypto[group], &props) != nil {
				continue
			}
			for _, key := range []string{"signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef"} {
				var ref string
				if json.Unmarshal(props[key], &ref) == nil && ref != "" {
					props[key], _ = json.Marshal(ids[ref])
				}
			}
			var refs []string
			if json.Unmarshal(props["cryptoRefArray"], &refs) == nil {
				for j, ref := range refs {
					refs[j] = ids[ref]
				}
				props["cryptoRefArray"], _ = json.Marshal(refs)
			}
			crypto[group], _ = json.Marshal(props)
		}
		a.Crypto, _ = json.Marshal(crypto)
	}
	return assets
}
