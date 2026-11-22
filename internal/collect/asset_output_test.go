package collect

import (
	"encoding/json"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestAssetRelationshipsPreserveSingleSPDXSource(t *testing.T) {
	const root = "SPDXRef-DocumentRoot-Directory-local-filesystem"
	raw := []byte(`{"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"` + root + `"}]}`)
	assets := []model.Asset{
		{ID: "board", Kind: "device", Name: "Board", Source: "fixture"},
		{ID: "driver", ParentID: "board", Kind: "device-driver", Name: "Driver", Source: "fixture"},
	}
	rendered, err := addAssetComponents(raw, "sbom.spdx.json", assets)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Relationships []struct {
			Type   string `json:"relationshipType"`
			Source string `json:"spdxElementId"`
			Target string `json:"relatedSpdxElement"`
		}
	}
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range doc.Relationships {
		got[r.Source+"/"+r.Type] = r.Target
	}
	if len(doc.Relationships) != 3 || got["SPDXRef-DOCUMENT/DESCRIBES"] != root ||
		got[root+"/CONTAINS"] != assetSPDXID("board") || got[assetSPDXID("board")+"/DEPENDS_ON"] != assetSPDXID("driver") {
		t.Fatalf("unexpected SPDX asset relationships: %+v", doc.Relationships)
	}
}

func TestCryptoConsumersAndHardwareDependencies(t *testing.T) {
	assets := []model.Asset{
		{ID: "board", Kind: "device", Name: "Board", Source: "fixture", Properties: map[string]string{"supplier": "Supplier"}},
		{ID: "dimm", Kind: "device", Name: "DIMM", Source: "fixture", ParentID: "board"},
		{ID: "algorithm", Kind: "cryptographic-asset", Name: "SHA256", Source: "fixture", Crypto: json.RawMessage(`{"assetType":"algorithm"}`)},
		{ID: "certificate", Kind: "cryptographic-asset", Name: "Certificate", Source: "fixture", DependsOn: []string{"algorithm"}, Crypto: json.RawMessage(`{"assetType":"certificate","certificateProperties":{"signatureAlgorithmRef":"algorithm"}}`)},
		{ID: "protocol", Kind: "cryptographic-asset", Name: "TLS declaration", Source: "etc/nginx/nginx.conf", DependsOn: []string{"certificate"}, Crypto: json.RawMessage(`{"assetType":"protocol","protocolProperties":{"type":"tls","cryptoRefArray":["certificate"]}}`), Properties: map[string]string{"consumer": "nginx", "configurationPath": "etc/nginx/nginx.conf"}},
	}
	rendered, err := addAssetComponents([]byte(`{}`), "sbom.cdx.json", assets)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components []struct {
			Ref      string `json:"bom-ref"`
			Supplier *struct{ Name string }
		}
		Services []struct {
			Ref  string `json:"bom-ref"`
			Name string
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 1 || doc.Services[0].Name != "nginx" {
		t.Fatalf("services %+v", doc.Services)
	}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		refs[c.Ref] = true
	}
	for _, s := range doc.Services {
		refs[s.Ref] = true
	}
	links := map[string][]string{}
	for _, d := range doc.Dependencies {
		if !refs[d.Ref] {
			t.Fatal("dangling source")
		}
		links[d.Ref] = d.DependsOn
		for _, ref := range d.DependsOn {
			if !refs[ref] {
				t.Fatal("dangling target")
			}
		}
	}
	if len(links["board"]) != 1 || links["board"][0] != "dimm" || len(links[doc.Services[0].Ref]) != 1 || links[doc.Services[0].Ref][0] != "protocol" {
		t.Fatalf("links %+v", links)
	}
}
