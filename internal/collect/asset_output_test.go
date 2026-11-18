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
