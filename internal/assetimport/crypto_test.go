package assetimport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, raw string) ([]byte, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	assets, _, err := Load(context.Background(), p)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(assets)
	return b, err
}

func TestCryptoEvidenceReferencesAndSecrets(t *testing.T) {
	raw := `{"schema":"koda-assets-1","assets":[
 {"id":"aes","kind":"cryptographic-asset","name":"AES-256","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"block-cipher","parameterSetIdentifier":"256","mode":"gcm"}}},
 {"id":"key","kind":"cryptographic-asset","name":"Encryption key metadata","cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"secret-key","algorithmRef":"aes","size":256,"state":"active"}},"properties":{"storageType":"HSM","keyAlias":"application-key"}},
 {"id":"app","kind":"application","name":"Backup","version":"1","dependsOn":["key"]}
 ]}`
	out, err := loadFixture(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	var assets []struct {
		ID        string
		DependsOn []string
		Crypto    map[string]json.RawMessage `json:"cryptoProperties"`
	}
	if err := json.Unmarshal(out, &assets); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, a := range assets {
		ids[a.ID] = true
	}
	refs := 0
	for _, a := range assets {
		for _, ref := range a.DependsOn {
			if !ids[ref] {
				t.Fatalf("dangling dependency %s", ref)
			}
			refs++
		}
		if a.Crypto["relatedCryptoMaterialProperties"] != nil {
			var props struct{ AlgorithmRef string }
			json.Unmarshal(a.Crypto["relatedCryptoMaterialProperties"], &props)
			if !ids[props.AlgorithmRef] {
				t.Fatal("algorithm ref was not namespaced")
			}
			refs++
		}
	}
	if refs != 3 {
		t.Fatalf("refs %d", refs)
	}
	for _, bad := range []string{
		strings.Replace(raw, `"size":256`, `"size":256,"value":"SECRET"`, 1),
		strings.Replace(raw, `"algorithmRef":"aes"`, `"algorithmRef":"missing"`, 1),
		strings.Replace(raw, `"algorithmRef":"aes"`, `"algorithmRef":"app"`, 1),
		strings.Replace(raw, `"state":"active"`, `"state":"invalid"`, 1),
		strings.Replace(raw, `"size":256`, `"size":-1`, 1),
	} {
		if _, err := loadFixture(t, bad); err == nil {
			t.Fatal("accepted invalid cryptographic evidence")
		}
	}
}

func TestExpandedRedfishParts(t *testing.T) {
	raw := `{"Members":[
 {"@odata.type":"#ComputerSystem.v1_20_0.ComputerSystem","@odata.id":"/redfish/v1/Systems/1","Name":"Server","Model":"Rack"},
 {"@odata.type":"#Memory.v1_20_0.Memory","@odata.id":"/redfish/v1/Systems/1/Memory/DIMM1","Name":"DIMM 1","Manufacturer":"Example","PartNumber":"DDR5-A","CapacityMiB":32768,"SerialNumber":"PRIVATE-SERIAL"},
 {"@odata.type":"#PowerSupply.v1_0_0.PowerSupply","Name":"PSU","PowerCapacityWatts":750,"PartNumber":"P750"},
 {"@odata.type":"#Fan.v1_0_0.Fan","Name":"Fan","PartNumber":"FAN-A"}
 ]}`
	out, err := loadFixture(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "PRIVATE-SERIAL") {
		t.Fatal("serial leaked")
	}
	var assets []struct {
		ID, Name, ParentID string
		Properties         map[string]string
	}
	json.Unmarshal(out, &assets)
	if len(assets) != 4 {
		t.Fatalf("assets %s", out)
	}
	var server string
	for _, a := range assets {
		if a.Name == "Server" {
			server = a.ID
		}
	}
	for _, a := range assets {
		if a.Name == "DIMM 1" && (a.ParentID != server || a.Properties["capacityMiB"] != "32768" || len(a.Properties["serialSHA256"]) != 64) {
			t.Fatalf("DIMM %+v", a)
		}
	}
	for _, raw := range []string{`{"PowerSupplies":[{"Name":"PSU","PartNumber":"P750"}]}`, `{"Fans":[{"Name":"Fan","PartNumber":"FAN"}]}`} {
		if _, err := loadFixture(t, raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNegotiatedTLSEvidence(t *testing.T) {
	raw := `{"schema":"koda-assets-1","observedAt":"2026-11-21T01:00:00Z","assets":[
 {"id":"cert","kind":"cryptographic-asset","name":"Peer certificate","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","cryptoProperties":{"assetType":"certificate","certificateProperties":{"certificateFormat":"X.509"}}},
 {"id":"tls","kind":"cryptographic-asset","name":"TLS session","cryptoProperties":{"assetType":"protocol","protocolProperties":{"type":"tls","version":"1.3","cipherSuites":[{"name":"TLS_AES_256_GCM_SHA384"}]}},"properties":{"endpoint":"example.invalid:443","transport":"tcp","sessionObservedAt":"2026-11-21T01:00:00Z","observationState":"negotiated","certificateSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
 ]}`
	out, err := loadFixture(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	var assets []struct {
		ID, Name  string
		DependsOn []string
	}
	json.Unmarshal(out, &assets)
	cert := ""
	for _, a := range assets {
		if a.Name == "Peer certificate" {
			cert = a.ID
		}
	}
	for _, a := range assets {
		if a.Name == "TLS session" && (len(a.DependsOn) != 1 || a.DependsOn[0] != cert) {
			t.Fatalf("TLS certificate link %+v", a)
		}
	}
	for _, bad := range []string{strings.Replace(raw, `"transport":"tcp",`, "", 1), strings.Replace(raw, "example.invalid:443", "user:password@example.invalid:443", 1), strings.Replace(raw, "2026-11-21T01:00:00Z", "invalid", -1)} {
		if _, err := loadFixture(t, bad); err == nil {
			t.Fatal("invalid TLS session accepted")
		}
	}
}
