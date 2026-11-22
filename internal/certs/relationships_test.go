package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

func TestCertificateKeyAndVerifiedIssuerLinks(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "private-service"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "chain.pem"), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...), 0600)
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), plan)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	ids := map[string]bool{}
	issuerID := ""
	leafID := ""
	for _, a := range assets {
		ids[a.ID] = true
		if a.Name == "X.509 certificate" {
			if a.Properties["isCA"] == "true" {
				issuerID = a.ID
			} else {
				leafID = a.ID
			}
		}
	}
	linked := false
	for _, a := range assets {
		for _, ref := range a.DependsOn {
			if !ids[ref] {
				t.Fatalf("dangling %s", ref)
			}
		}
		if a.ID == leafID {
			linked = slices.Contains(a.DependsOn, issuerID) && a.Properties["issuerRelationship"] == "signature-verified"
		}
		var crypto struct {
			CertificateProperties           struct{ SubjectPublicKeyRef, SignatureAlgorithmRef string }
			RelatedCryptoMaterialProperties struct{ AlgorithmRef string }
		}
		json.Unmarshal(a.Crypto, &crypto)
		for _, ref := range []string{crypto.CertificateProperties.SubjectPublicKeyRef, crypto.CertificateProperties.SignatureAlgorithmRef, crypto.RelatedCryptoMaterialProperties.AlgorithmRef} {
			if ref != "" && !ids[ref] {
				t.Fatal("missing crypto ref")
			}
		}
	}
	if !linked {
		t.Fatal("verified issuer relationship missing")
	}
	out, _ := json.Marshal(assets)
	if strings.Contains(string(out), "private-service") || strings.Contains(string(out), "private-ca") {
		t.Fatal("certificate identities leaked")
	}
}

func TestDeclaredCryptoConfigurationsAndExplicitCertificate(t *testing.T) {
	root := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := certificate(t, key, &key.PublicKey, x509.ECDSAWithSHA256, time.Now().Add(time.Hour))
	for name, text := range map[string][]byte{
		"etc/nginx/nginx.conf":     []byte("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL;\nssl_certificate /etc/ssl/certs/served.crt;\nssl_certificate_key /private/SECRET;\n"),
		"etc/ssh/sshd_config":      []byte("Ciphers aes256-gcm@openssh.com\nKexAlgorithms curve25519-sha256\nPassword SECRET\n"),
		"etc/ssl/certs/served.crt": data,
	} {
		full := filepath.Join(root, name)
		os.MkdirAll(filepath.Dir(full), 0700)
		os.WriteFile(full, text, 0600)
	}
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), plan)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	declarations := 0
	certificateLink := false
	for _, a := range assets {
		if a.Properties["observationState"] == "declared" {
			declarations++
		}
		if a.Properties["directive"] == "ssl_certificate" {
			certificateLink = len(a.DependsOn) == 1
		}
	}
	if declarations != 5 || !certificateLink {
		t.Fatalf("declarations %d certificate link %v", declarations, certificateLink)
	}
	raw, _ := json.Marshal(assets)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatal("unallowlisted directive leaked")
	}
	// A specifically referenced certificate remains subject to scan exclusions.
	plan, err = localfs.Build(context.Background(), root, []string{"**/served.crt"})
	if err != nil {
		t.Fatal(err)
	}
	assets, _ = Collect(context.Background(), plan)
	for _, a := range assets {
		if a.Properties["directive"] == "ssl_certificate" && len(a.DependsOn) > 0 {
			t.Fatal("excluded certificate was read")
		}
	}
}

func TestScopeKeepsCryptographicReferencesLocal(t *testing.T) {
	root := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	os.WriteFile(filepath.Join(root, "server.pem"), certificate(t, key, &key.PublicKey, x509.ECDSAWithSHA256, time.Now().Add(time.Hour)), 0600)
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := Collect(context.Background(), plan)
	second, _ := Collect(context.Background(), plan)
	first = ScopeAssets(first, "target-1")
	second = ScopeAssets(second, "target-2")
	seen := map[string]bool{}
	for _, group := range [][]model.Asset{first, second} {
		local := map[string]bool{}
		for _, a := range group {
			if seen[a.ID] {
				t.Fatal("cross-scope collision")
			}
			seen[a.ID] = true
			local[a.ID] = true
		}
		for _, a := range group {
			for _, ref := range a.DependsOn {
				if !local[ref] {
					t.Fatal("cross-scope dependency")
				}
			}
		}
	}
}

func TestCryptoConfigurationDoesNotCopyUnrelatedOrOpaqueValues(t *testing.T) {
	c := collection{now: time.Now(), algorithms: map[string]bool{}, keys: map[string]bool{}, certificates: map[string]bool{}}
	c.configFile("etc/nginx/nginx.conf", "nginx", strings.NewReader(`ssl_protocols TLSv1.3; proxy_set_header Authorization "SECRET";
ssl_ciphers "HIGH:!aNULL"; set $password SECRET;
ssl_certificate data:SECRET;
ssl_certificate https://user:SECRET@example.invalid/cert;
ssl_certificate "engine:provider:SECRET";
ssl_ciphers SECRET;
ssl_ciphers "HIGH;SECRET";
ssl_certificate "\\SECRET";
ssl_protocols "TLSv1.3"; # SECRET
`), func(string) []string { return nil })
	if len(c.assets) != 3 {
		t.Fatalf("retained declarations %d", len(c.assets))
	}
	raw, _ := json.Marshal(c.assets)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "Authorization") {
		t.Fatal("private or unrelated value copied")
	}
}
