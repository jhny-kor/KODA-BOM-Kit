package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
)

func certificate(t *testing.T, key any, public any, alg x509.SignatureAlgorithm, notAfter time.Time) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "internal-host.example"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, SignatureAlgorithm: alg}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertificateInventory(t *testing.T) {
	root := t.TempDir()
	put := func(p string, data []byte) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expired := certificate(t, weak, &weak.PublicKey, x509.SHA256WithRSA, time.Now().Add(-time.Hour))
	valid := certificate(t, ec, &ec.PublicKey, x509.ECDSAWithSHA256, time.Now().Add(365*24*time.Hour))
	keyDER, _ := x509.MarshalECPrivateKey(ec)
	put("etc/nginx/tls/legacy.crt", expired)
	put("opt/app/tls/server.pem", append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), valid...))
	put("etc/ssl/certs/ca.pem", valid)                                             // system trust store
	put("opt/app/bundle.crt", []byte(strings.Repeat(string(valid), bundleSize+1))) // trust bundle
	put("opt/app/notes.txt", valid)                                                // not a certificate extension
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), plan)
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	certs := map[string]map[string]string{}
	algorithms := 0
	for _, a := range assets {
		if a.Kind != "cryptographic-asset" {
			t.Fatalf("unexpected kind %q", a.Kind)
		}
		var crypto struct{ AssetType string }
		if err := json.Unmarshal(a.Crypto, &crypto); err != nil {
			t.Fatal(err)
		}
		switch crypto.AssetType {
		case "certificate":
			certs[a.Source] = a.Properties
			if len(a.SHA256) != 64 {
				t.Errorf("fingerprint %q", a.SHA256)
			}
		case "algorithm":
			algorithms++
		}
		if raw, _ := json.Marshal(a); strings.Contains(string(raw), "internal-host") || strings.Contains(string(raw), "PRIVATE") {
			t.Fatalf("subject name or key material leaked: %s", raw)
		}
	}
	if len(certs) != 2 || algorithms != 4 {
		t.Fatalf("want 2 certificates and 4 algorithms, got %v and %d", certs, algorithms)
	}
	if p := certs["etc/nginx/tls/legacy.crt"]; p["validity"] != "expired" || p["weakness"] != "rsa-key-below-2048" || p["publicKey"] != "RSA-1024" || p["selfSigned"] != "true" {
		t.Errorf("legacy certificate %v", p)
	}
	if p := certs["opt/app/tls/server.pem"]; p["validity"] != "valid" || p["publicKey"] != "ECDSA-P-256" || p["weakness"] != "" {
		t.Errorf("server certificate %v", p)
	}
}
