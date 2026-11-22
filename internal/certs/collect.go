// Package certs inventories public X.509 certificates, JKS entry metadata and
// declared cryptographic configuration. Private key values are not interpreted
// or emitted. Certificate subject and issuer names are omitted, and certificates
// are identified by their source path and SHA-256 fingerprint.
package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

const (
	maxFileBytes   = 1 << 20
	maxFiles       = 10000
	maxCerts       = 20000
	bundleSize     = 20 // more certificates than this in one file is a trust bundle
	expiringWithin = 30 * 24 * time.Hour
)

var extensions = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".der": true, ".cert": true, ".jks": true, ".keystore": true}

// System trust stores hold hundreds of public CA certificates managed by the
// distribution; they are not the operator's certificates.
var trustStores = []string{
	"usr/share/ca-certificates/", "etc/ssl/certs/", "etc/pki/ca-trust/", "usr/share/pki/",
	"etc/ca-certificates/", "etc/pki/tls/certs/ca-bundle", "etc/pki/java/cacerts",
}

func candidate(p string) bool {
	if !extensions[strings.ToLower(path.Ext(p))] {
		return false
	}
	for _, prefix := range trustStores {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}
	// Bundled trust stores and test fixtures of language packages.
	return !strings.Contains(p, "/certifi/") && !strings.Contains(p, "/node_modules/") && !strings.Contains(p, "/site-packages/pip/")
}

// Collect parses certificate files admitted by the filesystem plan.
func Collect(ctx context.Context, plan localfs.Plan) ([]model.Asset, []model.Issue) {
	r, err := plan.OpenRoot()
	if err != nil {
		return nil, []model.Issue{{Collector: "certificates", Status: "incomplete", Message: "certificate scan root could not be opened"}}
	}
	defer r.Close()
	now := time.Now().UTC()
	c := collection{algorithms: map[string]bool{}, keys: map[string]bool{}, certificates: map[string]bool{}, now: now}
	files := 0
	for _, p := range plan.Paths {
		if ctx.Err() != nil || len(c.assets) >= maxCerts {
			break
		}
		if !candidate(p) {
			continue
		}
		if files++; files > maxFiles {
			c.issues = append(c.issues, model.Issue{Collector: "certificates", Status: "incomplete", Message: "certificate file limit reached"})
			break
		}
		f, st, err := plan.OpenIndexedRegular(r, p)
		if err != nil {
			continue
		}
		if ext := strings.ToLower(path.Ext(p)); ext == ".jks" || ext == ".keystore" {
			if st.Size() <= maxKeystoreBytes {
				c.keystore(p, f)
			} else {
				c.issues = append(c.issues, model.Issue{Collector: "certificates", Status: "incomplete", Path: p, Message: "keystore exceeds 8 MiB"})
			}
			f.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
		f.Close()
		if err != nil || st.Size() > maxFileBytes || len(data) > maxFileBytes {
			continue
		}
		c.file(p, data)
	}
	c.configurations(ctx, plan, r)
	c.linkIssuers(ctx)
	return c.assets, c.issues
}

type collection struct {
	assets       []model.Asset
	issues       []model.Issue
	algorithms   map[string]bool
	keys         map[string]bool
	parsed       []parsedCertificate
	certificates map[string]bool
	now          time.Time
}

func certificatesIn(data []byte) [][]byte {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return [][]byte{data} // DER
	}
	var ders [][]byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			ders = append(ders, block.Bytes)
		}
		data = rest // other block types, including private keys, are skipped unread
	}
	return ders
}

func (c *collection) file(p string, data []byte) {
	ders := certificatesIn(data)
	if len(ders) > bundleSize {
		return
	}
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		c.add(p, i, der, cert)
	}
}

type keyInfo struct {
	name, primitive, parameter, curve string
	classical                         int
}

func publicKey(cert *x509.Certificate) keyInfo {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		level := map[int]int{1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}[bits]
		return keyInfo{name: fmt.Sprintf("RSA-%d", bits), primitive: "pke", parameter: strconv.Itoa(bits), classical: level}
	case *ecdsa.PublicKey:
		curve := key.Curve.Params().Name
		level := map[string]int{"P-224": 112, "P-256": 128, "P-384": 192, "P-521": 256}[curve]
		return keyInfo{name: "ECDSA-" + curve, primitive: "signature", curve: curve, classical: level}
	case ed25519.PublicKey:
		return keyInfo{name: "Ed25519", primitive: "signature", curve: "Ed25519", classical: 128}
	}
	return keyInfo{name: cert.PublicKeyAlgorithm.String(), primitive: "unknown"}
}

// weakness lists reasons a certificate should be replaced.
func weakness(cert *x509.Certificate, key keyInfo) []string {
	var reasons []string
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		reasons = append(reasons, "md5-signature")
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		reasons = append(reasons, "sha1-signature")
	}
	if strings.HasPrefix(key.name, "RSA-") && key.classical > 0 && key.classical < 112 {
		reasons = append(reasons, "rsa-key-below-2048")
	}
	if cert.PublicKeyAlgorithm == x509.DSA {
		reasons = append(reasons, "dsa-key")
	}
	return reasons
}

func assetID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "crypto-" + hex.EncodeToString(sum[:12])
}

// algorithm adds one shared algorithm component and returns its bom-ref.
// All listed algorithms are classical: nistQuantumSecurityLevel is 0.
func (c *collection) algorithm(name, primitive, parameter, curve string, classical int) string {
	id := assetID("algorithm", name)
	if c.algorithms[id] {
		return id
	}
	c.algorithms[id] = true
	props := map[string]any{"primitive": primitive, "nistQuantumSecurityLevel": 0}
	if parameter != "" {
		props["parameterSetIdentifier"] = parameter
	}
	if curve != "" {
		props["curve"] = curve
	}
	if classical > 0 {
		props["classicalSecurityLevel"] = classical
	}
	raw, _ := json.Marshal(map[string]any{"assetType": "algorithm", "algorithmProperties": props})
	c.assets = append(c.assets, model.Asset{ID: id, Kind: "cryptographic-asset", Name: name, Source: "x509", ObservedAt: c.now.Format(time.RFC3339), Crypto: raw,
		Properties: map[string]string{"quantumSafe": "false"}})
	return id
}

func (c *collection) add(p string, index int, der []byte, cert *x509.Certificate) {
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	id := assetID("certificate", p, fingerprint)
	if c.certificates[id] {
		return
	}
	c.certificates[id] = true
	key := publicKey(cert)
	signature := c.algorithm(cert.SignatureAlgorithm.String(), "signature", "", "", 0)
	keyAlgorithm := c.algorithm(key.name, key.primitive, key.parameter, key.curve, key.classical)
	keyRef := c.publicKeyAsset(cert, keyAlgorithm)
	format := "X.509"
	raw, _ := json.Marshal(map[string]any{"assetType": "certificate", "certificateProperties": map[string]any{
		"notValidBefore": cert.NotBefore.UTC().Format(time.RFC3339), "notValidAfter": cert.NotAfter.UTC().Format(time.RFC3339),
		"signatureAlgorithmRef": signature, "subjectPublicKeyRef": keyRef, "certificateFormat": format, "certificateExtension": strings.TrimPrefix(strings.ToLower(path.Ext(p)), "."),
	}})
	props := map[string]string{
		"path": p, "notValidAfter": cert.NotAfter.UTC().Format(time.RFC3339), "signatureAlgorithm": cert.SignatureAlgorithm.String(),
		"publicKey": key.name, "isCA": strconv.FormatBool(cert.IsCA),
		"selfSigned": strconv.FormatBool(bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil),
	}
	switch {
	case c.now.After(cert.NotAfter):
		props["validity"] = "expired"
	case c.now.Add(expiringWithin).After(cert.NotAfter):
		props["validity"] = "expiring-within-30-days"
	case c.now.Before(cert.NotBefore):
		props["validity"] = "not-yet-valid"
	default:
		props["validity"] = "valid"
	}
	if reasons := weakness(cert, key); len(reasons) > 0 {
		props["weakness"] = strings.Join(reasons, ",")
	}
	if index > 0 {
		props["positionInFile"] = strconv.Itoa(index)
	}
	c.parsed = append(c.parsed, parsedCertificate{index: len(c.assets), cert: cert})
	c.assets = append(c.assets, model.Asset{
		ID: id, Kind: "cryptographic-asset", Name: "X.509 certificate", Source: p,
		SHA256: fingerprint, ObservedAt: c.now.Format(time.RFC3339), Crypto: raw, Properties: props, DependsOn: []string{signature, keyRef},
	})
}
