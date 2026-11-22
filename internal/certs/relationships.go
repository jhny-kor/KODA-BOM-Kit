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
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

type parsedCertificate struct {
	index int
	cert  *x509.Certificate
}

func (c *collection) publicKeyAsset(cert *x509.Certificate, algorithm string) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fingerprint := hex.EncodeToString(digest[:])
	id := assetID("public-key", fingerprint)
	if c.keys[id] {
		return id
	}
	c.keys[id] = true
	properties := map[string]any{"type": "public-key", "algorithmRef": algorithm, "format": "SubjectPublicKeyInfo"}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		properties["size"] = key.N.BitLen()
	case *ecdsa.PublicKey:
		properties["size"] = key.Params().BitSize
	case ed25519.PublicKey:
		properties["size"] = len(key) * 8
	}
	raw, _ := json.Marshal(map[string]any{"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": properties})
	c.assets = append(c.assets, model.Asset{ID: id, Kind: "cryptographic-asset", Name: "Certificate public key", Source: "x509", ObservedAt: c.now.Format(time.RFC3339), SHA256: fingerprint, Crypto: raw, DependsOn: []string{algorithm}})
	return id
}

// Signature verification establishes an issuer relationship only. Trust and
// revocation require policy and evidence beyond the files collected here.
func (c *collection) linkIssuers(ctx context.Context) {
	issuers := map[string][]parsedCertificate{}
	for _, item := range c.parsed {
		if item.cert.IsCA {
			issuers[string(item.cert.RawSubject)] = append(issuers[string(item.cert.RawSubject)], item)
		}
	}
	for _, item := range c.parsed {
		if ctx.Err() != nil {
			return
		}
		a := &c.assets[item.index]
		a.Properties["trustState"] = "not-evaluated"
		for i, issuer := range issuers[string(item.cert.RawIssuer)] {
			if i >= 64 {
				if len(c.issues) < 200 {
					c.issues = append(c.issues, model.Issue{Collector: "certificates", Status: "incomplete", Message: "issuer candidate limit reached"})
				}
				break
			}
			if bytes.Equal(item.cert.Raw, issuer.cert.Raw) {
				continue
			}
			if len(item.cert.AuthorityKeyId) > 0 && len(issuer.cert.SubjectKeyId) > 0 && !bytes.Equal(item.cert.AuthorityKeyId, issuer.cert.SubjectKeyId) {
				continue
			}
			if item.cert.CheckSignatureFrom(issuer.cert) == nil {
				a.DependsOn = append(a.DependsOn, c.assets[issuer.index].ID)
				a.Properties["issuerRelationship"] = "signature-verified"
			}
		}
	}
}
