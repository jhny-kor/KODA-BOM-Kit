package certs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"koda.local/security-sbom-linux/internal/model"
)

// sshHostKeyPath matches OpenSSH host public keys such as etc/ssh/ssh_host_ed25519_key.pub.
func sshHostKeyPath(p string) bool {
	dir, base := path.Split(p)
	return dir == "etc/ssh/" && strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key.pub")
}

// sshHostKey records one host public key. The trailing comment (usually
// user@host) is not emitted; the key is identified by its wire-format SHA-256.
func (c *collection) sshHostKey(p string, data []byte) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		c.issues = append(c.issues, model.Issue{Collector: "certificates", Status: "incomplete", Path: p, Message: "SSH host public key could not be parsed"})
		return
	}
	info := keyInfo{name: key.Type(), primitive: "unknown"}
	if ck, ok := key.(ssh.CryptoPublicKey); ok {
		info = keyInfoOf(ck.CryptoPublicKey(), key.Type())
	}
	if key.Type() == ssh.KeyAlgoDSA {
		info = keyInfo{name: "DSA", primitive: "signature"}
	}
	algorithm := c.algorithm(info.name, info.primitive, info.parameter, info.curve, info.classical)
	digest := sha256.Sum256(key.Marshal())
	fingerprint := hex.EncodeToString(digest[:])
	material := map[string]any{"type": "public-key", "algorithmRef": algorithm, "format": "openssh"}
	switch {
	case strings.HasPrefix(info.name, "RSA-"):
		material["size"], _ = strconv.Atoi(info.parameter)
	case info.curve == "Ed25519":
		material["size"] = 256
	case strings.HasPrefix(info.name, "ECDSA-"):
		material["size"] = map[string]int{"P-256": 256, "P-384": 384, "P-521": 521}[info.curve]
	}
	raw, _ := json.Marshal(map[string]any{"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material})
	props := map[string]string{"path": p, "consumer": "sshd", "sshKeyType": key.Type(), "publicKey": info.name, "opensshFingerprint": ssh.FingerprintSHA256(key), "quantumSafe": "false"}
	var weak []string
	if bits, err := strconv.Atoi(info.parameter); strings.HasPrefix(info.name, "RSA-") && err == nil && bits < 2048 {
		weak = append(weak, "rsa-key-below-2048")
	}
	if info.name == "DSA" {
		weak = append(weak, "dsa-key")
	}
	if len(weak) > 0 {
		props["weakness"] = strings.Join(weak, ",")
	}
	c.assets = append(c.assets, model.Asset{
		ID: assetID("ssh-host-key", p, fingerprint), Kind: "cryptographic-asset", Name: "SSH host public key", Source: p,
		SHA256: fingerprint, ObservedAt: c.now.Format(time.RFC3339), Crypto: raw, Properties: props, DependsOn: []string{algorithm},
	})
}
