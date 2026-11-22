package certs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"koda.local/security-sbom-linux/internal/localfs"
)

func TestSSHHostKeysAndSystemCryptoPolicy(t *testing.T) {
	root := t.TempDir()
	put := func(p, data string) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	ed, _ := ssh.NewPublicKey(edPub)
	weak, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	put("etc/ssh/ssh_host_ed25519_key.pub", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ed)))+" root@internal-host\n")
	put("etc/ssh/ssh_host_rsa_key.pub", string(ssh.MarshalAuthorizedKey(weak)))
	put("etc/ssh/ssh_host_ed25519_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnot read\n")
	put("etc/crypto-policies/config", "# comment\nDEFAULT:SHA1\n")
	put("usr/share/crypto-policies/DEFAULT/opensslcnf.txt", "CipherString = @SECLEVEL=2:kEECDH:kRSA:kEDH:kPSK:kDHEPSK:kECDHEPSK:kRSAPSK:-aDSS:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8\nGroups = *X25519MLKEM768:*X25519:secp256r1/ffdhe2048\n[openssl_init]\n.include /etc/x\nCiphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_8_SHA256\nTLS.MinProtocol = TLSv1.2\nMinProtocol = TLSv1\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/crypto-policies/back-ends"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/share/crypto-policies/DEFAULT/opensslcnf.txt", filepath.Join(root, "etc/crypto-policies/back-ends/opensslcnf.config")); err != nil {
		t.Fatal(err)
	}
	put("etc/apache2/sites/ssl.conf", "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n")
	// Host "/" collection: absolute crypto-policies back-end links resolve inside the target.
	plan, err := localfs.BuildWithOptions(context.Background(), root, nil, localfs.Options{RootFilesystem: true})
	if err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), plan)
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	keys := map[string]map[string]string{}
	declarations := map[string]map[string]string{}
	for _, a := range assets {
		switch a.Name {
		case "SSH host public key":
			keys[a.Properties["sshKeyType"]] = a.Properties
			if len(a.SHA256) != 64 || len(a.DependsOn) != 1 || strings.Contains(string(a.Crypto), "root@") {
				t.Fatalf("host key asset %+v", a)
			}
		default:
			if d := a.Properties["directive"]; d != "" {
				declarations[d] = a.Properties
			}
		}
	}
	if len(keys) != 2 || keys["ssh-ed25519"]["publicKey"] != "Ed25519" || keys["ssh-rsa"]["weakness"] != "rsa-key-below-2048" ||
		!strings.HasPrefix(keys["ssh-ed25519"]["opensshFingerprint"], "SHA256:") {
		t.Fatalf("host keys %+v", keys)
	}
	if declarations["policy"]["configuredValue"] != "DEFAULT:SHA1" || declarations["policy"]["consumer"] != "crypto-policies" {
		t.Fatalf("policy %+v", declarations["policy"])
	}
	if declarations["CipherString"]["consumer"] != "openssl" || declarations["Ciphersuites"]["configuredValue"] == "" {
		t.Fatalf("openssl %+v", declarations)
	}
	if declarations["Groups"]["configuredValue"] != "*X25519MLKEM768:*X25519:secp256r1/ffdhe2048" || declarations["TLS.MinProtocol"]["weakness"] != "" {
		t.Fatalf("groups %+v", declarations)
	}
	if declarations["MinProtocol"]["weakness"] != "legacy-tls-allowed" || declarations["SSLProtocol"]["weakness"] != "" {
		t.Fatalf("legacy flags %+v %+v", declarations["MinProtocol"], declarations["SSLProtocol"])
	}
}

func TestDisabledDebianSiteDeclarationsAreIgnored(t *testing.T) {
	root := t.TempDir()
	for p, data := range map[string]string{
		"etc/apache2/sites-available/old.conf":  "SSLProtocol all\n",
		"etc/apache2/sites-available/live.conf": "SSLProtocol -all +TLSv1.2 +TLSv1.3\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/apache2/sites-enabled"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/live.conf", filepath.Join(root, "etc/apache2/sites-enabled/live.conf")); err != nil {
		t.Fatal(err)
	}
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assets, _ := Collect(context.Background(), plan)
	var paths []string
	for _, a := range assets {
		if a.Properties["directive"] != "" {
			paths = append(paths, a.Properties["configurationPath"])
		}
	}
	if len(paths) != 1 || paths[0] != "etc/apache2/sites-enabled/live.conf" {
		t.Fatalf("declarations %v", paths)
	}
}

func TestAbsoluteEnabledLinkInDirectoryScanKeepsDeclarations(t *testing.T) {
	root := t.TempDir()
	full := filepath.Join(root, "etc/apache2/sites-available/live.conf")
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("SSLProtocol all -SSLv3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc/apache2/sites-enabled"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/apache2/sites-available/live.conf", filepath.Join(root, "etc/apache2/sites-enabled/live.conf")); err != nil {
		t.Fatal(err)
	}
	plan, err := localfs.Build(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	assets, issues := Collect(context.Background(), plan)
	var weak []string
	for _, a := range assets {
		if a.Properties["directive"] == "SSLProtocol" {
			weak = append(weak, a.Properties["weakness"])
		}
	}
	if len(weak) != 1 || weak[0] != "legacy-tls-allowed" {
		t.Fatalf("declaration lost: %v", weak)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "*-enabled links could not be resolved") {
		t.Fatalf("issues %+v", issues)
	}
}
