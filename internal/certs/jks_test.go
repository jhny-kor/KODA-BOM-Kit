package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
)

func jksFixture(t *testing.T, version uint32) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	block, _ := pem.Decode(certificate(t, key, &key.PublicKey, x509.ECDSAWithSHA256, time.Now().Add(time.Hour)))
	var out bytes.Buffer
	put := func(value any) {
		if err := binary.Write(&out, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	utf := func(value string) { put(uint16(len(value))); out.WriteString(value) }
	put(uint32(0xfeedfeed))
	put(version)
	put(uint32(2))
	for _, tag := range []uint32{1, 2} {
		put(tag)
		utf(map[uint32]string{1: "server-key", 2: "trust-ca"}[tag])
		put(int64(1700000000000))
		if tag == 1 {
			protected := []byte("PROTECTED-KEY-SENTINEL")
			put(uint32(len(protected)))
			out.Write(protected)
			put(uint32(1))
		}
		if version == 2 {
			utf("X.509")
		}
		put(uint32(len(block.Bytes)))
		out.Write(block.Bytes)
	}
	out.Write(make([]byte, 20))
	return out.Bytes()
}

func TestJKSMetadataAndMalformedRollback(t *testing.T) {
	for _, version := range []uint32{1, 2} {
		root := t.TempDir()
		raw := jksFixture(t, version)
		filename := filepath.Join(root, "application.jks")
		os.WriteFile(filename, raw, 0600)
		plan, err := localfs.Build(context.Background(), root, nil)
		if err != nil {
			t.Fatal(err)
		}
		assets, issues := Collect(context.Background(), plan)
		if len(issues) > 0 {
			t.Fatal(issues)
		}
		keyFound, aliasFound := false, false
		for _, a := range assets {
			if a.Name == "JKS private key metadata" {
				keyFound = true
				if len(a.DependsOn) != 1 || a.Properties["keystoreIntegrity"] != "not-verified" {
					t.Fatalf("key %+v", a)
				}
			}
			if a.Properties["keyAlias"] == "trust-ca" {
				aliasFound = true
			}
		}
		output, _ := json.Marshal(assets)
		if !keyFound || !aliasFound || strings.Contains(string(output), "PROTECTED-KEY-SENTINEL") {
			t.Fatalf("keystore metadata %s", output)
		}
		for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 1), raw[:20]} {
			os.WriteFile(filename, bad, 0600)
			plan, _ = localfs.Build(context.Background(), root, nil)
			assets, issues = Collect(context.Background(), plan)
			if len(assets) != 0 || len(issues) != 1 {
				t.Fatalf("malformed store assets=%d issues=%d", len(assets), len(issues))
			}
		}
	}
}
