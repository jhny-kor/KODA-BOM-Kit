package certs

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	"koda.local/security-sbom-linux/internal/model"
)

const maxKeystoreBytes = 8 << 20

// JKS certificates and aliases are readable without a password. Encrypted key
// blobs are skipped, and the password-based store integrity digest is unverified.
func (c *collection) keystore(filename string, input io.Reader) {
	reader := &io.LimitedReader{R: input, N: maxKeystoreBytes + 1}
	startAssets, startParsed := len(c.assets), len(c.parsed)
	if err := c.readJKS(filename, reader); err != nil {
		// A partial or malformed store cannot establish its entry inventory.
		c.assets = c.assets[:startAssets]
		c.parsed = c.parsed[:startParsed]
		c.algorithms = map[string]bool{}
		c.keys = map[string]bool{}
		c.certificates = map[string]bool{}
		for _, a := range c.assets {
			var props struct{ AssetType string }
			json.Unmarshal(a.Crypto, &props)
			switch props.AssetType {
			case "algorithm":
				c.algorithms[a.ID] = true
			case "certificate":
				c.certificates[a.ID] = true
			case "related-crypto-material":
				c.keys[a.ID] = true
			}
		}
		c.issues = append(c.issues, model.Issue{Collector: "certificates", Status: "incomplete", Path: filename, Message: "JKS inventory unavailable: " + err.Error()})
	}
}

func jksUint32(reader io.Reader) (uint32, error) {
	var value uint32
	err := binary.Read(reader, binary.BigEndian, &value)
	return value, err
}

func javaUTF(reader io.Reader) (string, error) {
	var length uint16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return "", err
	}
	raw := make([]byte, int(length))
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", err
	}
	units := make([]uint16, 0, len(raw))
	for i := 0; i < len(raw); {
		first := raw[i]
		i++
		switch {
		case first > 0 && first < 0x80:
			units = append(units, uint16(first))
		case first&0xe0 == 0xc0 && i < len(raw) && raw[i]&0xc0 == 0x80:
			code := uint16(first&0x1f)<<6 | uint16(raw[i]&0x3f)
			i++
			if code < 0x80 && code != 0 {
				return "", errors.New("invalid alias encoding")
			}
			units = append(units, code)
		case first&0xf0 == 0xe0 && i+1 < len(raw) && raw[i]&0xc0 == 0x80 && raw[i+1]&0xc0 == 0x80:
			code := uint16(first&0xf)<<12 | uint16(raw[i]&0x3f)<<6 | uint16(raw[i+1]&0x3f)
			i += 2
			if code < 0x800 {
				return "", errors.New("invalid alias encoding")
			}
			units = append(units, code)
		default:
			return "", errors.New("invalid alias encoding")
		}
	}
	return string(utf16.Decode(units)), nil
}

func jksEntryProperties(filename, alias string) map[string]string {
	digest := sha256.Sum256([]byte(alias))
	props := map[string]string{"path": filename, "storageType": "JKS", "keystoreIntegrity": "not-verified", "keyAliasSHA256": hex.EncodeToString(digest[:])}
	if len(alias) <= 512 && strings.IndexFunc(alias, unicode.IsControl) < 0 {
		props["keyAlias"] = alias
	}
	return props
}

func (c *collection) readJKS(filename string, reader *io.LimitedReader) error {
	magic, err := jksUint32(reader)
	if err != nil {
		return errors.New("header truncated")
	}
	if magic != 0xfeedfeed {
		return errors.New("unsupported keystore format")
	}
	version, err := jksUint32(reader)
	if err != nil || (version != 1 && version != 2) {
		return errors.New("unsupported JKS version")
	}
	count, err := jksUint32(reader)
	if err != nil || count > 4096 {
		return errors.New("entry count limit or error")
	}
	for i := uint32(0); i < count; i++ {
		if len(c.assets) >= maxCerts {
			return errors.New("asset limit reached")
		}
		tag, err := jksUint32(reader)
		if err != nil || (tag != 1 && tag != 2) {
			return errors.New("invalid entry type")
		}
		alias, err := javaUTF(reader)
		if err != nil {
			return err
		}
		var timestamp int64
		if binary.Read(reader, binary.BigEndian, &timestamp) != nil {
			return errors.New("entry timestamp truncated")
		}
		chainCount := uint32(1)
		if tag == 1 {
			size, err := jksUint32(reader)
			if err != nil || size > maxKeystoreBytes || int64(size) > reader.N {
				return errors.New("encrypted entry exceeds limit")
			}
			if _, err := io.CopyN(io.Discard, reader, int64(size)); err != nil {
				return errors.New("encrypted entry truncated")
			}
			chainCount, err = jksUint32(reader)
			if err != nil || chainCount > 64 {
				return errors.New("certificate chain limit or error")
			}
		}
		var certificateIDs []string
		for j := uint32(0); j < chainCount; j++ {
			typ := "X.509"
			if version == 2 {
				typ, err = javaUTF(reader)
				if err != nil {
					return errors.New("certificate type truncated")
				}
			}
			size, err := jksUint32(reader)
			if err != nil || size > maxFileBytes || int64(size) > reader.N {
				return errors.New("certificate exceeds limit")
			}
			raw := make([]byte, int(size))
			if _, err := io.ReadFull(reader, raw); err != nil {
				return errors.New("certificate truncated")
			}
			if typ != "X.509" && typ != "X509" {
				return errors.New("unsupported certificate type")
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return errors.New("invalid X.509 certificate")
			}
			before := len(c.parsed)
			c.add(filename+"#entry-"+strconv.Itoa(int(i)), int(j), raw, cert)
			for _, item := range c.parsed[before:] {
				a := &c.assets[item.index]
				a.Source = filename
				for key, value := range jksEntryProperties(filename, alias) {
					a.Properties[key] = value
				}
				a.Properties["keystoreEntryType"] = map[bool]string{true: "private-key-entry", false: "trusted-certificate-entry"}[tag == 1]
				certificateIDs = append(certificateIDs, a.ID)
			}
		}
		if tag == 1 {
			raw, _ := json.Marshal(map[string]any{"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": map[string]string{"type": "private-key", "format": "JKS encrypted entry"}})
			c.assets = append(c.assets, model.Asset{ID: assetID("jks-key", filename, fmt.Sprint(i)), Kind: "cryptographic-asset", Name: "JKS private key metadata", Source: filename, ObservedAt: c.now.Format(time.RFC3339), Crypto: raw, Properties: jksEntryProperties(filename, alias), DependsOn: certificateIDs})
		}
	}
	// Every JKS store has a final SHA-1 integrity digest. It is only structurally
	// checked here because verifying it requires the password.
	digest := make([]byte, 20)
	if _, err := io.ReadFull(reader, digest); err != nil {
		return errors.New("integrity digest truncated")
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return errors.New("unexpected trailing data")
	}
	return nil
}
