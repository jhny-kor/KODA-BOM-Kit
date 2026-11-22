package assetimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"koda.local/security-sbom-linux/internal/model"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

func importedID(digest, id string) string {
	sum := sha256.Sum256([]byte(digest + "\x00" + id))
	return "import-" + hex.EncodeToString(sum[:12])
}

// Only non-secret metadata is accepted. Unknown fields (including key values)
// fail closed, so administrator exports cannot silently copy key material.
func importCrypto(raw json.RawMessage, digest string) (json.RawMessage, error) {
	var crypto map[string]json.RawMessage
	if json.Unmarshal(raw, &crypto) != nil {
		return nil, errors.New("cryptoProperties is required")
	}
	kind := str(crypto, "assetType")
	groups := map[string]string{"algorithm": "algorithmProperties", "certificate": "certificateProperties", "protocol": "protocolProperties", "related-crypto-material": "relatedCryptoMaterialProperties"}
	group, ok := groups[kind]
	if !ok {
		return nil, errors.New("invalid crypto asset type")
	}
	for key := range crypto {
		if key != "assetType" && key != group {
			return nil, fmt.Errorf("unsupported cryptographic field %q", key)
		}
	}
	fields := map[string]json.RawMessage{}
	if crypto[group] != nil && json.Unmarshal(crypto[group], &fields) != nil {
		return nil, errors.New("invalid crypto metadata")
	}
	allowed := map[string][]string{
		"algorithm":               {"primitive", "parameterSetIdentifier", "curve", "executionEnvironment", "implementationPlatform", "mode", "padding", "classicalSecurityLevel", "nistQuantumSecurityLevel"},
		"certificate":             {"notValidBefore", "notValidAfter", "signatureAlgorithmRef", "subjectPublicKeyRef", "certificateFormat", "certificateExtension"},
		"protocol":                {"type", "version", "cryptoRefArray", "cipherSuites"},
		"related-crypto-material": {"type", "state", "algorithmRef", "creationDate", "activationDate", "updateDate", "expirationDate", "size", "format", "securedBy"},
	}
	enums := map[string][]string{
		"algorithm.primitive":              {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"},
		"algorithm.executionEnvironment":   {"software-plain-ram", "software-encrypted-ram", "software-tee", "hardware", "other", "unknown"},
		"algorithm.implementationPlatform": {"generic", "x86_32", "x86_64", "armv7-a", "armv7-m", "armv8-a", "armv8-m", "armv9-a", "armv9-m", "s390x", "ppc64", "ppc64le", "other", "unknown"},
		"algorithm.mode":                   {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"},
		"algorithm.padding":                {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"},
		"protocol.type":                    {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"},
		"related-crypto-material.type":     {"private-key", "public-key", "secret-key", "key", "digest", "signature", "other", "unknown"},
		"related-crypto-material.state":    {"pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed"},
	}
	for key, value := range fields {
		if !slices.Contains(allowed[kind], key) {
			return nil, fmt.Errorf("unsupported cryptographic metadata %q", key)
		}
		switch key {
		case "size", "classicalSecurityLevel", "nistQuantumSecurityLevel":
			var n int
			if json.Unmarshal(value, &n) != nil || n < 0 || n > 1048576 || (key == "nistQuantumSecurityLevel" && n > 6) {
				return nil, errors.New("invalid cryptographic size or security level")
			}
		case "cipherSuites":
			var suites []importCipherSuite
			decoder := json.NewDecoder(bytes.NewReader(value))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&suites) != nil || len(suites) > 128 {
				return nil, errors.New("invalid cipher suites")
			}
			for i := range suites {
				if clean(suites[i].Name) == "" || len(suites[i].Algorithms) > 32 || len(suites[i].Identifiers) > 16 {
					return nil, errors.New("invalid cipher suite")
				}
				for j, ref := range suites[i].Algorithms {
					if clean(ref) == "" {
						return nil, errors.New("invalid cipher algorithm")
					}
					suites[i].Algorithms[j] = importedID(digest, ref)
				}
				for _, id := range suites[i].Identifiers {
					if clean(id) == "" {
						return nil, errors.New("invalid cipher identifier")
					}
				}
			}
			fields[key], _ = json.Marshal(suites)
		case "securedBy":
			var secured struct {
				Mechanism    string `json:"mechanism"`
				AlgorithmRef string `json:"algorithmRef,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewReader(value))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&secured) != nil || clean(secured.Mechanism) == "" {
				return nil, errors.New("invalid key protection metadata")
			}
			if secured.AlgorithmRef != "" {
				secured.AlgorithmRef = importedID(digest, secured.AlgorithmRef)
			}
			fields[key], _ = json.Marshal(secured)
		case "cryptoRefArray":
			var refs []string
			if json.Unmarshal(value, &refs) != nil || len(refs) > 128 {
				return nil, errors.New("invalid cryptographic references")
			}
			for i, ref := range refs {
				if clean(ref) == "" {
					return nil, errors.New("empty cryptographic reference")
				}
				refs[i] = importedID(digest, ref)
			}
			fields[key], _ = json.Marshal(refs)
		default:
			var text string
			if json.Unmarshal(value, &text) != nil || clean(text) == "" || clean(text) != text {
				return nil, errors.New("invalid cryptographic metadata value")
			}
			if choices := enums[kind+"."+key]; choices != nil && !slices.Contains(choices, text) {
				return nil, errors.New("unsupported cryptographic metadata value")
			}
			if strings.HasSuffix(key, "Date") || strings.HasPrefix(key, "notValid") {
				if _, err := time.Parse(time.RFC3339, text); err != nil {
					return nil, errors.New("invalid cryptographic timestamp")
				}
			}
			if strings.HasSuffix(key, "Ref") {
				fields[key], _ = json.Marshal(importedID(digest, text))
			}
		}
	}
	crypto[group], _ = json.Marshal(fields)
	return json.Marshal(crypto)
}

func cryptoReferences(raw json.RawMessage) []string {
	var crypto map[string]json.RawMessage
	if json.Unmarshal(raw, &crypto) != nil {
		return nil
	}
	var refs []string
	for _, group := range []string{"certificateProperties", "relatedCryptoMaterialProperties", "protocolProperties"} {
		var fields map[string]json.RawMessage
		if json.Unmarshal(crypto[group], &fields) != nil {
			continue
		}
		for key, value := range fields {
			if key == "cipherSuites" {
				var suites []importCipherSuite
				if json.Unmarshal(value, &suites) == nil {
					for _, suite := range suites {
						refs = append(refs, suite.Algorithms...)
					}
				}
			}
			if key == "securedBy" {
				var secured struct{ AlgorithmRef string }
				if json.Unmarshal(value, &secured) == nil && secured.AlgorithmRef != "" {
					refs = append(refs, secured.AlgorithmRef)
				}
			}
			if strings.HasSuffix(key, "Ref") {
				var ref string
				if json.Unmarshal(value, &ref) == nil {
					refs = append(refs, ref)
				}
			}
			if key == "cryptoRefArray" {
				var values []string
				if json.Unmarshal(value, &values) == nil {
					refs = append(refs, values...)
				}
			}
		}
	}
	return refs
}

type importCipherSuite struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

func validateCryptoObservation(props map[string]string) error {
	for _, key := range []string{"certificateSHA256", "keyAliasSHA256"} {
		if val := props[key]; val != "" {
			if b, err := hex.DecodeString(val); err != nil || len(b) != 32 {
				return errors.New("invalid cryptographic evidence digest")
			}
		}
	}
	if val := props["sessionObservedAt"]; val != "" {
		if _, err := time.Parse(time.RFC3339, val); err != nil {
			return errors.New("invalid session observation timestamp")
		}
	}
	if val := props["endpoint"]; val != "" {
		if props["transport"] == "" {
			return errors.New("endpoint requires a transport")
		}
		host, port, err := net.SplitHostPort(val)
		number, numberErr := strconv.Atoi(port)
		if err != nil || numberErr != nil || number < 1 || number > 65535 || host == "" || strings.ContainsAny(host, "/@?# ") {
			return errors.New("endpoint must be a host and numeric port")
		}
	}
	if val := props["transport"]; val != "" && val != "tcp" && val != "udp" {
		return errors.New("unsupported transport")
	}
	if val := props["observationState"]; val != "" && !slices.Contains([]string{"declared", "reported", "observed", "negotiated"}, val) {
		return errors.New("unsupported observation state")
	}
	if props["observationState"] == "negotiated" && (props["endpoint"] == "" || props["transport"] == "" || props["sessionObservedAt"] == "") {
		return errors.New("negotiated protocol requires endpoint, transport and observation time")
	}
	return nil
}

// A session export may identify its peer certificate by SHA-256. Resolve it
// only when the same evidence file contains exactly one matching certificate.
func linkSessionCertificates(assets []model.Asset) {
	byHash := map[string][]string{}
	for _, a := range assets {
		var props struct{ AssetType string }
		if json.Unmarshal(a.Crypto, &props) == nil && props.AssetType == "certificate" && a.SHA256 != "" {
			byHash[strings.ToLower(a.SHA256)] = append(byHash[strings.ToLower(a.SHA256)], a.ID)
		}
	}
	for i := range assets {
		a := &assets[i]
		refs := byHash[strings.ToLower(a.Properties["certificateSHA256"])]
		if len(refs) != 1 {
			continue
		}
		var props map[string]json.RawMessage
		if json.Unmarshal(a.Crypto, &props) != nil || str(props, "assetType") != "protocol" {
			continue
		}
		var protocol map[string]json.RawMessage
		if json.Unmarshal(props["protocolProperties"], &protocol) != nil {
			continue
		}
		var existing []string
		_ = json.Unmarshal(protocol["cryptoRefArray"], &existing)
		if !slices.Contains(existing, refs[0]) {
			existing = append(existing, refs[0])
		}
		protocol["cryptoRefArray"], _ = json.Marshal(existing)
		props["protocolProperties"], _ = json.Marshal(protocol)
		a.Crypto, _ = json.Marshal(props)
		if !slices.Contains(a.DependsOn, refs[0]) {
			a.DependsOn = append(a.DependsOn, refs[0])
		}
	}
}

func validateSessionCrypto(asset model.Asset) error {
	if asset.Properties["observationState"] != "negotiated" {
		return nil
	}
	var metadata struct {
		AssetType          string
		ProtocolProperties struct {
			Type, Version string
			CipherSuites  []importCipherSuite
		}
	}
	if json.Unmarshal(asset.Crypto, &metadata) != nil || metadata.AssetType != "protocol" || metadata.ProtocolProperties.Type != "tls" || metadata.ProtocolProperties.Version == "" || len(metadata.ProtocolProperties.CipherSuites) != 1 {
		return errors.New("negotiated TLS evidence requires protocol version and exactly one selected cipher suite")
	}
	if selected := asset.Properties["negotiatedCipherSuite"]; selected != "" && selected != metadata.ProtocolProperties.CipherSuites[0].Name {
		return errors.New("conflicting negotiated cipher suite")
	}
	return nil
}

func validateCryptoTargets(assets []model.Asset) error {
	types := map[string]string{}
	for _, a := range assets {
		var crypto struct {
			AssetType                       string
			RelatedCryptoMaterialProperties struct{ Type string }
		}
		if json.Unmarshal(a.Crypto, &crypto) == nil {
			types[a.ID] = crypto.AssetType
			if crypto.AssetType == "related-crypto-material" {
				types[a.ID] += "/" + crypto.RelatedCryptoMaterialProperties.Type
			}
		}
	}
	for _, a := range assets {
		var crypto struct {
			CertificateProperties           struct{ SignatureAlgorithmRef, SubjectPublicKeyRef string }
			RelatedCryptoMaterialProperties struct {
				AlgorithmRef string
				SecuredBy    struct{ AlgorithmRef string }
			}
			ProtocolProperties struct {
				CryptoRefArray []string
				CipherSuites   []importCipherSuite
			}
		}
		if len(a.Crypto) == 0 {
			continue
		}
		if json.Unmarshal(a.Crypto, &crypto) != nil {
			return errors.New("invalid cryptographic metadata")
		}
		algorithms := []string{crypto.CertificateProperties.SignatureAlgorithmRef, crypto.RelatedCryptoMaterialProperties.AlgorithmRef, crypto.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef}
		for _, suite := range crypto.ProtocolProperties.CipherSuites {
			algorithms = append(algorithms, suite.Algorithms...)
		}
		for _, ref := range algorithms {
			if ref != "" && types[ref] != "algorithm" {
				return errors.New("cryptographic algorithm reference has incompatible target")
			}
		}
		if ref := crypto.CertificateProperties.SubjectPublicKeyRef; ref != "" && types[ref] != "related-crypto-material/public-key" {
			return errors.New("certificate public key reference has incompatible target")
		}
		for _, ref := range crypto.ProtocolProperties.CryptoRefArray {
			if types[ref] == "" {
				return errors.New("protocol reference must identify a cryptographic asset")
			}
		}
	}
	return nil
}
