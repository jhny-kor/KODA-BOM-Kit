package certs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

// Configurations are declarations at a file and line. Includes, precedence,
// virtual hosts and runtime overrides are not resolved into effective settings.
func configConsumer(p string) string {
	switch {
	case strings.HasPrefix(p, "etc/nginx/") && strings.HasSuffix(p, ".conf"):
		return "nginx"
	case (strings.HasPrefix(p, "etc/apache2/") || strings.HasPrefix(p, "etc/httpd/")) && strings.HasSuffix(p, ".conf"):
		return "apache"
	case p == "etc/ssh/sshd_config" || strings.HasPrefix(p, "etc/ssh/sshd_config.d/") && strings.HasSuffix(p, ".conf"):
		return "sshd"
	}
	return ""
}

func (c *collection) configurations(ctx context.Context, plan localfs.Plan, root *os.Root) {
	certificates := map[string][]string{}
	for _, asset := range c.assets {
		if asset.Name == "X.509 certificate" {
			certificates[asset.Source] = append(certificates[asset.Source], asset.ID)
		}
	}
	resolveCertificate := func(name string) []string {
		if refs, exists := certificates[name]; exists {
			return refs
		}
		certificates[name] = nil
		if ctx.Err() != nil || len(c.assets) >= maxCerts {
			return nil
		}
		f, st, err := plan.OpenIndexedRegular(root, name)
		if err != nil {
			return nil
		}
		defer f.Close()
		if st.Size() > maxFileBytes {
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
		if err != nil || len(data) > maxFileBytes {
			return nil
		}
		before := len(c.parsed)
		c.file(name, data)
		for _, parsed := range c.parsed[before:] {
			certificates[name] = append(certificates[name], c.assets[parsed.index].ID)
		}
		return certificates[name]
	}
	files := 0
	for _, p := range plan.Paths {
		if ctx.Err() != nil {
			return
		}
		consumer := configConsumer(p)
		if consumer == "" {
			continue
		}
		files++
		if files > 1000 {
			c.issues = append(c.issues, model.Issue{Collector: "crypto-configuration", Status: "incomplete", Message: "configuration file limit reached"})
			return
		}
		f, st, err := plan.OpenIndexedRegular(root, p)
		if err != nil {
			continue
		}
		if st.Size() > maxFileBytes {
			f.Close()
			continue
		}
		c.configFile(p, consumer, io.LimitReader(f, maxFileBytes+1), resolveCertificate)
		f.Close()
	}
}

func (c *collection) configFile(filename, consumer string, r io.Reader, resolveCertificate func(string) []string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 65536)
	line := 0
	for scanner.Scan() {
		line++
		fields := cryptoDirectiveFields(scanner.Text(), consumer == "nginx")
		if len(fields) < 2 {
			continue
		}
		directive := strings.ToLower(fields[0])
		protocol := "tls"
		allowed := false
		switch consumer {
		case "nginx":
			allowed = directive == "ssl_protocols" || directive == "ssl_ciphers" || directive == "ssl_certificate" || directive == "ssl_trusted_certificate"
		case "apache":
			allowed = directive == "sslprotocol" || directive == "sslciphersuite" || directive == "sslcertificatefile" || directive == "sslcertificatechainfile" || directive == "sslcacertificatefile"
		case "sshd":
			protocol = "ssh"
			allowed = directive == "ciphers" || directive == "kexalgorithms" || directive == "macs" || directive == "hostkeyalgorithms" || directive == "pubkeyacceptedalgorithms"
		}
		if !allowed {
			continue
		}
		value := strings.Join(fields[1:], " ")
		if !safeCryptoValue(directive, fields[1:]) {
			if len(c.issues) < 200 {
				c.issues = append(c.issues, model.Issue{Collector: "crypto-configuration", Status: "incomplete", Path: filename, Message: "unsupported or opaque cryptographic declaration omitted"})
			}
			continue
		}
		properties := map[string]string{"consumer": consumer, "configurationPath": filename, "configurationLine": strconv.Itoa(line), "directive": fields[0], "configuredValue": value, "observationState": "declared", "configurationResolution": "file-and-line-only"}
		var refs []string
		if strings.Contains(directive, "certificate") {
			certificatePath := value
			// Only literal absolute paths have an unambiguous filesystem root here.
			if strings.HasPrefix(certificatePath, "/") && !strings.ContainsAny(certificatePath, "$% ") {
				refs = resolveCertificate(strings.TrimPrefix(path.Clean(certificatePath), "/"))
			}
			if len(refs) == 0 {
				properties["certificateResolution"] = "not-collected-or-unresolved"
			}
		}
		proto := map[string]any{"type": protocol}
		if len(refs) > 0 {
			proto["cryptoRefArray"] = refs
		}
		raw, _ := json.Marshal(map[string]any{"assetType": "protocol", "protocolProperties": proto})
		c.assets = append(c.assets, model.Asset{ID: assetID("configuration", filename, strconv.Itoa(line), directive), Kind: "cryptographic-asset", Name: fmt.Sprintf("%s %s declaration", consumer, strings.ToUpper(protocol)), Source: filename, ObservedAt: c.now.Format(time.RFC3339), Crypto: raw, Properties: properties, DependsOn: refs})
		if len(c.assets) >= maxCerts {
			c.issues = append(c.issues, model.Issue{Collector: "crypto-configuration", Status: "incomplete", Message: "cryptographic asset limit reached"})
			return
		}
	}
	if scanner.Err() != nil {
		c.issues = append(c.issues, model.Issue{Collector: "crypto-configuration", Status: "incomplete", Message: "configuration line limit or read error"})
	}
}

// Parse the first physical directive only. Quotes are recognized, while escaped
// or multiline forms are skipped because they require the server's full parser.
func cryptoDirectiveFields(line string, nginx bool) []string {
	var fields []string
	var token strings.Builder
	var quote rune
	for _, char := range line {
		if char == '\\' || char == 0 {
			return nil
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				token.WriteRune(char)
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote = char
			continue
		}
		if char == '#' || (nginx && char == ';') {
			if token.Len() > 0 {
				fields = append(fields, token.String())
			}
			return fields
		}
		if unicode.IsSpace(char) {
			if token.Len() > 0 {
				fields = append(fields, token.String())
				token.Reset()
			}
		} else {
			token.WriteRune(char)
		}
	}
	if quote != 0 {
		return nil
	}
	if token.Len() > 0 {
		fields = append(fields, token.String())
	}
	// nginx directives require a terminator; a continued line is not a complete declaration.
	if nginx {
		return nil
	}
	return fields
}

func safeCryptoValue(directive string, fields []string) bool {
	value := strings.Join(fields, " ")
	if len(value) == 0 || len(value) > 1024 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	if strings.Contains(directive, "certificate") {
		return len(fields) == 1 && len(value) <= 512 && !strings.ContainsAny(value, ":$%{};\\") && !strings.Contains(value, "-----")
	}
	if directive == "ssl_protocols" || directive == "sslprotocol" {
		for _, field := range fields {
			if !slices.Contains([]string{"all", "TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv2", "SSLv3"}, strings.TrimLeft(field, "+-")) {
				return false
			}
		}
		return true
	}
	if directive == "ssl_ciphers" || directive == "sslciphersuite" {
		if len(fields) == 2 && slices.Contains([]string{"TLSv1.3", "SSL"}, fields[0]) {
			fields = fields[1:]
		}
		if len(fields) != 1 {
			return false
		}
		for _, selector := range strings.Split(fields[0], ":") {
			selector = strings.TrimLeft(selector, "!+-")
			if strings.HasPrefix(selector, "@SECLEVEL=") && len(selector) == 11 && selector[10] >= '0' && selector[10] <= '5' {
				continue
			}
			for _, part := range strings.Split(selector, "+") {
				if !knownTLSCipher(part) {
					return false
				}
			}
		}
		return true
	}
	if len(fields) != 1 {
		return false
	}
	for _, algorithm := range strings.Split(strings.TrimLeft(fields[0], "+-^"), ",") {
		if !knownSSHAlgorithm(algorithm) {
			return false
		}
	}
	return true
}

func knownTLSCipher(name string) bool {
	if slices.Contains([]string{"ALL", "DEFAULT", "COMPLEMENTOFDEFAULT", "COMPLEMENTOFALL", "HIGH", "MEDIUM", "LOW", "aNULL", "eNULL", "kRSA", "aRSA", "RSA", "kECDHE", "kDHE", "ECDHE", "DHE", "ECDH", "DH", "ECDSA", "aECDSA", "PSK", "SRP", "AES", "AES128", "AES256", "AESGCM", "AESCCM", "CHACHA20", "SHA", "SHA1", "SHA256", "SHA384", "MD5", "3DES", "DES", "RC4", "TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv3", "SSLv2"}, name) {
		return true
	}
	if strings.HasPrefix(name, "TLS_") {
		name = strings.TrimPrefix(name, "TLS_")
		name = strings.ReplaceAll(name, "_", "-")
	}
	for _, token := range strings.Split(name, "-") {
		if !slices.Contains([]string{"ECDHE", "ECDH", "DHE", "DH", "RSA", "ECDSA", "DSS", "PSK", "SRP", "AES", "AES128", "AES256", "128", "256", "CHACHA20", "POLY1305", "GCM", "CCM", "CCM8", "CBC", "SHA", "SHA1", "SHA256", "SHA384", "SHA512", "DES", "EDE3", "3DES", "RC4", "MD5", "NULL", "WITH", "CAMELLIA128", "CAMELLIA256", "ARIA128", "ARIA256"}, token) {
			return false
		}
	}
	return strings.Contains(name, "-")
}

func knownSSHAlgorithm(name string) bool {
	if suffix := strings.Index(name, "@"); suffix >= 0 {
		if !slices.Contains([]string{"@openssh.com", "@libssh.org"}, name[suffix:]) {
			return false
		}
		name = name[:suffix]
	}
	if slices.Contains([]string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "aes128-gcm", "aes256-gcm", "chacha20-poly1305", "3des-cbc", "curve25519-sha256", "curve448-sha512", "sntrup761x25519-sha512", "mlkem768x25519-sha256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-sha2-256-etm", "hmac-sha2-512-etm", "hmac-sha1-etm", "umac-64", "umac-128", "umac-64-etm", "umac-128-etm", "ssh-ed25519", "ssh-rsa", "ssh-dss", "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519", "sk-ecdsa-sha2-nistp256"}, name) {
		return true
	}
	if strings.HasSuffix(name, "-cert-v01") {
		return knownSSHAlgorithm(strings.TrimSuffix(name, "-cert-v01"))
	}
	return false
}
