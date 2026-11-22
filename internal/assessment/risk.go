package assessment

import (
	"cmp"
	"errors"
	"path"
	"strconv"
	"strings"
)

// Risk findings report conditions the collector already recorded in the SBOM,
// so they need no advisory input. risk_observed means the recorded evidence
// shows the condition; review_required means it could not be ruled out.
const riskSource = "KODA collection evidence"

// weaknessRemediation lists the cryptographic weaknesses the collector records.
// Other values are not reported.
var weaknessRemediation = map[string]string{
	"rsa-key-below-2048":   "Replace the key with RSA of at least 2048 bits, ECDSA or Ed25519",
	"dsa-key":              "Replace the DSA key with RSA of at least 2048 bits, ECDSA or Ed25519",
	"md5-signature":        "Reissue the certificate with a SHA-256 or stronger signature",
	"sha1-signature":       "Reissue the certificate with a SHA-256 or stronger signature",
	"legacy-tls-allowed":   "Allow only TLS 1.2 and later",
	"legacy-crypto-policy": "Replace the LEGACY system crypto policy with DEFAULT or a stricter policy",
}

// firewallVerdicts maps the OBOM firewall-declared value of a non-loopback
// host listener to a finding status and evidence. no-accept-declared is not reported.
var firewallVerdicts = map[string][2]string{
	"accept-declared":            {"risk_observed", "declared firewall rules accept this port from any source"},
	"policy-accept-declared":     {"risk_observed", "the declared default input policy accepts this port"},
	"accept-declared-restricted": {"review_required", "declared firewall rules accept this port from restricted sources"},
	"undetermined":               {"review_required", "declared firewall rules could not be fully evaluated for this port"},
	"none-observed":              {"review_required", "no active host firewall declaration was observed"},
}

var pickleRank = map[string]int{"unknown-imports": 1, "dangerous-imports": 2}

func riskFindings(components []component, services []service) ([]Finding, error) {
	out := []Finding{}
	// Risks repeat BOM text, so their total size is bounded like the
	// fixed-version output of advisory findings.
	budget, full := maxInput, false
	add := func(id, status, ref, name, evidence, remediation string) {
		budget -= len(ref) + len(name) + len(evidence)
		full = full || len(out) == 100_000 || budget < 0
		if !full {
			out = append(out, Finding{ID: id, Source: riskSource, ComponentRef: ref, ComponentName: name, Status: status, Evidence: evidence, Remediation: remediation})
		}
	}
	for _, c := range components {
		if full {
			break
		}
		if weak := c.Properties["weakness"]; weak != "" {
			where := cmp.Or(c.Properties["path"], c.Properties["configurationPath"], c.Name)
			if line := c.Properties["configurationLine"]; line != "" && where == c.Properties["configurationPath"] {
				where += ":" + line
			}
			// positionInFile counts from 0 and is set only after the first certificate.
			if position, err := strconv.Atoi(c.Properties["positionInFile"]); err == nil && position > 0 {
				where += ", certificate " + strconv.Itoa(position+1) + " in the file"
			}
			seen := map[string]bool{}
			for w := range strings.SplitSeq(weak, ",") {
				fix, known := weaknessRemediation[w]
				// A trust anchor's own signature is not verified, so it carries no signature risk.
				if !known || seen[w] || c.Properties["selfSigned"] == "true" && strings.HasSuffix(w, "-signature") {
					continue
				}
				seen[w] = true
				add("KODA-RISK-"+strings.ToUpper(w), "risk_observed", c.ID, c.Name, w+" recorded for "+where, fix)
			}
		}

		// A model directory reports the least safe pickle among its checkpoint
		// files (artifact-pickle-safety); each inspected file reports its own.
		safety, location, rollup, referenced := "", c.Name, false, false
		var imports []string
		for _, p := range c.props {
			switch p.Name {
			case "koda:domain:pickle:safety", "koda:domain:artifact-pickle-safety":
				if pickleRank[p.Value] > pickleRank[safety] {
					safety, rollup = p.Value, p.Name == "koda:domain:artifact-pickle-safety"
				}
			case "koda:domain:pickle:dangerous-import":
				imports = append(imports, p.Value)
			case "koda:domain:path":
				location = p.Value
			case "koda:domain:runtime-state":
				referenced = p.Value == "referenced-by-running-process"
			}
		}
		if safety == "" {
			continue
		}
		target := location
		if rollup {
			target = "a checkpoint file in " + path.Dir(location)
		}
		id, status, evidence, fix := "KODA-RISK-PICKLE-DANGEROUS-IMPORTS", "risk_observed", "unpickling "+target+" imports "+cmp.Or(strings.Join(imports, ", "), "callables that can run code"), "Do not load it; use a safetensors copy from a verified source"
		if safety == "unknown-imports" {
			id, status, evidence, fix = "KODA-RISK-PICKLE-UNKNOWN-IMPORTS", "review_required", "unpickling "+target+" imports modules outside the allowlist, or inspection was incomplete", "Review the imports before loading it, or use a safetensors copy"
		}
		if referenced {
			evidence += "; a running process references this model"
		}
		add(id, status, c.ID, c.Name, evidence, fix)
	}
	for _, s := range services {
		if full {
			break
		}
		for _, p := range s.Properties {
			if p.Name != "koda:obom:firewall-declared" {
				continue
			}
			if verdict, ok := firewallVerdicts[p.Value]; ok {
				add("KODA-RISK-LISTENER-FIREWALL-ACCEPT", verdict[0], s.Ref, s.Name, "listening beyond loopback; "+verdict[1], "Confirm the port must be reachable; otherwise bind the service to loopback or block the port")
			}
			break
		}
	}
	if full {
		return nil, errors.New("assessment exceeds 100000 risk findings or the risk evidence size limit")
	}
	return out, nil
}
