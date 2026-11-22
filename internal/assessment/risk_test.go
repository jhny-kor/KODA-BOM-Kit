package assessment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func TestRecordedRiskSignalsBecomeRisksWithoutAdvisories(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","components":[
		{"type":"cryptographic-asset","name":"SSH host public key","bom-ref":"ssh","properties":[
			{"name":"koda:asset:evidence:path","value":"etc/ssh/ssh_host_rsa_key.pub"},{"name":"koda:asset:evidence:weakness","value":"rsa-key-below-2048"}]},
		{"type":"cryptographic-asset","name":"X.509 certificate","bom-ref":"cert","properties":[
			{"name":"koda:asset:evidence:path","value":"etc/pki/tls/certs/chain.pem"},{"name":"koda:asset:evidence:positionInFile","value":"1"},
			{"name":"koda:asset:evidence:weakness","value":"sha1-signature,rsa-key-below-2048"}]},
		{"type":"cryptographic-asset","name":"system crypto policy declaration","bom-ref":"policy","properties":[
			{"name":"koda:asset:evidence:configurationPath","value":"etc/crypto-policies/config"},{"name":"koda:asset:evidence:configurationLine","value":"1"},
			{"name":"koda:asset:evidence:weakness","value":"legacy-crypto-policy"}]},
		{"type":"file","name":"pytorch_model.bin","bom-ref":"file","properties":[
			{"name":"koda:domain:path","value":"srv/models/ckpt/pytorch_model.bin"},{"name":"koda:domain:pickle:safety","value":"dangerous-imports"},
			{"name":"koda:domain:pickle:dangerous-import","value":"os.system"},{"name":"koda:domain:pickle:dangerous-import","value":"builtins.eval"}]},
		{"type":"machine-learning-model","name":"ckpt","bom-ref":"model","properties":[
			{"name":"koda:domain:path","value":"srv/models/ckpt/config.json"},{"name":"koda:domain:runtime-state","value":"referenced-by-running-process"},
			{"name":"koda:domain:artifact-pickle-safety","value":"unknown-imports"}]}],
	"services":[
		{"bom-ref":"open","name":"tcp 0.0.0.0:8080","properties":[{"name":"koda:obom:firewall-declared","value":"accept-declared"}]},
		{"bom-ref":"cron","name":"cron etc/cron.d/report:1","properties":[{"name":"koda:obom:observation","value":"scheduled-job"}]}]}`
	report, err := evaluate(context.Background(), []byte(bom), nil, model.Context{})
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]string{}
	for _, f := range report.Risks {
		if f.Source != riskSource || f.Remediation == "" {
			t.Fatalf("risk %+v", f)
		}
		evidence[f.ID+" "+f.ComponentRef] = f.Evidence
	}
	want := map[string]string{
		"KODA-RISK-RSA-KEY-BELOW-2048 ssh":        "rsa-key-below-2048 recorded for etc/ssh/ssh_host_rsa_key.pub",
		"KODA-RISK-SHA1-SIGNATURE cert":           "sha1-signature recorded for etc/pki/tls/certs/chain.pem, certificate 2 in the file",
		"KODA-RISK-RSA-KEY-BELOW-2048 cert":       "rsa-key-below-2048 recorded for etc/pki/tls/certs/chain.pem, certificate 2 in the file",
		"KODA-RISK-LEGACY-CRYPTO-POLICY policy":   "legacy-crypto-policy recorded for etc/crypto-policies/config:1",
		"KODA-RISK-PICKLE-DANGEROUS-IMPORTS file": "unpickling srv/models/ckpt/pytorch_model.bin imports os.system, builtins.eval",
		"KODA-RISK-PICKLE-UNKNOWN-IMPORTS model":  "unpickling a checkpoint file in srv/models/ckpt imports modules outside the allowlist, or inspection was incomplete; a running process references this model",
		"KODA-RISK-LISTENER-FIREWALL-ACCEPT open": "listening beyond loopback; declared firewall rules accept this port from any source",
	}
	if len(evidence) != len(want) {
		t.Fatalf("risks %v", evidence)
	}
	for k, v := range want {
		if evidence[k] != v {
			t.Fatalf("%s: got %q want %q", k, evidence[k], v)
		}
	}
	if len(report.Findings) != 0 || report.AdvisoriesAt != "" || report.RulesEvaluated != 0 || report.ComponentCount != 5 {
		t.Fatalf("report %+v", report)
	}
}

// Every recorded value maps to exactly one outcome; a typo in a mapping key
// would otherwise silently drop a whole class of risks.
func TestEveryRecordedValueHasItsOutcome(t *testing.T) {
	weakness := map[string]string{
		"rsa-key-below-2048": "KODA-RISK-RSA-KEY-BELOW-2048", "dsa-key": "KODA-RISK-DSA-KEY",
		"md5-signature": "KODA-RISK-MD5-SIGNATURE", "sha1-signature": "KODA-RISK-SHA1-SIGNATURE",
		"legacy-tls-allowed": "KODA-RISK-LEGACY-TLS-ALLOWED", "legacy-crypto-policy": "KODA-RISK-LEGACY-CRYPTO-POLICY",
		"made-up": "",
	}
	for value, id := range weakness {
		risks, err := riskFindings([]component{{Asset: model.Asset{ID: "a", Properties: map[string]string{"weakness": value}}}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if id == "" && len(risks) != 0 || id != "" && (len(risks) != 1 || risks[0].ID != id || risks[0].Status != "risk_observed") {
			t.Fatalf("weakness %s: %+v", value, risks)
		}
	}
	firewall := map[string]string{
		"accept-declared": "risk_observed", "policy-accept-declared": "risk_observed",
		"accept-declared-restricted": "review_required", "undetermined": "review_required", "none-observed": "review_required",
		"no-accept-declared": "",
	}
	for value, status := range firewall {
		risks, err := riskFindings(nil, []service{{Ref: "s", Properties: []property{{"koda:obom:firewall-declared", value}}}})
		if err != nil {
			t.Fatal(err)
		}
		if status == "" && len(risks) != 0 || status != "" && (len(risks) != 1 || risks[0].ID != "KODA-RISK-LISTENER-FIREWALL-ACCEPT" || risks[0].Status != status) {
			t.Fatalf("firewall %s: %+v", value, risks)
		}
	}
	// Only the firewall verdict property carries a verdict.
	if risks, _ := riskFindings(nil, []service{{Properties: []property{{"koda:obom:bind-scope", "accept-declared"}}}}); len(risks) != 0 {
		t.Fatalf("unrelated property: %+v", risks)
	}
	pickle := map[string]string{"dangerous-imports": "risk_observed", "unknown-imports": "review_required", "allowlisted-imports-only": ""}
	for value, status := range pickle {
		for _, name := range []string{"koda:domain:pickle:safety", "koda:domain:artifact-pickle-safety"} {
			risks, err := riskFindings([]component{{props: []property{{name, value}}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if status == "" && len(risks) != 0 || status != "" && (len(risks) != 1 || risks[0].Status != status) {
				t.Fatalf("%s=%s: %+v", name, value, risks)
			}
		}
	}
}

func TestSelfSignedCertificateKeepsOnlyKeyWeakness(t *testing.T) {
	root := component{Asset: model.Asset{ID: "root", Properties: map[string]string{"selfSigned": "true", "weakness": "sha1-signature,rsa-key-below-2048"}}}
	risks, err := riskFindings([]component{root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(risks) != 1 || risks[0].ID != "KODA-RISK-RSA-KEY-BELOW-2048" {
		t.Fatalf("a trust anchor's own signature is not verified: %+v", risks)
	}
}

func TestRiskFindingsAreBounded(t *testing.T) {
	repeated := component{Asset: model.Asset{ID: "a", Properties: map[string]string{"weakness": strings.Repeat("dsa-key,", 1000)}}}
	twice := service{Ref: "s", Properties: []property{{"koda:obom:firewall-declared", "accept-declared"}, {"koda:obom:firewall-declared", "accept-declared"}}}
	risks, err := riskFindings([]component{repeated}, []service{twice})
	if err != nil || len(risks) != 2 {
		t.Fatalf("repeated values must yield one risk each: %d %v", len(risks), err)
	}
	many := make([]component, 100_001)
	for i := range many {
		many[i].Properties = map[string]string{"weakness": "dsa-key"}
	}
	if _, err := riskFindings(many, nil); err == nil {
		t.Fatal("more than 100000 risks accepted")
	}
	long := component{Asset: model.Asset{ID: "b", Properties: map[string]string{"path": strings.Repeat("a", 22<<20), "weakness": "rsa-key-below-2048,md5-signature,sha1-signature"}}}
	if _, err := riskFindings([]component{long}, nil); err == nil {
		t.Fatal("risk evidence beyond the size limit accepted")
	}
}

func TestSPDXAssetWeaknessIsReported(t *testing.T) {
	asset, err := json.Marshal(model.Asset{ID: "crypto-1", Kind: "cryptographic-asset", Name: "SSH host public key", Properties: map[string]string{"path": "etc/ssh/ssh_host_dsa_key.pub", "weakness": "dsa-key"}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"spdxVersion": "SPDX-2.3", "packages": []map[string]any{
		{"SPDXID": "SPDXRef-crypto", "name": "SSH host public key", "primaryPackagePurpose": "OTHER", "comment": "koda:asset:" + string(asset)}}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := evaluate(context.Background(), doc, nil, model.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Risks) != 1 || report.Risks[0].ID != "KODA-RISK-DSA-KEY" || report.Risks[0].Evidence != "dsa-key recorded for etc/ssh/ssh_host_dsa_key.pub" {
		t.Fatalf("risks %+v", report.Risks)
	}
}

func TestAssessmentWithoutAdvisoriesOmitsAdvisoryFields(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "bom.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := EvaluateFiles(context.Background(), sbom, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "advisories") || !strings.Contains(string(encoded), `"findings":[],"risks":[]`) {
		t.Fatalf("report %s", encoded)
	}
}

func TestAdvisoryFindingsAndRisksStayApart(t *testing.T) {
	const bom = `{"bomFormat":"CycloneDX","components":[
		{"type":"library","name":"ssh","bom-ref":"pkg","version":"1.0","purl":"pkg:rpm/redhat/openssh@1.0?distro=rhel-9.4"},
		{"type":"cryptographic-asset","name":"SSH host public key","bom-ref":"key","properties":[{"name":"koda:asset:evidence:weakness","value":"dsa-key"}]}]}`
	const rules = `{"schema":"koda-advisory-rules-v1","publishedAt":"2026-11-18T00:00:00Z","rules":[{"id":"ADV","source":"vendor","component":{"purl":"pkg:rpm/redhat/openssh?distro=rhel-9.4"},"affectedVersions":["1.0"]}]}`
	report, err := evaluate(context.Background(), []byte(bom), []byte(rules), model.Context{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "ADV" || report.Findings[0].Status != "affected_version_observed" ||
		len(report.Risks) != 1 || report.Risks[0].ID != "KODA-RISK-DSA-KEY" || report.RulesEvaluated != 1 || report.UnmatchedRules != 0 {
		t.Fatalf("report %+v", report)
	}
}

// The merged BOM repeats host packages as OBOM nodes of the host scope; those
// are matched once. Packages of running containers appear only as OBOM nodes,
// and an OBOM alone has no inventory to repeat, so those are still matched.
func TestOBOMNodesRepeatingHostPackagesAreMatchedOnce(t *testing.T) {
	const rules = `{"schema":"koda-advisory-rules-v1","publishedAt":"2026-11-18T00:00:00Z","rules":[
		{"id":"ADV-BUSYBOX","source":"vendor","component":{"purl":"pkg:apk/alpine/busybox?distro=alpine-3.21.10"},"affectedVersions":["1.37.0-r14"]},
		{"id":"ADV-OPENSSL","source":"vendor","component":{"purl":"pkg:apk/alpine/openssl?distro=alpine-3.19.0"},"affectedVersions":["3.1.4-r0"]}]}`
	const host = `{"type":"device","name":"Observed host","bom-ref":"host","properties":[{"name":"koda:obom:role","value":"host"}]}`
	const hostNode = `{"type":"library","name":"busybox","bom-ref":"host-node","version":"1.37.0-r14","purl":"pkg:apk/alpine/busybox@1.37.0-r14?distro=alpine-3.21.10",
		"properties":[{"name":"koda:obom:scope","value":"host"}]}`
	const containerNode = `{"type":"library","name":"openssl","bom-ref":"container-node","version":"3.1.4-r0","purl":"pkg:apk/alpine/openssl@3.1.4-r0?distro=alpine-3.19.0",
		"properties":[{"name":"koda:obom:scope","value":"container"}]}`
	const inventory = `{"type":"library","name":"busybox","bom-ref":"inventory","version":"1.37.0-r14","purl":"pkg:apk/alpine/busybox@1.37.0-r14?distro=alpine-3.21.10"}`
	// The same package inside a running container is a separate exposure.
	const containerCopy = `{"type":"library","name":"busybox","bom-ref":"container-copy","version":"1.37.0-r14","purl":"pkg:apk/alpine/busybox@1.37.0-r14?distro=alpine-3.21.10",
		"properties":[{"name":"koda:obom:scope","value":"container"}]}`
	for name, tc := range map[string]struct {
		components string
		want       []string
	}{
		"merged": {host + "," + inventory + "," + hostNode + "," + containerNode + "," + containerCopy, []string{"inventory", "container-node", "container-copy"}},
		"obom":   {host + "," + hostNode + "," + containerNode, []string{"host-node", "container-node"}},
	} {
		report, err := evaluate(context.Background(), []byte(`{"bomFormat":"CycloneDX","components":[`+tc.components+`]}`), []byte(rules), model.Context{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, f := range report.Findings {
			got[f.ComponentRef] = true
		}
		if len(report.Findings) != len(tc.want) || report.UnmatchedRules != 0 {
			t.Fatalf("%s: %+v", name, report.Findings)
		}
		for _, ref := range tc.want {
			if !got[ref] {
				t.Fatalf("%s: missing %s in %+v", name, ref, report.Findings)
			}
		}
	}
}
