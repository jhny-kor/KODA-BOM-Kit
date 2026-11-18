package assessment

import (
	"strings"
	"testing"
)

func TestCSAFExactAssertions(t *testing.T) {
	raw := `{"document":{"csaf_version":"2.0","tracking":{"id":"vendor-1","status":"final","current_release_date":"2025-01-01T00:00:00Z"},"references":[{"url":"https://example.org/advisory"}]},"product_tree":{"branches":[{"product":{"product_id":"one","product_identification_helper":{"purl":"pkg:npm/example@1.0.0"}}}]},"vulnerabilities":[{"cve":"CVE-2025-12345","product_status":{"known_affected":["one"]}}]}`
	out, err := parseCSAF([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Component.PURL != "pkg:npm/example" || out.Rules[0].AffectedVersions[0] != "1.0.0" {
		t.Fatal(out)
	}
	for _, bad := range []string{strings.Replace(raw, "known_affected", "known_not_affected", 1), strings.Replace(raw, "@1.0.0", "", 1), strings.Replace(raw, `"cve":`, `"flags":[{"label":"vulnerable_code_not_present"}],"cve":`, 1), strings.Replace(raw, "final", "draft", 1)} {
		if _, err := parseCSAF([]byte(bad)); err == nil {
			t.Fatal("accepted unsupported CSAF")
		}
	}
	fixed, err := parseCSAF([]byte(strings.Replace(raw, "known_affected", "fixed", 1)))
	if err != nil || len(fixed.Rules[0].FixedVersions) != 1 {
		t.Fatalf("%+v %v", fixed, err)
	}
}
