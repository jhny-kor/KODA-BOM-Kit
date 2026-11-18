package assessment

import (
	"strings"
	"testing"
)

func TestOSVExactVersionsPreserveIdentifiers(t *testing.T) {
	raw := `{"id":"GHSA-example","aliases":["CVE-2024-12345"],"modified":"2024-01-01T00:00:00Z","references":[{"type":"ADVISORY","url":"https://example.org/advisory"}],"affected":[{"package":{"purl":"pkg:npm/example"},"versions":["1.2.3","1.2.3","1.2.4-beta.1"]}]}`
	for _, input := range []string{raw, "[" + raw + "]"} {
		out, err := parseOSV([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Rules) != 1 || len(out.Rules[0].AffectedVersions) != 2 || out.Rules[0].Aliases[0] != "CVE-2024-12345" {
			t.Fatalf("%+v", out)
		}
	}
	for _, bad := range []string{
		strings.Replace(raw, `"versions":`, `"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],"versions":`, 1),
		strings.Replace(raw, "pkg:npm/example", "pkg:npm/example@1.0.0", 1),
		strings.Replace(raw, `"id":`, `"withdrawn":"2024-02-01T00:00:00Z","id":`, 1),
		strings.Replace(raw, "pkg:npm/example", "", 1),
	} {
		if _, err := parseOSV([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
