package nissbom

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

const sample = `{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1",
"metadata":{"timestamp":"2026-11-25T01:02:03Z","component":{"bom-ref":"root","type":"file","name":"web01"},
 "tools":{"components":[{"type":"application","name":"koda-bom","version":"0.1.9"}]}},
"components":[
 {"bom-ref":"a","type":"library","name":"busybox","version":"1.37.0-r14","purl":"pkg:apk/alpine/busybox@1.37.0-r14?arch=x86_64",
  "licenses":[{"license":{"id":"GPL-2.0-only"}}],"hashes":[{"alg":"SHA-1","content":"aa"},{"alg":"SHA-256","content":"bb"}],
  "properties":[{"name":"syft:location:0:path","value":"lib/apk/db/installed"},{"name":"syft:package:type","value":"apk"}]},
 {"bom-ref":"b","type":"library","name":"=cmd","version":"1","purl":"pkg:golang/github.com/acme/tool@1","supplier":{"name":"Acme"}},
 {"bom-ref":"c","type":"application","name":"plain"},
 {"bom-ref":"d","type":"device","name":"cpu0"},
 {"bom-ref":"e","type":"cryptographic-asset","name":"Ed25519"}],
"dependencies":[{"ref":"root","dependsOn":["a"]},{"ref":"b","dependsOn":["a","a"]},{"ref":"c","dependsOn":["a"]}]}`

func TestRows(t *testing.T) {
	rows, err := Rows([]byte(sample), Options{Organization: "KODA", Sequence: 7, ProductVersion: "2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(Header) != 20 || len(rows) != 4 {
		t.Fatalf("want 20 fields and header plus 3 software rows, got %d fields, %d rows", len(Header), len(rows))
	}
	want := []string{"NIS 1.0", "Deployed", "urn:uuid:1", "", "KODA-20261125-000007", "web01", "2.0", "busybox", "",
		"1.37.0-r14", "alpine", "SHA-256:bb", "lib/apk/db/installed", "koda-bom 0.1.9",
		"pkg:apk/alpine/busybox@1.37.0-r14?arch=x86_64", "'=cmd@1; plain; web01@2.0", "2026-11-25T01:02:03Z", "GPL-2.0-only", "", ""}
	if got := rows[1]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("busybox row\n got %q\nwant %q", got, want)
	}
	if rows[2][7] != "'=cmd" || rows[2][10] != "Acme" {
		t.Fatalf("formula not neutralised or recorded supplier ignored: %q", rows[2])
	}
	if rows[3][10] != "" || rows[3][14] != "" {
		t.Fatalf("component without evidence must stay blank: %q", rows[3])
	}
	var out bytes.Buffer
	if err := Write(&out, rows); err != nil || !strings.HasPrefix(out.String(), "\xEF\xBB\xBFSBOM Standard,SBOM Type,") {
		t.Fatalf("CSV lacks the byte order mark or header: %v %q", err, out.String()[:40])
	}
}

func TestRowsRejects(t *testing.T) {
	for name, c := range map[string]struct {
		raw string
		o   Options
	}{
		"not CycloneDX":   {`{"spdxVersion":"SPDX-2.3"}`, Options{Organization: "K", Sequence: 1}},
		"no timestamp":    {`{"bomFormat":"CycloneDX"}`, Options{Organization: "K", Sequence: 1}},
		"no organization": {sample, Options{Sequence: 1}},
		"bad sequence":    {sample, Options{Organization: "K", Sequence: 1000000}},
	} {
		if _, err := Rows([]byte(c.raw), c.o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNestedLifecycleAndCap(t *testing.T) {
	deps := ""
	for i := 0; i < 51; i++ {
		deps += fmt.Sprintf(`,{"ref":"p%02d","dependsOn":["n"]}`, i)
	}
	parents := ""
	for i := 0; i < 51; i++ {
		parents += fmt.Sprintf(`,{"bom-ref":"p%02d","type":"library","name":"p%02d"}`, i, i)
	}
	raw := `{"bomFormat":"CycloneDX","metadata":{"timestamp":"2026-11-25T00:00:00Z","lifecycles":[{"phase":"build"}]},
"components":[{"bom-ref":"war","type":"application","name":"app.war","hashes":[{"alg":"md5","content":"x"}],
 "components":[{"bom-ref":"n","type":"library","name":"nested"},{"bom-ref":"f","type":"file","name":"/etc/passwd"}]}` + parents + `],
"dependencies":[{"ref":"war","dependsOn":["n"]}` + deps + `]}`
	rows, err := Rows([]byte(raw), Options{Organization: "K", Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 54 || rows[1][1] != "Build" || rows[1][11] != "" || rows[2][7] != "nested" {
		t.Fatalf("want app, nested and 51 parents as Build rows without the file or the weak hash: %d %q %q", len(rows), rows[1], rows[2])
	}
	if up := rows[2][15]; strings.Count(up, ";") != 50 || !strings.HasSuffix(up, "(+2 more)") {
		t.Fatalf("parent cap: %q", up)
	}
}

func TestSupplierAndInert(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:maven/org.x/y@1#a/b":              "org.x",
		"pkg:npm/foo#a/b/c":                    "",
		"pkg:npm/@angular/core@1.0.0":          "@angular",
		"pkg:npm/%40angular/core@1.0.0":        "@angular",
		"pkg:deb/debian/curl@8?repo=a/b@c":     "debian",
		"pkg:golang/github.com/acme/tool@v1.0": "github.com/acme",
	} {
		if got := supplier(component{PURL: purl}); got != want {
			t.Errorf("%s: got %q, want %q", purl, got, want)
		}
	}
	for _, cell := range []string{"=1+1", " =1+1", "\n=1+1", "＝1+1", "|calc", "-x", "@x", "+x", "\tabc", "\r\nx"} {
		if !strings.HasPrefix(inert(cell), "'") {
			t.Errorf("%q passed as a formula", cell)
		}
	}
	if inert("libc 2.39") != "libc 2.39" || inert(" padded") != " padded" {
		t.Error("plain text changed")
	}
}
