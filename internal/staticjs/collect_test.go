package staticjs

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"koda.local/security-sbom-linux/internal/localfs"
)

func evidencePlan(t *testing.T, dir string, paths ...string) localfs.Plan {
	t.Helper()
	plan, err := localfs.Build(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan.Paths = paths
	return plan
}

func TestCollectDeploymentEvidence(t *testing.T) {
	const core = "/*! jQuery v3.1.1 | jquery.org/license */\n"
	const ui = "/*! jQuery UI - v1.12.1 - 2016-09-14\n * http://jqueryui.com\n */\n"
	const extension = `// Extension documentation
/*!
 * jquery.fancytree.wide.js
 * https://github.com/mar10/fancytree/
 * @version 2.17.0
 */
$.ui.fancytree.registerExtension({name:"wide",version:"0.0.3"})`
	dir := t.TempDir()
	writeFile(t, dir, "jquery.js", []byte(core))
	writeFile(t, dir, "jquery-4.5.6.min.js", []byte("/* stripped custom code */"))
	writeFile(t, dir, "jquery.fancytree.childcounter.min.js", []byte(`$.ui.fancytree.registerExtension({name:"childcounter",version:"1.0.0"})`))
	writeFile(t, dir, "outside-scope.js", []byte("/*! jQuery v4.5.6 | jquery.org/license */"))
	makeZIP(t, dir, "deploy.war", []entry{
		{"assets/jquery-3.1.1.min.js", core, 0},
		{"assets/renamed-bundle.js", ui + extension, 0},
		{"../outside.js", "/*! jQuery v4.5.6 | jquery.org/license */", 0},
		{"assets/link.js", "/*! jQuery v4.5.6 | jquery.org/license */", os.ModeSymlink},
		{"assets/duplicate.js", "/*! jQuery v4.5.6 | jquery.org/license */", 0},
		{"assets/duplicate.js", "/*! jQuery v4.5.7 | jquery.org/license */", 0},
	})
	paths := []string{"deploy.war", "jquery.fancytree.childcounter.min.js", "jquery-4.5.6.min.js", "jquery.js"}
	components, issues := Collect(context.Background(), evidencePlan(t, dir, paths...))
	want := []Component{
		{"jquery-ui", "1.12.1", "pkg:npm/jquery-ui@1.12.1", []string{"deploy.war!/assets/renamed-bundle.js"}, nil},
		{"jquery.fancytree", "2.17.0", "pkg:npm/jquery.fancytree@2.17.0", []string{"deploy.war!/assets/renamed-bundle.js"}, nil},
		{"jquery", "3.1.1", "pkg:npm/jquery@3.1.1", []string{"deploy.war!/assets/jquery-3.1.1.min.js", "jquery.js"}, nil},
	}
	if !reflect.DeepEqual(components, want) {
		t.Fatalf("components = %#v, want %#v", components, want)
	}
	counts := map[string]int{}
	for _, issue := range issues {
		counts[issue.Code]++
		if issue.Path == "../outside.js" {
			t.Fatal("unsafe archive path was exported")
		}
	}
	if len(issues) != 5 || counts["static_js_identity_unconfirmed"] != 2 || counts["static_js_archive_invalid_entry"] != 3 {
		t.Fatalf("unexpected issues: %#v", issues)
	}
}

func TestIdentifyRequiresProductEvidence(t *testing.T) {
	data := `
var note = "jQuery v5.6.7 https://jquery.com";
/* jquery plugin unrelated to jQuery v9.1.1 */
/* jQuery v9.3.3 | https://example.org */
/*!
 * jquery.fancytree.wide.js
 * https://github.com/mar10/fancytree/
 * @version @VERSION
 */
x.ui.fancytree.registerExtension({name:"wide",version:"0.0.3"});
x.extend(x.ui.fancytree,{version:"2.38.5",buildType:"production"});
/*!
 * jQuery JavaScript Library v1.4.4
 * http://jquery.com/
 */
/*! jQuery Fancytree Plugin - 2.17.0 - 2016-04-11T20:10
 * https://github.com/mar10/fancytree
 */
`
	got, limited := identify([]byte(data))
	want := []identity{{"jquery.fancytree", "2.38.5"}, {"jquery", "1.4.4"}, {"jquery.fancytree", "2.17.0"}}
	if limited || !reflect.DeepEqual(got, want) {
		t.Fatalf("identities = %#v, want %#v", got, want)
	}
}

func TestCollectBoundsAndRoot(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "jquery.js", []byte("/*! jQuery v2.2.4 | jquery.org/license */"))
	if err := os.Symlink(outside, filepath.Join(dir, "external")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "large.js", append(bytes.Repeat([]byte(" "), probeBytes), []byte("/*! jQuery v3.1.1 | jquery.org/license */")...))
	end := make([]byte, 22)
	copy(end, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint16(end[10:12], maxArchiveEntries+1)
	writeFile(t, dir, "oversized.war", end)
	got, issues := Collect(context.Background(), evidencePlan(t, dir, "external/jquery.js", "../outside/jquery.js", "large.js", "oversized.war"))
	if len(got) != 0 || len(issues) != 4 {
		t.Fatalf("got %#v, issues %#v", got, issues)
	}
	want := []string{"static_js_file_unavailable", "static_js_invalid_path", "static_js_probe_truncated", "static_js_archive_limit"}
	for i, issue := range issues {
		if issue.Code != want[i] {
			t.Errorf("issue %d: got %q, want %q", i, issue.Code, want[i])
		}
	}
}

func TestNestedDeploymentArchives(t *testing.T) {
	jquery := func(version string) string { return fmt.Sprintf("/*! jQuery v%s | jquery.org/license */", version) }
	webResources := archiveBytes(t, zip.Deflate, []entry{
		{"META-INF/resources/jquery.min.js", jquery("2.2.4"), 0},
		{"examples/unused.js", jquery("9.9.9"), 0},
	})
	war := archiveBytes(t, zip.Deflate, []entry{
		{"assets/jquery.min.js", jquery("3.1.1"), 0},
		{"WEB-INF/lib/web.jar", string(webResources), 0},
		{"downloads/unused.jar", string(archiveBytes(t, zip.Deflate, []entry{{"static/jquery.js", jquery("9.9.8"), 0}})), 0},
	})
	webZip := archiveBytes(t, zip.Deflate, []entry{{"assets/renamed.js", jquery("3.2.1"), 0}})
	boot := archiveBytes(t, zip.Store, []entry{
		{"BOOT-INF/classes/static/jquery.min.js", jquery("3.7.1"), 0},
		{"BOOT-INF/lib/resources.jar", string(webResources), 0},
	})
	dir := t.TempDir()
	makeZIP(t, dir, "app.ear", []entry{
		{"apps/app.war", string(war), 0},
		{"other/ui.zip", string(webZip), 0},
	})
	writeFile(t, dir, "boot.jar", boot)
	got, issues := Collect(context.Background(), evidencePlan(t, dir, "app.ear", "boot.jar"))
	want := []Component{
		{"jquery", "2.2.4", "pkg:npm/jquery@2.2.4", []string{"app.ear!/apps/app.war!/WEB-INF/lib/web.jar!/META-INF/resources/jquery.min.js", "boot.jar!/BOOT-INF/lib/resources.jar!/META-INF/resources/jquery.min.js"}, nil},
		{"jquery", "3.1.1", "pkg:npm/jquery@3.1.1", []string{"app.ear!/apps/app.war!/assets/jquery.min.js"}, nil},
		{"jquery", "3.2.1", "pkg:npm/jquery@3.2.1", []string{"app.ear!/other/ui.zip!/assets/renamed.js"}, nil},
		{"jquery", "3.7.1", "pkg:npm/jquery@3.7.1", []string{"boot.jar!/BOOT-INF/classes/static/jquery.min.js"}, nil},
	}
	if len(issues) != 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("components = %#v, want %#v; issues = %#v", got, want, issues)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("unexpected archive extraction: %#v, %v", files, err)
	}
}

func TestNestedArchiveBoundaries(t *testing.T) {
	dir := t.TempDir()
	hidden := archiveBytes(t, zip.Deflate, []entry{{"jquery.js", "/*! jQuery v9.1.1 | jquery.org/license */", 0}})
	deep := hidden
	for i := 0; i < maxArchiveDepth; i++ {
		deep = archiveBytes(t, zip.Deflate, []entry{{"nested.zip", string(deep), 0}})
	}
	writeFile(t, dir, "deep.zip", deep)
	makeZIP(t, dir, "invalid.ear", []entry{
		{"../escape.war", string(hidden), 0},
		{"symlink.war", string(hidden), os.ModeSymlink},
		{"dupe.war", string(hidden), 0},
		{"dupe.war", string(hidden), 0},
		{"invalid.war", "not an archive", 0},
	})
	got, issues := Collect(context.Background(), evidencePlan(t, dir, "deep.zip", "invalid.ear"))
	if len(got) != 0 {
		t.Fatalf("unexpected components %#v", got)
	}
	want := map[string]int{"static_js_archive_depth_limit": 1, "static_js_archive_invalid": 1, "static_js_archive_invalid_entry": 3}
	counts := map[string]int{}
	for _, issue := range issues {
		counts[issue.Code]++
		if issue.Path == "invalid.ear!/../escape.war" {
			t.Fatal("unsafe archive path was exported")
		}
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("issues = %#v; want counts %#v", issues, want)
	}
}

func TestNestedArchiveBudgetPreservesDirectScripts(t *testing.T) {
	const script = "/*! jQuery v3.1.1 | jquery.org/license */"
	nested := archiveBytes(t, zip.Deflate, []entry{{"assets/jquery.js", script, 0}})
	archive := archiveBytes(t, zip.Deflate, []entry{
		{"app.war", string(nested), 0},
		{"jquery.js", script, 0},
	})
	c := collector{ctx: context.Background(), components: map[string]*Component{}, archiveReadBudget: totalArchiveReads, nestedBytes: totalNestedBytes}
	c.scanArchive(bytes.NewReader(archive), int64(len(archive)), "app.ear", ".ear", 1)
	item := c.components["pkg:npm/jquery@3.1.1"]
	if item == nil || !reflect.DeepEqual(item.Locations, []string{"app.ear!/jquery.js"}) || len(c.issues) != 1 || c.issues[0].Code != "static_js_nested_archive_limit" {
		t.Fatalf("components = %#v; issues = %#v", c.components, c.issues)
	}
}

func writeFile(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
		t.Fatal(err)
	}
}

type entry struct {
	name, content string
	mode          os.FileMode
}

func makeZIP(t *testing.T, dir, name string, entries []entry) {
	t.Helper()
	writeFile(t, dir, name, archiveBytes(t, zip.Deflate, entries))
}

func archiveBytes(t *testing.T, method uint16, entries []entry) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	z := zip.NewWriter(buf)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: method}
		header.SetMode(entry.mode | 0644)
		w, err := z.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
