package products

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/model"
)

func fixture(t *testing.T, root, rel string, content []byte) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, content, 0600); err != nil {
		t.Fatal(err)
	}
}
func jar(t *testing.T, root, rel string, files map[string]string) {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, content := range files {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	fixture(t, root, rel, b.Bytes())
}
func collect(t *testing.T, root string, paths ...string) ([]model.Product, []model.Issue) {
	t.Helper()
	return Collect(context.Background(), root, paths)
}
func haveIssue(issues []model.Issue, status string) bool {
	for _, i := range issues {
		if i.Status == status {
			return true
		}
	}
	return false
}

func TestJDKFullRuntimeVendorAndAllowlistedFields(t *testing.T) {
	root := t.TempDir()
	rel := "usr/lib/jvm/java-17/release"
	fixture(t, root, rel, []byte("JAVA_VERSION=\"17.0.13\"\nJAVA_RUNTIME_VERSION=\"17.0.13+11-LTS\"\nIMPLEMENTOR=\"Oracle Corporation\"\nOS_ARCH=\"x86_64\"\nJAVA_VERSION_DATE=\"2024-10-15\"\nSECRET_TOKEN=\"never-record-this\"\n"))
	products, issues := collect(t, root, rel)
	if len(products) != 1 || len(issues) != 0 {
		t.Fatalf("products=%+v issues=%+v", products, issues)
	}
	p := products[0]
	if p.Version != "17.0.13+11-LTS" || p.Vendor != "Oracle Corporation" || p.InstallPath != "usr/lib/jvm/java-17" {
		t.Fatalf("%+v", p)
	}
	encoded, _ := json.Marshal(p)
	if bytes.Contains(encoded, []byte("never-record-this")) {
		t.Fatal("unapproved metadata leaked")
	}
}
func TestUnrelatedReleaseIsNotJava(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "app/release", []byte("VERSION=1.2.3\n"))
	p, i := collect(t, root, "app/release")
	if len(p) != 0 || len(i) != 0 {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestDistinctJDKInstallationsArePreservedAndDeterministic(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"opt/jdk-a/release", "opt/jdk-b/release"} {
		fixture(t, root, p, []byte("JAVA_VERSION=\"21.0.5\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n"))
	}
	a, _ := collect(t, root, "opt/jdk-b/release", "opt/jdk-a/release", "opt/jdk-a/release")
	b, _ := collect(t, root, "opt/jdk-a/release", "opt/jdk-b/release")
	if len(a) != 2 || a[0].ID == a[1].ID || a[0].ID != b[0].ID || a[1].ID != b[1].ID {
		t.Fatalf("%+v %+v", a, b)
	}
}
func TestTomcatCorroboratesRealServerInfoAndManifest(t *testing.T) {
	root := t.TempDir()
	rel := "opt/tomcat/lib/catalina.jar"
	jar(t, root, rel, map[string]string{"org/apache/catalina/util/ServerInfo.properties": "server.info=Apache Tomcat/11.0.26\nserver.number=11.0.26.0\nserver.built=Oct 1 2026 14:00:00 UTC\n", "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nImplementation-Title: Apache Tomcat\r\nImplementation-Version: 11.0.26\r\nPassword: must-not-leak\r\n"})
	p, i := collect(t, root, rel)
	if len(p) != 1 || len(i) != 0 || p[0].Name != "Apache Tomcat" || p[0].Version != "11.0.26" || p[0].Confidence != "corroborated" || p[0].InstallPath != "opt/tomcat" {
		t.Fatalf("%+v %+v", p, i)
	}
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte("must-not-leak")) {
		t.Fatal("unapproved manifest field leaked")
	}
}
func TestTomcatMilestoneNumberIsNotFalseConflict(t *testing.T) {
	root := t.TempDir()
	rel := "tomcat/lib/catalina.jar"
	jar(t, root, rel, map[string]string{"org/apache/catalina/util/ServerInfo.properties": "server.info=Apache Tomcat/11.0.0-M25\nserver.number=11.0.0.0\n", "META-INF/MANIFEST.MF": "Implementation-Version: 11.0.0-M25\n"})
	p, i := collect(t, root, rel)
	if len(p) != 1 || p[0].Version != "11.0.0-M25" || len(i) > 0 {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestConflictingTomcatVersionsRemainUnknown(t *testing.T) {
	root := t.TempDir()
	rel := "opt/tomcat/lib/catalina.jar"
	jar(t, root, rel, map[string]string{"org/apache/catalina/util/ServerInfo.properties": "server.info=Apache Tomcat/11.0.26\nserver.number=11.0.26.0\n", "META-INF/MANIFEST.MF": "Implementation-Version: 10.1.50\n"})
	p, i := collect(t, root, rel)
	if len(p) != 1 || p[0].Version != "" || p[0].Confidence != "conflicting" || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestTomcatManifestAloneRequiresProductTitle(t *testing.T) {
	root := t.TempDir()
	rel := "lib/catalina.jar"
	jar(t, root, rel, map[string]string{"META-INF/MANIFEST.MF": "Implementation-Title: Unrelated\nImplementation-Version: 1.2.3\n"})
	p, _ := collect(t, root, rel)
	if len(p) != 0 {
		t.Fatalf("%+v", p)
	}
}
func TestArchiveEvidenceDoesNotExtractTraversalOrLeakUnrelatedContent(t *testing.T) {
	root := t.TempDir()
	rel := "lib/catalina.jar"
	jar(t, root, rel, map[string]string{"../../secrets.txt": "do-not-record", "META-INF/MANIFEST.MF": "Implementation-Title: Apache Tomcat\nImplementation-Version: 11.0.26\n"})
	p, i := collect(t, root, rel)
	if len(p) != 1 || len(i) != 0 {
		t.Fatalf("%+v %+v", p, i)
	}
	data, _ := json.Marshal(p)
	if bytes.Contains(data, []byte("do-not-record")) {
		t.Fatal("irrelevant archive content leaked")
	}
	if _, err := os.Stat(filepath.Join(root, "secrets.txt")); !os.IsNotExist(err) {
		t.Fatal("archive contents extracted")
	}
}
func TestOversizedCompressedMetadataIsRejectedBeforeReading(t *testing.T) {
	root := t.TempDir()
	rel := "lib/catalina.jar"
	jar(t, root, rel, map[string]string{"org/apache/catalina/util/ServerInfo.properties": strings.Repeat("x", maxMetadata+1)})
	p, i := collect(t, root, rel)
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestDuplicateArchiveMetadataIsRejected(t *testing.T) {
	root := t.TempDir()
	rel := "lib/catalina.jar"
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for range 2 {
		w, _ := z.Create("META-INF/MANIFEST.MF")
		_, _ = w.Write([]byte("Implementation-Title: Apache Tomcat\nImplementation-Version: 11.0.26\n"))
	}
	_ = z.Close()
	fixture(t, root, rel, buf.Bytes())
	p, i := collect(t, root, rel)
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestMalformedArchiveIsReported(t *testing.T) {
	root := t.TempDir()
	rel := "lib/catalina.jar"
	fixture(t, root, rel, []byte("not-a-zip"))
	p, i := collect(t, root, rel)
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestWebLogicManifestAndInventorySameHomeMerge(t *testing.T) {
	root := t.TempDir()
	manifest := "opt/oracle/wlserver/server/lib/weblogic.jar"
	inventory := "opt/oracle/inventory/ContentsXML/comps.xml"
	jar(t, root, manifest, map[string]string{"META-INF/MANIFEST.MF": "Implementation-Title: WebLogic Server\nImplementation-Version: 14.1.1.0.0\n"})
	fixture(t, root, inventory, []byte(`<PRD_LIST><TL_LIST><COMP_LIST><COMP NAME="oracle.wls" VER="14.1.1.0.0"><PATCH ID="12345678" STATUS="applied"/></COMP></COMP_LIST></TL_LIST></PRD_LIST>`))
	p, i := collect(t, root, manifest, inventory)
	if len(p) != 1 || len(i) != 0 || p[0].InstallPath != "opt/oracle" || p[0].Version != "14.1.1.0.0" || p[0].PatchState != "unknown" || len(p[0].PatchIDs) != 0 {
		t.Fatalf("%+v %+v", p, i)
	}
	found := false
	for _, ev := range p[0].Evidence {
		if ev.Field == "observed-patch-id-not-application-proof" && ev.Value == "12345678" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing bounded patch observation")
	}
}
func TestWebLogicShortSpecificationVersionIsNotServerVersion(t *testing.T) {
	root := t.TempDir()
	rel := "wlserver/server/lib/weblogic.jar"
	jar(t, root, rel, map[string]string{"META-INF/MANIFEST.MF": "Implementation-Title: WebLogic Server\nSpecification-Version: 4.0\n"})
	p, i := collect(t, root, rel)
	if len(p) != 1 || p[0].Version != "" || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestPatchStorageDoesNotImplyAppliedPatch(t *testing.T) {
	root := t.TempDir()
	rel := "opt/oracle/.patch_storage/12345678/inventory/ContentsXML/comps.xml"
	fixture(t, root, rel, []byte(`<COMP NAME="oracle.wls" VER="12.2.1.4.0"/>`))
	p, _ := collect(t, root, rel)
	if len(p) != 0 {
		t.Fatalf("patch cache was collected as active home: %+v", p)
	}
}
func TestOracleXMLDirectivesRejected(t *testing.T) {
	root := t.TempDir()
	rel := "inventory/ContentsXML/comps.xml"
	fixture(t, root, rel, []byte(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><COMP NAME="oracle.wls" VER="14.1.1.0.0"/>`))
	p, i := collect(t, root, rel)
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestWildFlyProductManifest(t *testing.T) {
	root := t.TempDir()
	rel := "opt/wildfly/modules/system/layers/base/org/jboss/as/product/main/dir/META-INF/MANIFEST.MF"
	fixture(t, root, rel, []byte("JBoss-Product-Release-Name: WildFly Full\nJBoss-Product-Release-Version: 37.0.0.Final\nPassword: secret\n"))
	p, i := collect(t, root, rel)
	if len(p) != 1 || len(i) != 0 || p[0].Name != "WildFly" || p[0].Version != "37.0.0.Final" || p[0].InstallPath != "opt/wildfly" {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestJEUSOnlyReportsUnsupported(t *testing.T) {
	root := t.TempDir()
	rel := "opt/jeus/version.txt"
	fixture(t, root, rel, []byte("JEUS 9.0 secret-credentials"))
	p, i := collect(t, root, rel)
	if len(p) != 0 || !haveIssue(i, "not_supported") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestNativeELFSignaturesPreserveRolesAndIgnoreSecrets(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{"usr/sbin/sshd": "OpenSSH_9.9p2", "usr/bin/ssh": "OpenSSH_9.9p2", "usr/lib64/libssl.so.3": "OpenSSL 3.5.4", "opt/php/sbin/php-fpm8.2": "PHP/8.2.35", "opt/node/bin/node": "node.js/v22.23.4"}
	paths := []string{}
	for p, v := range fixtures {
		fixture(t, root, p, []byte("\x7fELF\x00"+v+"\x00PASSWORD=never-record-this"))
		paths = append(paths, p)
	}
	products, issues := collect(t, root, paths...)
	if len(products) != 5 || len(issues) != 0 {
		t.Fatalf("%+v %+v", products, issues)
	}
	b, _ := json.Marshal(products)
	if bytes.Contains(b, []byte("never-record-this")) {
		t.Fatal("native secret leaked")
	}
	ids := map[string]bool{}
	for _, p := range products {
		if ids[p.ID] {
			t.Fatal("artifact identities collapsed")
		}
		ids[p.ID] = true
		if len(p.Evidence) < 2 {
			t.Fatalf("%+v", p)
		}
	}
}
func TestFilenameAndUnqualifiedVersionAreNotEnough(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "usr/sbin/sshd", []byte("#!/bin/sh\necho OpenSSH_9.9p2\n"))
	fixture(t, root, "usr/bin/node", []byte("\x7fELF\x00v22.23.4\x00"))
	p, i := collect(t, root, "usr/sbin/sshd", "usr/bin/node")
	if len(p) != 0 || len(i) != 0 {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestConflictingEmbeddedNativeVersions(t *testing.T) {
	root := t.TempDir()
	rel := "usr/lib/libssl.so.3"
	fixture(t, root, rel, []byte("\x7fELF\x00OpenSSL 3.5.4\x00OpenSSL 3.4.2\x00"))
	p, i := collect(t, root, rel)
	if len(p) != 1 || p[0].Version != "" || p[0].Confidence != "conflicting" || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestNoWalkForNilInputAndRejectedAbsoluteTraversal(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "jdk/release", []byte("JAVA_VERSION=\"21.0.5\"\n"))
	p, i := collect(t, root)
	if len(p) != 0 || len(i) != 0 {
		t.Fatalf("%+v %+v", p, i)
	}
	p, i = collect(t, root, "../jdk/release", "/jdk/release")
	if len(p) != 0 || len(i) != 2 {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestSymlinkCannotEscapeRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	fixture(t, outside, "release", []byte("JAVA_VERSION=\"21.0.5\"\n"))
	if err := os.Symlink(filepath.Join(outside, "release"), filepath.Join(root, "release")); err != nil {
		t.Fatal(err)
	}
	p, i := collect(t, root, "release")
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestCancellationIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, i := Collect(ctx, t.TempDir(), []string{"release"})
	if len(p) != 0 || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}

func TestConflictingWebLogicHomeDoesNotClaimTwoInstalledVersions(t *testing.T) {
	root := t.TempDir()
	manifest := "opt/oracle/wlserver/server/lib/weblogic.jar"
	inventory := "opt/oracle/inventory/ContentsXML/comps.xml"
	jar(t, root, manifest, map[string]string{"META-INF/MANIFEST.MF": "Implementation-Title: WebLogic Server\nImplementation-Version: 14.1.1.0.0\n"})
	fixture(t, root, inventory, []byte(`<COMP NAME="oracle.wls" VER="12.2.1.4.0"/>`))
	p, i := collect(t, root, manifest, inventory)
	if len(p) != 1 || p[0].Version != "" || p[0].Confidence != "conflicting" || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
func TestConflictingJavaRuntimeVersionIsUnknown(t *testing.T) {
	root := t.TempDir()
	fixture(t, root, "jdk/release", []byte("JAVA_VERSION=\"17.0.13\"\nJAVA_RUNTIME_VERSION=\"17.0.12+11\"\n"))
	p, i := collect(t, root, "jdk/release")
	if len(p) != 1 || p[0].Version != "" || p[0].Confidence != "conflicting" || !haveIssue(i, "incomplete") {
		t.Fatalf("%+v %+v", p, i)
	}
}
