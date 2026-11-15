package collect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"koda.local/security-sbom-linux/internal/localfs"
)

func TestJavaDeploymentSBOMs(t *testing.T) {
	const warLocation = "suite.ear!/apps/web.war"
	const libraryLocation = warLocation + "!/WEB-INF/lib/"
	const webPURL = "pkg:maven/org.example/web@4.5.6"
	const mainPURL = "pkg:maven/org.example/primary@1.2.3"
	const supportPURL = "pkg:maven/org.example/support@2.3.4"
	const upperPURL = "pkg:maven/org.example/upper@3.4.5"
	const unselectedRangePURL = "pkg:maven/org.example/upper@3.5.0"
	const testPURL = "pkg:maven/org.example/test-helper@6.7.8"
	const wrongVersionPURL = "pkg:maven/org.example/other-version@7.8.9"
	const secondVersionPURL = "pkg:maven/org.example/other-version@7.8.10"
	const projectVersionPURL = "pkg:maven/org.example/sibling@1.2.3"
	const earPURL = "pkg:maven/org.example/suite@8.9.0"

	// Real deployment layout, with metadata that disagrees with the renamed JAR
	// and two JARs that satisfy the same range without proving a unique target.
	mainDependencies := `<properties>
		<support.version>2.3.4</support.version>
		<version.alias>${support.version}</version.alias>
		<upper.range>[3.4,3.5)</upper.range>
	</properties><dependencies>
		<dependency><groupId>${project.groupId}</groupId><artifactId>support</artifactId><version>${version.alias}</version></dependency>
		<dependency><groupId>org.example</groupId><artifactId>upper</artifactId><version>${upper.range}</version><scope>runtime</scope></dependency>
		<dependency><groupId>org.example</groupId><artifactId>sibling</artifactId><version>${project.version}</version></dependency>
		<dependency><groupId>org.example</groupId><artifactId>test-helper</artifactId><version>6.7.8</version><scope>test</scope></dependency>
		<dependency><groupId>org.example</groupId><artifactId>test-helper</artifactId><version>6.7.8</version><scope>runtime</scope></dependency>
		<dependency><groupId>org.example</groupId><artifactId>other-version</artifactId><version>[7.8,7.9)</version></dependency>
		<dependency><groupId>org.example</groupId><artifactId>other-version</artifactId><version>[7.8.9]</version></dependency>
		<dependency><groupId>org.example</groupId><artifactId>other-version</artifactId><version>[7.8.10]</version></dependency>
		<dependency><groupId>org.example</groupId><artifactId>absent</artifactId><version>9.0.0</version></dependency>
	</dependencies>`
	war := javaTestArchive(t, javaTestMetadata("web", "4.5.6", true, ""), map[string][]byte{
		"WEB-INF/lib/renamed-99.0.0.jar":       javaTestArchive(t, javaTestMetadata("primary", "1.2.3", true, mainDependencies)),
		"WEB-INF/lib/support-2.3.4.jar":        javaTestArchive(t, javaTestMetadata("support", "2.3.4", false, "")),
		"WEB-INF/lib/upper-3.4.5.JAR":          javaTestArchive(t, javaTestMetadata("upper", "3.4.5", true, "")),
		"WEB-INF/lib/upper-3.5.0.jar":          javaTestArchive(t, javaTestMetadata("upper", "3.5.0", true, "")),
		"WEB-INF/lib/test-helper-6.7.8.jar":    javaTestArchive(t, javaTestMetadata("test-helper", "6.7.8", true, "")),
		"WEB-INF/lib/other-version-7.8.9.jar":  javaTestArchive(t, javaTestMetadata("other-version", "7.8.9", true, "")),
		"WEB-INF/lib/other-version-7.8.10.jar": javaTestArchive(t, javaTestMetadata("other-version", "7.8.10", true, "")),
		"WEB-INF/lib/sibling-1.2.3.jar":        javaTestArchive(t, javaTestMetadata("sibling", "1.2.3", true, "")),
	})
	root := t.TempDir()
	ear := javaTestArchive(t, javaTestMetadata("suite", "8.9.0", true, ""), map[string][]byte{"apps/web.war": war})
	if err := os.WriteFile(filepath.Join(root, "suite.ear"), ear, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	plan, err := localfs.Build(ctx, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	bom, err := Scan(ctx, plan, "test")
	if err != nil {
		t.Fatal(err)
	}
	Scrub(bom)
	out := t.TempDir()
	if err := WriteSBOMs(out, "both", bom); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		webPURL:             warLocation,
		mainPURL:            libraryLocation + "renamed-99.0.0.jar",
		supportPURL:         libraryLocation + "support-2.3.4.jar",
		upperPURL:           libraryLocation + "upper-3.4.5.JAR",
		unselectedRangePURL: libraryLocation + "upper-3.5.0.jar",
		testPURL:            libraryLocation + "test-helper-6.7.8.jar",
		wrongVersionPURL:    libraryLocation + "other-version-7.8.9.jar",
		secondVersionPURL:   libraryLocation + "other-version-7.8.10.jar",
		projectVersionPURL:  libraryLocation + "sibling-1.2.3.jar",
		earPURL:             "suite.ear",
	}
	expectedEdges := map[[2]string]bool{
		{webPURL, mainPURL}:            true,
		{webPURL, supportPURL}:         true,
		{webPURL, upperPURL}:           true,
		{webPURL, unselectedRangePURL}: true,
		{webPURL, testPURL}:            true,
		{webPURL, wrongVersionPURL}:    true,
		{webPURL, secondVersionPURL}:   true,
		{webPURL, projectVersionPURL}:  true,
		{mainPURL, supportPURL}:        true,
		{mainPURL, upperPURL}:          true,
		{mainPURL, projectVersionPURL}: true,
	}
	var cdx struct {
		Components []struct {
			Ref      string `json:"bom-ref"`
			Name     string
			Version  string
			PURL     string
			Evidence struct{ Occurrences []struct{ Location string } }
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	readJavaTestSBOM(t, out, "sbom.cdx.json", &cdx)
	cdxRefs := make(map[string]string)
	for _, component := range cdx.Components {
		paths := make([]string, 0, len(component.Evidence.Occurrences))
		for _, occurrence := range component.Evidence.Occurrences {
			paths = append(paths, occurrence.Location)
		}
		checkJavaTestOccurrence(t, "CycloneDX", component.PURL, component.Name, component.Version, paths, expected)
		cdxRefs[component.Ref] = component.PURL
	}
	cdxEdges := make(map[[2]string]bool)
	for _, dependency := range cdx.Dependencies {
		for _, target := range dependency.DependsOn {
			from, fromFound := cdxRefs[dependency.Ref]
			to, toFound := cdxRefs[target]
			if !fromFound || !toFound {
				t.Errorf("dangling CycloneDX dependency: %q to %q", dependency.Ref, target)
			}
			cdxEdges[[2]string{from, to}] = true
		}
	}
	checkJavaTestGraph(t, "CycloneDX", mainPURL, cdxRefs, cdxEdges, expected, expectedEdges)

	var spdx struct {
		Packages []struct {
			SPDXID, Name, VersionInfo, Comment string
			ExternalRefs                       []struct{ ReferenceType, ReferenceLocator string }
		}
		Relationships []struct{ SPDXElementID, RelationshipType, RelatedSPDXElement string }
	}
	readJavaTestSBOM(t, out, "sbom.spdx.json", &spdx)
	spdxRefs := make(map[string]string)
	for _, item := range spdx.Packages {
		var purl string
		for _, ref := range item.ExternalRefs {
			if ref.ReferenceType == "purl" {
				purl = ref.ReferenceLocator
			}
		}
		if purl == "" && item.Name == "local-filesystem" {
			continue // SPDX describes the scanned directory separately.
		}
		var evidence struct{ EvidencePaths []string }
		if item.Comment != "" {
			if err := json.Unmarshal([]byte(item.Comment), &evidence); err != nil {
				t.Errorf("invalid SPDX package comment for %s: %v", item.Name, err)
			}
		}
		checkJavaTestOccurrence(t, "SPDX", purl, item.Name, item.VersionInfo, evidence.EvidencePaths, expected)
		spdxRefs[item.SPDXID] = purl
	}
	spdxEdges := make(map[[2]string]bool)
	for _, relation := range spdx.Relationships {
		from, to := relation.SPDXElementID, relation.RelatedSPDXElement
		switch relation.RelationshipType {
		case "DEPENDENCY_OF":
			from, to = to, from
		case "DEPENDS_ON":
		default:
			continue
		}
		dependent, fromFound := spdxRefs[from]
		dependency, toFound := spdxRefs[to]
		if !fromFound || !toFound {
			t.Errorf("dangling SPDX dependency: %q to %q", from, to)
		}
		spdxEdges[[2]string{dependent, dependency}] = true
	}
	checkJavaTestGraph(t, "SPDX", mainPURL, spdxRefs, spdxEdges, expected, expectedEdges)
}

func javaTestMetadata(artifactID, version string, manifest bool, dependencies string) map[string][]byte {
	base := "META-INF/maven/org.example/" + artifactID + "/"
	entries := map[string][]byte{
		base + "pom.properties": []byte(fmt.Sprintf("groupId=org.example\nartifactId=%s\nversion=%s\n", artifactID, version)),
	}
	if manifest {
		entries["META-INF/MANIFEST.MF"] = []byte("Manifest-Version: 1.0\r\nImplementation-Version: " + version + "\r\n\r\n")
	}
	if dependencies != "" {
		entries[base+"pom.xml"] = []byte(fmt.Sprintf(`<project xmlns="http://maven.apache.org/POM/4.0.0">
	<modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>%s</artifactId><version>%s</version>%s
</project>`, artifactID, version, dependencies))
	}
	return entries
}

func javaTestArchive(t *testing.T, groups ...map[string][]byte) []byte {
	t.Helper()
	var bytesOut bytes.Buffer
	archive := zip.NewWriter(&bytesOut)
	for _, entries := range groups {
		for name, data := range entries {
			entry, err := archive.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write(data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return bytesOut.Bytes()
}

func readJavaTestSBOM(t *testing.T, dir, name string, output any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, output); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func checkJavaTestOccurrence(t *testing.T, format, purl, name, version string, paths []string, expected map[string]string) {
	t.Helper()
	location, ok := expected[purl]
	if !ok {
		t.Errorf("%s unexpected Java package %s (%s@%s)", format, purl, name, version)
		return
	}
	_, identity, _ := strings.Cut(purl, "org.example/")
	expectedName, expectedVersion, _ := strings.Cut(identity, "@")
	if name != expectedName || version != expectedVersion || !slices.Equal(paths, []string{location}) {
		t.Errorf("%s %s reports %s@%s at %v, want %s@%s at %s", format, purl, name, version, paths, expectedName, expectedVersion, location)
	}
}

func checkJavaTestGraph(t *testing.T, format, mainPURL string, refs map[string]string, edges map[[2]string]bool, expected map[string]string, expectedEdges map[[2]string]bool) {
	t.Helper()
	counts := make(map[string]int)
	for _, purl := range refs {
		counts[purl]++
	}
	for purl := range expected {
		if counts[purl] != 1 {
			t.Errorf("%s has %d components for %s, want one", format, counts[purl], purl)
		}
	}
	for edge := range expectedEdges {
		if !edges[edge] {
			t.Errorf("%s missing Java dependency %s -> %s", format, edge[0], edge[1])
		}
	}
	for edge := range edges {
		if edge[0] == mainPURL && !expectedEdges[edge] {
			t.Errorf("%s fabricated Java dependency %s -> %s", format, edge[0], edge[1])
		}
	}
}

func TestJavaLocalPOMProperties(t *testing.T) {
	const doc = `<project xmlns="http://maven.apache.org/POM/4.0.0">
		<groupId>org.example</groupId><artifactId>main</artifactId><version>${revision}</version>
		<properties>
			<cycle-a>${cycle-b}</cycle-a><cycle-b>${cycle-a}</cycle-b>
			<duplicate>1.0</duplicate><duplicate>2.0</duplicate>
			<may-change>1.0</may-change><external>${env.JAVA_TEST}</external>
			<unsafe><nested>1.0</nested></unsafe>
			<same>2.5</same><same>2.5</same>
		</properties>
		<profiles><profile><id>possible</id><properties><may-change>2.0</may-change></properties></profile></profiles>
	</project>`
	var pom javaPOM
	if err := xml.Unmarshal([]byte(doc), &pom); err != nil {
		t.Fatal(err)
	}
	want := javaCoordinate{"org.example", "main", "1.0.0"}
	model, vars := pom.localModel(want)
	if model != want {
		t.Fatalf("effective coordinate from pom.properties = %+v, want %+v", model, want)
	}
	for expression, expected := range map[string]string{
		"${project.version}":           "1.0.0",
		"${pom.groupId}":               "org.example",
		"[${project.version},${same})": "[1.0.0,2.5)",
		"${cycle-a}":                   "",
		"${duplicate}":                 "",
		"${may-change}":                "",
		"${external}":                  "",
		"${unknown}":                   "",
		"${unsafe}":                    "",
		"${unclosed":                   "",
	} {
		if actual := vars.expand(expression); actual != expected {
			t.Errorf("expand %q = %q, want %q", expression, actual, expected)
		}
	}
}

func TestJavaNumericMavenRanges(t *testing.T) {
	for _, test := range []struct {
		spec, version string
		valid, match  bool
	}{
		{"[01.002]", "1.2.0", true, true},
		{"[1.0,2.0)", "2", true, false},
		{"(1.2,2.0]", "1.10", true, true},
		{"(1.2,2.0]", "1.2.0", true, false},
		{"[1.2,)", "9999999999999999999999999999999", true, true},
		{"(,1.0],[1.2,)", "1.1", true, false},
		{"(,1.0], [1.2,)", "1.3", true, true},
		{"(,1.0], [1.2,)", "0", true, true},
		{"[2,1]", "1", false, false},
		{"[2,2)", "2", false, false},
		{"[1.2,]", "2", false, false},
		{"[1,2),", "1.5", false, false},
		{"[1,2) [3,4]", "1.5", false, false},
		{"[1.2-rc,2)", "1.5", false, false},
	} {
		intervals := parseJavaVersionRanges(test.spec)
		match := slices.ContainsFunc(intervals, func(r javaVersionRange) bool { return r.contains(test.version) })
		if (len(intervals) > 0) != test.valid || match != test.match {
			t.Errorf("range %q with version %q valid=%t match=%t, want %t/%t", test.spec, test.version,
				len(intervals) > 0, match, test.valid, test.match)
		}
	}
}
