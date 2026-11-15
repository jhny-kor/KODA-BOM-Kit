package collect

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/packageurl-go"
)

const maxJavaMetadataBytes = 512 << 10

var javaCoordinatePart = regexp.MustCompile(`^[[:alnum:]_][[:alnum:]_.+-]{0,179}$`)

type javaCoordinate struct {
	Group    string `xml:"groupId"`
	Artifact string `xml:"artifactId"`
	Version  string `xml:"version"`
}

func (id javaCoordinate) purl() string {
	if !javaCoordinatePart.MatchString(id.Group) || !javaCoordinatePart.MatchString(id.Artifact) ||
		!javaCoordinatePart.MatchString(id.Version) {
		return ""
	}
	return packageurl.NewPackageURL(packageurl.TypeMaven, id.Group, id.Artifact, id.Version, nil, "").ToString()
}

type javaPOM struct {
	XMLName xml.Name `xml:"project"`
	javaCoordinate
	Parent     javaCoordinate    `xml:"parent"`
	Properties javaPOMProperties `xml:"properties"`
	Profiles   []struct {
		Properties javaPOMProperties `xml:"properties"`
	} `xml:"profiles>profile"`
	Dependencies []struct {
		javaCoordinate
		Scope      string `xml:"scope"`
		Type       string `xml:"type"`
		Classifier string `xml:"classifier"`
	} `xml:"dependencies>dependency"`
}

type javaMetadata struct {
	identity     javaCoordinate
	unique       bool
	version      string
	earLib       string
	dependencies []javaDependency
}

func javaMetadataEntry(name string) bool {
	if name == "META-INF/MANIFEST.MF" || name == "META-INF/application.xml" {
		return true
	}
	suffix, ok := strings.CutPrefix(name, "META-INF/maven/")
	if !ok || strings.Count(suffix, "/") != 2 {
		return false
	}
	filename := path.Base(name)
	return filename == "pom.xml" || filename == "pom.properties"
}

func (c *javaDeployment) metadataEntry(entry *zip.File, location string) ([]byte, error) {
	limit := min(int64(maxJavaMetadataBytes), javaMetadataBudget-c.metadataBytes)
	if limit <= 0 {
		if !c.limitHit {
			c.issue(location, "Java metadata inspection reached its total resource limit")
		}
		c.limitHit = true
		return nil, zip.ErrFormat
	}
	raw, err := readJavaZIPEntry(entry, limit)
	c.metadataBytes += int64(len(raw))
	return raw, err
}

func (c *javaDeployment) readJavaMetadata(entries map[string]*zip.File, name string) javaMetadata {
	out := javaMetadata{earLib: "lib"}
	if lib := entries["META-INF/application.xml"]; lib != nil && strings.EqualFold(path.Ext(name), ".ear") {
		var descriptor struct {
			XMLName xml.Name `xml:"application"`
			Library *string  `xml:"library-directory"`
		}
		raw, err := c.metadataEntry(lib, name)
		if err != nil || xml.Unmarshal(raw, &descriptor) != nil {
			out.earLib = ""
			c.issue(name, "EAR application descriptor could not be read")
		} else if descriptor.Library != nil {
			out.earLib = strings.TrimSuffix(strings.TrimSpace(*descriptor.Library), "/")
			if !safeJavaArchivePath(out.earLib) {
				out.earLib = ""
			}
		}
	}
	if manifest := entries["META-INF/MANIFEST.MF"]; manifest != nil {
		raw, err := c.metadataEntry(manifest, name)
		if err == nil {
			out.version = javaImplementationVersion(raw)
		}
	}
	type mavenEntry struct {
		id  javaCoordinate
		pom *javaPOM
	}
	maven := map[string]mavenEntry{}
	for filename, entry := range entries {
		if c.ctx.Err() != nil {
			break
		}
		suffix, ok := strings.CutPrefix(filename, "META-INF/maven/")
		if !ok || strings.Count(suffix, "/") != 2 {
			continue
		}
		file := path.Base(suffix)
		if file != "pom.properties" && file != "pom.xml" {
			continue
		}
		fields := strings.Split(suffix, "/")
		raw, err := c.metadataEntry(entry, name)
		if err != nil {
			c.issue(name, "embedded Maven metadata could not be read within collection limits")
			continue
		}
		dir := path.Dir(suffix)
		m := maven[dir]
		if file == "pom.properties" {
			id := parseJavaPomProperties(string(raw))
			if id.Group == fields[0] && id.Artifact == fields[1] && id.purl() != "" {
				m.id = id
			}
		} else {
			var pom javaPOM
			if xml.Unmarshal(raw, &pom) == nil {
				m.pom = &pom
			}
		}
		maven[dir] = m
	}
	base := path.Base(name)
	stem := strings.TrimSuffix(base, path.Ext(base))
	var choices, matching []mavenEntry
	for directory, candidate := range maven {
		if candidate.pom != nil {
			group, artifact, _ := strings.Cut(directory, "/")
			id, _ := candidate.pom.localModel(candidate.id)
			if id.Group != group || id.Artifact != artifact ||
				(candidate.id.Version != "" && id.Version != candidate.id.Version) {
				candidate.pom = nil
			} else if candidate.id.purl() == "" {
				candidate.id = id
			}
		}
		if candidate.id.purl() == "" {
			continue
		}
		choices = append(choices, candidate)
		if stem == candidate.id.Artifact || strings.HasPrefix(stem, candidate.id.Artifact+"-") {
			matching = append(matching, candidate)
		}
	}
	out.unique = len(choices) == 1
	var chosen mavenEntry
	switch {
	case out.unique:
		chosen = choices[0]
	case len(matching) == 1:
		chosen = matching[0]
	}
	out.identity = chosen.id
	if chosen.pom != nil {
		out.dependencies = chosen.pom.localDependencies(chosen.id)
	}
	return out
}

func readJavaZIPEntry(entry *zip.File, limit int64) ([]byte, error) {
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, zip.ErrFormat
	}
	r, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = zip.ErrFormat
	}
	return data, err
}

// Maven emits literal coordinate keys using Java properties syntax.
func parseJavaPomProperties(raw string) javaCoordinate {
	props := map[string]string{}
	for line := range strings.Lines(raw) {
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			continue
		}
		key, value := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		switch key {
		case "groupId", "artifactId", "version":
			if old, found := props[key]; found && old != value {
				return javaCoordinate{}
			}
			props[key] = value
		}
	}
	return javaCoordinate{props["groupId"], props["artifactId"], props["version"]}
}

func javaImplementationVersion(raw []byte) string {
	var version string
	lines := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines = strings.ReplaceAll(lines, "\n ", "")
	for line := range strings.Lines(lines) {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		key, value, _ := strings.Cut(line, ":")
		if strings.EqualFold(key, "Implementation-Version") {
			value = strings.TrimSpace(value)
			if !javaCoordinatePart.MatchString(value) || version != "" && version != value {
				return ""
			}
			version = value
		}
	}
	return version
}
