package collect

import (
	"encoding/xml"
	"slices"
	"strings"
)

const maxJavaVersionExpression = 512

type javaPOMProperties struct {
	Values []javaPOMProperty `xml:",any"`
}

type javaPOMProperty struct {
	XMLName xml.Name
	Text    string     `xml:",chardata"`
	Nested  []struct{} `xml:",any"`
}

type javaPOMVariables map[string]string

func (p javaPOM) localModel(observed javaCoordinate) (javaCoordinate, javaPOMVariables) {
	model := p.javaCoordinate
	if model.Group == "" {
		model.Group = p.Parent.Group
	}
	if model.Version == "" {
		model.Version = p.Parent.Version
	}
	vars := make(javaPOMVariables)
	for _, prop := range p.Properties.Values {
		key := prop.XMLName.Local
		value := strings.TrimSpace(prop.Text)
		if len(prop.Nested) != 0 || len(value) > maxJavaVersionExpression {
			value = ""
		}
		if previous, ok := vars[key]; ok && previous != value {
			value = ""
		}
		vars[key] = value
	}
	// The active build profiles cannot be reconstructed from an embedded POM.
	for _, profile := range p.Profiles {
		for _, prop := range profile.Properties.Values {
			if vars[prop.XMLName.Local] != strings.TrimSpace(prop.Text) || len(prop.Nested) != 0 {
				delete(vars, prop.XMLName.Local)
			}
		}
	}
	vars.addCoordinates(model, p.Parent)
	model = javaCoordinate{vars.expand(model.Group), vars.expand(model.Artifact), vars.expand(model.Version)}
	if model.Version == "" && observed.Version != "" {
		// pom.properties records the packaged version for CI-friendly builds.
		model.Version = observed.Version
	}
	vars.addCoordinates(model, p.Parent)
	return model, vars
}

func (values javaPOMVariables) addCoordinates(project, parent javaCoordinate) {
	for _, prefix := range []string{"project.", "pom."} {
		values[prefix+"groupId"] = project.Group
		values[prefix+"artifactId"] = project.Artifact
		values[prefix+"version"] = project.Version
		values[prefix+"parent.groupId"] = parent.Group
		values[prefix+"parent.artifactId"] = parent.Artifact
		values[prefix+"parent.version"] = parent.Version
	}
}

func (values javaPOMVariables) expand(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > maxJavaVersionExpression {
		return ""
	}
	if !strings.Contains(value, "${") {
		return value
	}
	replacements := 64
	return strings.TrimSpace(values.expandBounded(value, 0, &replacements))
}

func (values javaPOMVariables) expandBounded(value string, depth int, replacements *int) string {
	if len(value) > maxJavaVersionExpression || depth > 16 {
		return ""
	}
	var expanded strings.Builder
	for {
		literal, rest, variable := strings.Cut(value, "${")
		if expanded.Len()+len(literal) > maxJavaVersionExpression {
			return ""
		}
		expanded.WriteString(literal)
		if !variable {
			return expanded.String()
		}
		key, tail, closed := strings.Cut(rest, "}")
		raw := values[key]
		if !closed || raw == "" || *replacements == 0 || strings.HasPrefix(key, "env.") {
			return ""
		}
		*replacements--
		replacement := values.expandBounded(raw, depth+1, replacements)
		if replacement == "" || expanded.Len()+len(replacement) > maxJavaVersionExpression {
			return ""
		}
		expanded.WriteString(replacement)
		value = tail
	}
}

func (p javaPOM) localDependencies(observed javaCoordinate) []javaDependency {
	_, vars := p.localModel(observed)
	type conditions struct{ version, scope string }
	declared := map[[2]string]conditions{}
	conflicting := map[[2]string]bool{}
	var dependencies []javaDependency
	for _, dep := range p.Dependencies {
		if dep.Classifier != "" || dep.Type != "" && dep.Type != "jar" {
			continue
		}
		coordinate := javaCoordinate{vars.expand(dep.Group), vars.expand(dep.Artifact), vars.expand(dep.Version)}
		if !javaCoordinatePart.MatchString(coordinate.Group) || !javaCoordinatePart.MatchString(coordinate.Artifact) {
			continue
		}
		key := [2]string{coordinate.Group, coordinate.Artifact}
		scope := dep.Scope
		if scope == "" {
			scope = "compile"
		}
		current := conditions{coordinate.Version, scope}
		if previous, exists := declared[key]; exists {
			// Maven requires one declaration per group, artifact, type and classifier.
			// A copied pair of different versions or scopes cannot prove an edge.
			if previous != current {
				conflicting[key] = true
			}
			continue
		}
		declared[key] = current
		if scope != "compile" && scope != "runtime" {
			continue
		}
		dependency := javaDependency{coordinate: coordinate,
			expanded: strings.Contains(dep.Group, "${") || strings.Contains(dep.Artifact, "${") || strings.Contains(dep.Version, "${")}
		if !javaCoordinatePart.MatchString(coordinate.Version) {
			dependency.ranges = parseJavaVersionRanges(coordinate.Version)
			if len(dependency.ranges) == 0 {
				continue
			}
		}
		dependencies = append(dependencies, dependency)
	}
	return slices.DeleteFunc(dependencies, func(d javaDependency) bool {
		return conflicting[[2]string{d.coordinate.Group, d.coordinate.Artifact}]
	})
}
