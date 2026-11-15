package collect

import (
	"cmp"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

var javaNumericVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

type javaDependency struct {
	coordinate javaCoordinate
	ranges     []javaVersionRange
	expanded   bool
}

type javaVersionRange struct {
	lower, upper               string
	includeLower, includeUpper bool
}

// For Maven range forms and ordering, see
// https://maven.apache.org/pom.html#dependency-version-requirement-specification.
// Only dotted numeric versions are ordered here. An unknown ordering can make
// even a single apparent match ambiguous, so a qualified version blocks it.
func parseJavaVersionRanges(spec string) []javaVersionRange {
	var ranges []javaVersionRange
	for spec != "" {
		if spec[0] != '(' && spec[0] != '[' {
			return nil
		}
		end := strings.IndexAny(spec, "])")
		if end < 2 {
			return nil
		}
		bound := javaVersionRange{includeLower: spec[0] == '[', includeUpper: spec[end] == ']'}
		lower, upper, interval := strings.Cut(spec[1:end], ",")
		bound.lower, bound.upper = strings.TrimSpace(lower), strings.TrimSpace(upper)
		if !interval {
			if !bound.includeLower || !bound.includeUpper || bound.lower == "" {
				return nil
			}
			bound.upper = bound.lower
		}
		if !bound.valid() {
			return nil
		}
		if len(ranges) > 0 {
			previous := ranges[len(ranges)-1]
			if previous.upper == "" || bound.lower == "" || compareJavaNumericVersions(previous.upper, bound.lower) > 0 {
				return nil
			}
		}
		ranges = append(ranges, bound)
		spec = strings.TrimSpace(spec[end+1:])
		if spec == "" {
			return ranges
		}
		if spec[0] != ',' {
			return nil
		}
		spec = strings.TrimSpace(spec[1:])
	}
	return nil
}

func (r javaVersionRange) valid() bool {
	if r.lower == "" && r.upper == "" ||
		r.lower == "" && r.includeLower || r.upper == "" && r.includeUpper ||
		r.lower != "" && !validJavaNumericVersion(r.lower) || r.upper != "" && !validJavaNumericVersion(r.upper) {
		return false
	}
	if r.lower == "" || r.upper == "" {
		return true
	}
	order := compareJavaNumericVersions(r.lower, r.upper)
	return order < 0 || order == 0 && r.includeLower && r.includeUpper
}

func (r javaVersionRange) contains(version string) bool {
	if r.lower != "" {
		order := compareJavaNumericVersions(version, r.lower)
		if order < 0 || order == 0 && !r.includeLower {
			return false
		}
	}
	if r.upper != "" {
		order := compareJavaNumericVersions(version, r.upper)
		if order > 0 || order == 0 && !r.includeUpper {
			return false
		}
	}
	return true
}

func validJavaNumericVersion(version string) bool {
	return len(version) <= 180 && javaNumericVersion.MatchString(version)
}

func compareJavaNumericVersions(left, right string) int {
	for left != "" || right != "" {
		l, leftRest, _ := strings.Cut(left, ".")
		r, rightRest, _ := strings.Cut(right, ".")
		l, r = strings.TrimLeft(l, "0"), strings.TrimLeft(r, "0")
		if order := cmp.Compare(len(l), len(r)); order != 0 {
			return order
		}
		if order := cmp.Compare(l, r); order != 0 {
			return order
		}
		left, right = leftRest, rightRest
	}
	return 0
}

func (d javaDependency) uniqueTarget(candidates []javaClasspathPackage) *pkg.Package {
	if len(candidates) == 0 {
		return nil
	}
	var target *pkg.Package
	exact := d.coordinate.purl()
	for i := range candidates {
		candidate := &candidates[i]
		matches := candidate.item.PURL == exact
		if len(d.ranges) != 0 {
			if !validJavaNumericVersion(candidate.version) {
				return nil
			}
			matches = false
			for _, interval := range d.ranges {
				if interval.contains(candidate.version) {
					matches = true
					break
				}
			}
		}
		if matches {
			if target != nil || (d.expanded || len(d.ranges) != 0) && !candidate.confirmed {
				return nil
			}
			target = &candidate.item
		}
	}
	return target
}
