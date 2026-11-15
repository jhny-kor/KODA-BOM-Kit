package staticjs

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
)

type identity struct {
	name, version string
}

const versionPattern = `((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)`

var (
	jqueryTitle    = title(`jQuery(?:[ \t]+JavaScript Library)?`)
	jqueryUITitle  = title(`jQuery UI(?:[ \t]+JavaScript Library)?`)
	fancytreeTitle = title(`(?:jQuery )?Fancytree(?:[ \t]+Plugin)?`)
	fancytreeFile  = regexp.MustCompile(`(?im)^[ \t]*(?:\*[ \t]*)?jquery\.fancytree(?:[.-][a-z][a-z0-9-]*)*\.js[ \t]*\r?$`)
	tagVersion     = regexp.MustCompile(`(?m)^[ \t]*(?:\*[ \t]*)?@version[ \t]+` + versionPattern + `[ \t]*\r?$`)

	// Modern minified Fancytree releases can omit the license banner. Match
	// the upstream core's qualified assignment, not registerExtension's
	// version field, which describes the extension rather than the release.
	fancytreeCore = regexp.MustCompile(`\.extend\([\w$]+\.ui\.fancytree\s*,\s*\{\s*version\s*:\s*["']` + versionPattern + `["']\s*,\s*buildType\s*:`)
)

func title(label string) *regexp.Regexp {
	return regexp.MustCompile(`(?im)^[ \t]*(?:\*[ \t]*)?` + label + `[ \t]+(?:-[ \t]+)?v?` +
		versionPattern + `(?:[ \t\r\n|]|$)`)
}

const maxIdentitiesPerScript = 32

func identify(data []byte) ([]identity, bool) {
	var found []identity
	limitReached := false
	add := func(name string, match [][]byte) {
		if len(match) != 2 || len(match[1]) > 80 {
			return
		}
		id := identity{name: name, version: string(match[1])}
		if !slices.Contains(found, id) {
			if len(found) >= maxIdentitiesPerScript {
				limitReached = true
				return
			}
			found = append(found, id)
		}
	}
	if bytes.Contains(data, []byte(".ui.fancytree")) {
		matches := fancytreeCore.FindAllSubmatch(data, maxIdentitiesPerScript+1)
		limitReached = len(matches) > maxIdentitiesPerScript
		for _, match := range matches {
			add("jquery.fancytree", match)
		}
	}
	for offset := 0; offset < len(data); {
		start := bytes.Index(data[offset:], []byte("/*"))
		if start == -1 {
			break
		}
		start += offset + 2
		end := bytes.Index(data[start:], []byte("*/"))
		if end == -1 {
			break
		}
		offset = start + end + 2
		if end > 8192 {
			continue
		}
		header := data[start : start+end]
		header = bytes.TrimPrefix(header, []byte("!"))
		switch {
		case bytes.Contains(header, []byte("jqueryui.com")):
			add("jquery-ui", jqueryUITitle.FindSubmatch(header))
		case bytes.Contains(header, []byte("github.com/mar10/fancytree")):
			add("jquery.fancytree", fancytreeTitle.FindSubmatch(header))
			if fancytreeFile.Match(header) {
				add("jquery.fancytree", tagVersion.FindSubmatch(header))
			}
		case bytes.Contains(header, []byte("jquery.com")) || bytes.Contains(header, []byte("jquery.org")):
			add("jquery", jqueryTitle.FindSubmatch(header))
		}
	}
	return found, limitReached
}

func filenameHint(base string) string {
	name := strings.ToLower(base)
	switch {
	case strings.HasPrefix(name, "jquery.fancytree.") || strings.HasPrefix(name, "jquery.fancytree-"):
		return "jquery.fancytree"
	case strings.HasPrefix(name, "jquery-ui.") || strings.HasPrefix(name, "jquery-ui-") || strings.HasPrefix(name, "jquery.ui."):
		return "jquery-ui"
	case strings.HasPrefix(name, "jquery-"):
		rest := strings.TrimPrefix(name, "jquery-")
		if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
			return "jquery"
		}
	case name == "jquery.js" || name == "jquery.min.js" || strings.HasPrefix(name, "jquery.slim.") || strings.HasPrefix(name, "jquery.module."):
		return "jquery"
	}
	return ""
}
