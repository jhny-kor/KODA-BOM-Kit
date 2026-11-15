package collect

import (
	"context"
	"io"
	"os"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
	"koda.local/security-sbom-linux/internal/localfs"
)

type pnpmLayouts struct {
	stores   map[string]bool
	hoisted  map[string]string
	injected map[string][]string
}

type pnpmModulesManifest struct {
	PackageManager  string              `yaml:"packageManager"`
	NodeLinker      string              `yaml:"nodeLinker"`
	VirtualStoreDir string              `yaml:"virtualStoreDir"`
	Hoisted         map[string][]string `yaml:"hoistedLocations"`
	Injected        map[string][]string `yaml:"injectedDeps"`
}

func readPNPMLayouts(ctx context.Context, root *os.Root, plan localfs.Plan) pnpmLayouts {
	layouts := pnpmLayouts{stores: map[string]bool{}, hoisted: map[string]string{}, injected: map[string][]string{}}
	for _, name := range plan.Paths {
		if ctx.Err() != nil {
			break
		}
		if !strings.HasSuffix("/"+name, "/node_modules/.modules.yaml") {
			continue
		}
		manifest, ok := readPNPMModulesManifest(root, name)
		if !ok {
			continue
		}
		modules := path.Dir(name)
		project := path.Dir(modules)
		if manifest.NodeLinker == "isolated" {
			if store := pnpmStorePath(manifest.VirtualStoreDir, modules, plan); store != "" {
				layouts.stores[store] = true
			}
		}
		if manifest.NodeLinker == "hoisted" {
			for id, places := range manifest.Hoisted {
				if len(id) > 8192 {
					continue
				}
				for _, place := range places {
					if !localPNPMPath(place) || !strings.Contains("/"+place, "/node_modules/") {
						continue
					}
					file := path.Join(project, place, "package.json")
					if old, exists := layouts.hoisted[file]; exists && old != id {
						layouts.hoisted[file] = "" // conflicting place records
					} else {
						layouts.hoisted[file] = id
					}
				}
			}
		}
		for from, places := range manifest.Injected {
			if from != "." && !localPNPMPath(from) {
				continue
			}
			source := path.Join(project, from, "package.json")
			for _, place := range places {
				if localPNPMPath(place) {
					layouts.injected[source] = append(layouts.injected[source], path.Join(project, place, "package.json"))
				}
			}
		}
	}
	return layouts
}

func (layouts pnpmLayouts) isInjectedSource(name string, installed map[string]npmObservation) bool {
	source := installed[name].item
	for _, place := range layouts.injected[name] {
		copy := installed[place].item
		if place != name && copy.ID() != "" && source.Name == copy.Name && source.Version == copy.Version {
			return true
		}
	}
	return false
}

func readPNPMModulesManifest(root *os.Root, name string) (pnpmModulesManifest, bool) {
	var manifest pnpmModulesManifest
	const maxSize = 4 << 20
	f, info, err := localfs.OpenRegularEvidence(root, name)
	if err != nil {
		return manifest, false
	}
	defer f.Close()
	if info.Size() > maxSize {
		return manifest, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil || len(data) > maxSize || yaml.Unmarshal(data, &manifest) != nil {
		return manifest, false
	}
	return manifest, strings.HasPrefix(manifest.PackageManager, "pnpm@")
}

func localPNPMPath(name string) bool {
	return name != "" && name != "." && name != ".." && !path.IsAbs(name) &&
		!strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\x00\r\n\\") && path.Clean(name) == name
}

func pnpmStorePath(value, modules string, plan localfs.Plan) string {
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n\\") || path.Clean(value) != value {
		return ""
	}
	if path.IsAbs(value) {
		var within bool
		value, within = strings.CutPrefix(value, strings.TrimSuffix(plan.Root, "/")+"/")
		if !within {
			return ""
		}
	} else {
		value = path.Join(modules, value)
	}
	if !localPNPMPath(value) {
		return ""
	}
	canonical, _, err := plan.ResolveIndexedPath(value)
	if err != nil || !localPNPMPath(canonical) {
		return ""
	}
	return canonical
}

// The modules manifest describes which peer context was placed at this
// physical directory. Require the on-disk provider to agree with that context.
func hoistedPeerVersion(id, consumer, installedVersion, peer string) string {
	id, ok := strings.CutPrefix(id, consumer+"@")
	if !ok {
		return ""
	}
	var match string
	for strings.HasSuffix(id, ")") {
		depth, start := 1, len(id)-2
		for ; start >= 0 && depth > 0; start-- {
			switch id[start] {
			case ')':
				depth++
			case '(':
				depth--
			}
		}
		if depth != 0 {
			return ""
		}
		group := id[start+2 : len(id)-1]
		if nested, _, found := strings.Cut(group, "("); found {
			group = nested
		}
		if version, found := strings.CutPrefix(group, peer+"@"); found {
			if match != "" || version == "" {
				return ""
			}
			match = version
		}
		id = id[:start+1]
	}
	if id != installedVersion && !strings.HasPrefix(id, "file:") && !strings.HasPrefix(id, "link:") {
		return ""
	}
	return match
}
