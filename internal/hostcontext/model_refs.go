package hostcontext

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Model servers whose command line names the model they load.
var modelServers = []string{"vllm", "text-generation-launcher", "text-generation-server", "llama-server", "llama-cli", "sglang", "tritonserver", "lmdeploy"}

var modelOptions = []string{"--model", "--model-id", "--model-path", "--model-repository", "--model-dir"}

var repositoryID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)

// parseModelReferences returns the local model paths (root-relative) or
// Hugging Face repository IDs a model server was started with. Other
// arguments are not kept. Ollama selects models per request and is not covered.
func parseModelReferences(cmdline string, denied []string) []string {
	args := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
	serving := false
	for _, a := range args {
		base := path.Base(a)
		for _, s := range modelServers {
			if base == s || strings.HasPrefix(a, s+".") || a == s {
				serving = true
			}
		}
	}
	if !serving || len(args) == 0 {
		return nil
	}
	llama := strings.HasPrefix(path.Base(args[0]), "llama")
	var refs []string
	add := func(v string) {
		switch {
		case strings.HasPrefix(v, "/"):
			if p := safeRuntimePath(v); p != "" && !blocked(p, denied) {
				v = p
			} else {
				return
			}
		case !repositoryID.MatchString(v):
			return
		}
		if !slices.Contains(refs, v) && len(refs) < 8 {
			refs = append(refs, v)
		}
	}
	for i, a := range args {
		name, value, inline := strings.Cut(a, "=")
		if slices.Contains(modelOptions, name) || (llama && name == "-m") {
			if inline {
				add(value)
			} else if i+1 < len(args) {
				add(args[i+1])
			}
		}
		// vllm serve <model>, sglang ... positional forms.
		if a == "serve" && i > 0 && path.Base(args[i-1]) == "vllm" && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			add(args[i+1])
		}
	}
	sort.Strings(refs)
	return refs
}

// safeRuntimePath converts an absolute /proc path to a root-relative one.
func safeRuntimePath(p string) string {
	p = strings.TrimSuffix(p, " (deleted)")
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\r\n") {
		return ""
	}
	return strings.TrimPrefix(path.Clean(p), "/")
}
