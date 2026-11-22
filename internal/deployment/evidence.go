// Package deployment joins declared Kubernetes resources to locally observed
// containers. Only inventory fields and input digests survive the import.
package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/localfs"
)

const maxResources = 10000
const maxResourceLinks = 100000

type Evidence struct {
	Network      []NetworkReport `json:"networkReports,omitempty"`
	Environment  string          `json:"environment,omitempty"`
	DeploymentID string          `json:"deploymentId,omitempty"`
	SourceSHA256 []string        `json:"sourceSha256,omitempty"`
	Resources    []Resource      `json:"resources,omitempty"`
}

type Resource struct {
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	UID        string   `json:"uid"`
	Owner      string   `json:"owner,omitempty"`
	Containers []string `json:"containerIds,omitempty"`
	Targets    []string `json:"targetUIDs,omitempty"`
}

func validLabel(s string) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= 128 && strings.TrimSpace(s) == s &&
		strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) == -1
}

type resourceInput struct {
	APIVersion string
	Kind       string
	Metadata   struct {
		Name, Namespace, UID string
		Labels               map[string]string
		OwnerReferences      []struct {
			UID        string
			Controller bool
		}
	}
	Status struct {
		ContainerStatuses, InitContainerStatuses, EphemeralContainerStatuses []struct{ ContainerID string }
	}
	Spec struct {
		Selector       json.RawMessage
		DefaultBackend backend
		Rules          []struct {
			HTTP struct{ Paths []struct{ Backend backend } }
		}
	}
}
type backend struct{ Service struct{ Name string } }

var hexID = regexp.MustCompile("^[0-9a-f]{64}$")
var resourceName = regexp.MustCompile("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
var uidText = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")

// Load accepts a Kubernetes List export (or typed list / single object).
// All files in one call must be exports of the same cluster.
func Load(ctx context.Context, environment, id string, paths []string) (*Evidence, error) {
	if environment == "" && id == "" && len(paths) == 0 {
		return nil, nil
	}
	if !validLabel(environment) || !validLabel(id) || len(paths) > 12 {
		return nil, fmt.Errorf("invalid deployment label or too many Kubernetes exports")
	}
	e := &Evidence{Environment: environment, DeploymentID: id}
	var inputs []resourceInput
	for _, filename := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, err := localfs.ResolveLocal(filename)
		if err != nil {
			return nil, err
		}
		f, err := evidencefile.Open(p)
		if err != nil {
			return nil, err
		}
		raw, err := readExport(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		var header struct {
			Kind, APIVersion string
			Items            []json.RawMessage
		}
		if json.Unmarshal(raw, &header) != nil {
			return nil, fmt.Errorf("invalid Kubernetes JSON")
		}
		docs := []json.RawMessage{raw}
		if strings.HasSuffix(header.Kind, "List") {
			if header.Items == nil {
				return nil, fmt.Errorf("Kubernetes list missing items")
			}
			docs = header.Items
		}
		if len(inputs)+len(docs) > maxResources {
			return nil, fmt.Errorf("Kubernetes resource limit exceeded")
		}
		for _, b := range docs {
			var r resourceInput
			if err := json.Unmarshal(b, &r); err != nil {
				return nil, fmt.Errorf("invalid Kubernetes resource")
			}
			if header.Kind != "List" && strings.HasSuffix(header.Kind, "List") {
				kind := strings.TrimSuffix(header.Kind, "List")
				if r.Kind == "" {
					r.Kind = kind
				}
				if r.APIVersion == "" {
					r.APIVersion = header.APIVersion
				}
				if r.Kind != kind || r.APIVersion != header.APIVersion {
					return nil, fmt.Errorf("Kubernetes list item type mismatch")
				}
			}
			inputs = append(inputs, r)
		}
		e.SourceSHA256 = append(e.SourceSHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
	}
	lookup := map[string]string{}
	seen := map[string]bool{}
	podsByNamespace := map[string][]resourceInput{}
	for _, r := range inputs {
		if !supported(r) {
			return nil, fmt.Errorf("unsupported Kubernetes resource kind or apiVersion")
		}
		m := r.Metadata
		if !uidText.MatchString(m.UID) || len(m.Namespace) > 63 || !resourceName.MatchString(m.Namespace) || len(m.Name) > 253 || !resourceName.MatchString(m.Name) {
			return nil, fmt.Errorf("Kubernetes resources require namespace, name and UID")
		}
		key := r.Kind + "/" + m.Namespace + "/" + m.Name
		if seen[m.UID] || lookup[key] != "" {
			return nil, fmt.Errorf("duplicate Kubernetes resource identity")
		}
		lookup[key], seen[m.UID] = m.UID, true
		if r.Kind == "Pod" {
			podsByNamespace[m.Namespace] = append(podsByNamespace[m.Namespace], r)
		}
	}
	links := 0
	podForContainer := map[string]string{}
	for _, r := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := r.Metadata
		res := Resource{Kind: r.Kind, Name: m.Name, Namespace: m.Namespace, UID: m.UID}
		for _, o := range m.OwnerReferences {
			if o.Controller {
				if res.Owner != "" {
					return nil, fmt.Errorf("multiple Kubernetes controller owners")
				}
				res.Owner = o.UID
			}
		}
		switch r.Kind {
		case "Pod":
			statuses := slices.Concat(r.Status.ContainerStatuses, r.Status.InitContainerStatuses, r.Status.EphemeralContainerStatuses)
			for _, s := range statuses {
				runtime, id, ok := strings.Cut(s.ContainerID, "://")
				if ok && runtime != "" && hexID.MatchString(id) {
					if old := podForContainer[id]; old != "" && old != m.UID {
						return nil, fmt.Errorf("ambiguous Kubernetes container identity")
					}
					podForContainer[id] = m.UID
					res.Containers = append(res.Containers, id)
				}
			}
		case "Service":
			var selector map[string]string
			if len(r.Spec.Selector) > 0 && json.Unmarshal(r.Spec.Selector, &selector) != nil {
				return nil, fmt.Errorf("invalid Kubernetes Service selector")
			}
			if len(selector) > 0 {
				for _, pod := range podsByNamespace[m.Namespace] {
					match := true
					for k, v := range selector {
						if val, ok := pod.Metadata.Labels[k]; !ok || val != v {
							match = false
							break
						}
					}
					if match {
						res.Targets = append(res.Targets, pod.Metadata.UID)
					}
				}
			}
		case "Ingress":
			add := func(name string) {
				if uid := lookup["Service/"+m.Namespace+"/"+name]; uid != "" {
					res.Targets = append(res.Targets, uid)
				}
			}
			add(r.Spec.DefaultBackend.Service.Name)
			for _, rule := range r.Spec.Rules {
				for _, p := range rule.HTTP.Paths {
					add(p.Backend.Service.Name)
				}
			}
		}
		links += len(res.Containers) + len(res.Targets)
		if links > maxResourceLinks {
			return nil, fmt.Errorf("Kubernetes relationship limit exceeded")
		}
		slices.Sort(res.Containers)
		res.Containers = slices.Compact(res.Containers)
		slices.Sort(res.Targets)
		res.Targets = slices.Compact(res.Targets)
		e.Resources = append(e.Resources, res)
	}
	slices.Sort(e.SourceSHA256)
	slices.SortFunc(e.Resources, func(a, b Resource) int { return strings.Compare(a.UID, b.UID) })
	return e, nil
}

func supported(r resourceInput) bool {
	switch r.Kind {
	case "Pod", "Service":
		return r.APIVersion == "v1"
	case "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet":
		return r.APIVersion == "apps/v1"
	case "Job", "CronJob":
		return r.APIVersion == "batch/v1"
	case "Ingress":
		return r.APIVersion == "networking.k8s.io/v1"
	}
	return false
}
func readExport(f *os.File) ([]byte, error) {
	const limit = 16 << 20
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("Kubernetes export must be a regular file under 16 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) > limit {
		return nil, fmt.Errorf("Kubernetes export unreadable or too large")
	}
	return b, nil
}
