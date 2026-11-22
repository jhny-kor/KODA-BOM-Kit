package deployment

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// EnrichJSON adds only resources connected to container IDs observed in the
// collection. Service selectors describe intended routing, never observed traffic.
func EnrichJSON(raw []byte, e *Evidence) ([]byte, error) {
	if e == nil {
		return raw, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(doc["metadata"], &meta); err != nil {
		return nil, err
	}
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var props []prop
	if b := meta["properties"]; b != nil {
		if err := json.Unmarshal(b, &props); err != nil {
			return nil, err
		}
	}
	if e.Environment != "" {
		props = append(props, prop{"koda:deployment:environment", e.Environment})
	}
	if e.DeploymentID != "" {
		props = append(props, prop{"koda:deployment:id", e.DeploymentID})
	}
	for _, hash := range e.SourceSHA256 {
		props = append(props, prop{"koda:kubernetes:source-sha256", hash})
	}
	var components, services []json.RawMessage
	if b := doc["components"]; b != nil {
		if err := json.Unmarshal(b, &components); err != nil {
			return nil, err
		}
	}
	if b := doc["services"]; b != nil {
		if err := json.Unmarshal(b, &services); err != nil {
			return nil, err
		}
	}
	containers := map[string]string{}
	for _, b := range components {
		var item struct {
			Type       string
			Ref        string `json:"bom-ref"`
			Properties []prop
		}
		if err := json.Unmarshal(b, &item); err != nil {
			return nil, err
		}
		if item.Type == "container" {
			for _, p := range item.Properties {
				if p.Name == "koda:container:id" {
					containers[p.Value] = item.Ref
				}
			}
		}
	}
	if len(e.Network) > 0 {
		matched, unmatched, err := attachNetwork(e.Network, meta["component"], containers, services)
		if err != nil {
			return nil, err
		}
		props = append(props, prop{"koda:network:matched-tests", fmt.Sprint(matched)}, prop{"koda:network:unmatched-tests", fmt.Sprint(unmatched)})
		for _, r := range e.Network {
			props = append(props, prop{"koda:network:source-sha256", r.SHA256})
		}
	}
	type dep struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn,omitempty"`
	}
	// Keep original dependency objects (including provides edges) intact.
	var deps []json.RawMessage
	if b := doc["dependencies"]; b != nil {
		if err := json.Unmarshal(b, &deps); err != nil {
			return nil, err
		}
	}
	byID := map[string]Resource{}
	for _, r := range e.Resources {
		byID[r.UID] = r
	}
	edges := map[string][]string{}
	included := map[string]bool{}
	ref := func(uid string) string { return fmt.Sprintf("koda-k8s-%x", sha256.Sum256([]byte(uid))) }
	for _, pod := range e.Resources {
		if pod.Kind != "Pod" {
			continue
		}
		for _, id := range pod.Containers {
			if target := containers[id]; target != "" {
				edges[pod.UID] = append(edges[pod.UID], target)
			}
		}
		if len(edges[pod.UID]) == 0 {
			continue
		}
		included[pod.UID] = true
		visited := map[string]bool{pod.UID: true}
		for child := pod; child.Owner != ""; {
			parent, ok := byID[child.Owner]
			if !ok || parent.Namespace != pod.Namespace {
				break
			}
			if visited[parent.UID] {
				return nil, fmt.Errorf("cyclic Kubernetes owner chain")
			}
			visited[parent.UID], included[parent.UID] = true, true
			edges[parent.UID] = append(edges[parent.UID], ref(child.UID))
			child = parent
		}
	}
	for _, kind := range []string{"Service", "Ingress"} {
		for _, r := range e.Resources {
			if r.Kind != kind {
				continue
			}
			for _, uid := range r.Targets {
				if included[uid] {
					edges[r.UID] = append(edges[r.UID], ref(uid))
					included[r.UID] = true
				}
			}
		}
	}
	if len(e.Resources) > 0 {
		props = append(props, prop{"koda:kubernetes:matched-resources", fmt.Sprint(len(included))})
	}
	for _, r := range e.Resources {
		if !included[r.UID] {
			continue
		}
		item := map[string]any{"bom-ref": ref(r.UID), "name": r.Name, "properties": []prop{{"koda:kubernetes:kind", r.Kind}, {"koda:kubernetes:namespace", r.Namespace}, {"koda:kubernetes:uid", r.UID}, {"koda:kubernetes:evidence", "exported-configuration"}}}
		isService := r.Kind == "Ingress" || r.Kind == "Service"
		if !isService {
			item["type"] = "platform"
		}
		row, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if isService {
			services = append(services, row)
		} else {
			components = append(components, row)
		}
		targets := edges[r.UID]
		slices.Sort(targets)
		row, err = json.Marshal(dep{ref(r.UID), slices.Compact(targets)})
		if err != nil {
			return nil, err
		}
		deps = append(deps, row)
	}
	var err error
	for k, rows := range map[string][]json.RawMessage{"components": components, "services": services, "dependencies": deps} {
		if len(rows) > 0 {
			doc[k], err = json.Marshal(rows)
			if err != nil {
				return nil, err
			}
		}
	}
	meta["properties"], err = json.Marshal(props)
	if err != nil {
		return nil, err
	}
	doc["metadata"], err = json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

// Merge accepts supplemental evidence only when it does not replace existing
// deployment identity or independently resolved cluster snapshots.
func Merge(a, b *Evidence) (*Evidence, error) {
	if a == nil {
		return b, nil
	}
	if b == nil {
		return a, nil
	}
	out := *a
	for _, pair := range []struct {
		field *string
		value string
	}{{&out.Environment, b.Environment}, {&out.DeploymentID, b.DeploymentID}} {
		if pair.value != "" {
			if *pair.field != "" && *pair.field != pair.value {
				return nil, fmt.Errorf("conflicting deployment identity")
			}
			*pair.field = pair.value
		}
	}
	if len(b.SourceSHA256) > 0 {
		if len(out.SourceSHA256) > 0 && strings.Join(out.SourceSHA256, ",") != strings.Join(b.SourceSHA256, ",") {
			return nil, fmt.Errorf("conflicting Kubernetes exports")
		}
		out.Resources, out.SourceSHA256 = b.Resources, b.SourceSHA256
	}
	if len(b.Network) > 0 {
		out.Network = slices.Clone(a.Network)
		seen := map[string]bool{}
		for _, r := range out.Network {
			seen[r.SHA256] = true
		}
		for _, r := range b.Network {
			if !seen[r.SHA256] {
				out.Network = append(out.Network, r)
				seen[r.SHA256] = true
			}
		}
	}
	return &out, nil
}
