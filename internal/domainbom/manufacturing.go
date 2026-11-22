package domainbom

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type slsaResource struct {
	Name, URI string
	Digest    map[string]string
}
type slsaStatement struct {
	Type          string `json:"_type"`
	PredicateType string
	Subject       []slsaResource
	Predicate     struct {
		BuildDefinition struct {
			BuildType            string
			ResolvedDependencies []slsaResource
		}
		RunDetails struct {
			Builder  struct{ ID string }
			Metadata struct{ InvocationID, StartedOn, FinishedOn string }
		}
	}
}

func loadProvenance(ctx context.Context, input ProvenanceInput, d *document) error {
	raw, sum, err := readEvidence(ctx, input.Evidence)
	if err != nil {
		return err
	}
	d.source(sum)
	var header struct{ Schema string }
	if json.Unmarshal(raw, &header) != nil {
		return fmt.Errorf("invalid manufacturing evidence")
	}
	if header.Schema == "koda-manufacturing-1" {
		return physicalManufacturing(ctx, input, raw, sum, d)
	}
	var s slsaStatement
	if json.Unmarshal(raw, &s) != nil || s.Type != "https://in-toto.io/Statement/v1" || s.PredicateType != "https://slsa.dev/provenance/v1" {
		return fmt.Errorf("expected SLSA provenance/v1 Statement or koda-manufacturing-1")
	}
	if !safeURI(s.Predicate.BuildDefinition.BuildType) || !safeURI(s.Predicate.RunDetails.Builder.ID) || len(s.Subject) == 0 || len(s.Subject) > maxItems || len(s.Predicate.BuildDefinition.ResolvedDependencies) > maxItems {
		return fmt.Errorf("invalid SLSA builder, build type or resource count")
	}
	f, actual, _, err := openArtifact(ctx, input.Artifact, "")
	if err != nil {
		return err
	}
	f.Close()
	matches := []slsaResource{}
	for _, subject := range s.Subject {
		if subject.Digest["sha256"] == actual {
			matches = append(matches, subject)
		}
	}
	if len(matches) != 1 || !textOK(matches[0].Name, true) {
		return fmt.Errorf("artifact must match exactly one SLSA subject SHA-256")
	}
	product := ref("slsa-subject", sum, actual)
	if d.seen[product] {
		return nil
	}
	builder := ref("slsa-builder", sum)
	workflow := ref("slsa-workflow", sum)
	d.add(&d.components, object{"type": "file", "bom-ref": product, "name": matches[0].Name, "hashes": hashes(actual), "properties": []property{prop("source-sha256", sum), prop("artifact-binding", "sha256-matched")}})
	d.add(&d.services, object{"bom-ref": builder, "name": s.Predicate.RunDetails.Builder.ID, "properties": []property{prop("observation", "reported-build-platform")}})
	inputs := []object{}
	targets := []string{builder}
	for index, resource := range s.Predicate.BuildDefinition.ResolvedDependencies {
		if !safeURI(resource.URI) || !textOK(resource.Name, false) {
			return fmt.Errorf("invalid SLSA dependency URI")
		}
		name := resource.Name
		if name == "" {
			name = resource.URI
		}
		id := ref("slsa-input", sum, strconv.Itoa(index))
		component := object{"type": "file", "bom-ref": id, "name": name, "externalReferences": []object{{"type": "distribution", "url": resource.URI}}, "properties": []property{prop("observation", "reported-build-input"), prop("source-sha256", sum)}}
		if sha := resource.Digest["sha256"]; sha != "" {
			if !digestOK(sha) {
				return fmt.Errorf("invalid SLSA dependency SHA-256")
			}
			component["hashes"] = hashes(sha)
		}
		d.add(&d.components, component)
		inputs = append(inputs, object{"resource": object{"ref": id}})
		targets = append(targets, id)
	}
	metadata := s.Predicate.RunDetails.Metadata
	if !textOK(metadata.InvocationID, false) {
		return fmt.Errorf("invalid SLSA invocation ID")
	}
	w := object{"bom-ref": workflow, "uid": workflow, "name": "Reported build", "taskTypes": []string{"build"}, "resourceReferences": []object{{"ref": builder}}, "outputs": []object{{"type": "artifact", "resource": object{"ref": product}}}, "properties": []property{prop("source-sha256", sum), prop("observation", "reported"), prop("build-type", s.Predicate.BuildDefinition.BuildType), prop("signature-verification", "unverified")}}
	if metadata.InvocationID != "" {
		w["uid"] = metadata.InvocationID
	}
	if len(inputs) > 0 {
		w["inputs"] = inputs
	}
	if err := times(w, metadata.StartedOn, metadata.FinishedOn); err != nil {
		return err
	}
	formulaRef := ref("slsa-formula", sum)
	for _, formula := range d.formulas {
		if formula["bom-ref"] == formulaRef {
			existing := formula["workflows"].([]object)[0]
			existing["outputs"] = append(existing["outputs"].([]object), w["outputs"].([]object)...)
			d.edge(product, targets)
			return nil
		}
	}
	d.formulas = append(d.formulas, object{"bom-ref": formulaRef, "workflows": []object{w}})
	d.edge(product, targets)
	return nil
}
func times(obj object, start, end string) error {
	var started, finished time.Time
	var err error
	if start != "" {
		started, err = time.Parse(time.RFC3339Nano, start)
		if err != nil {
			return fmt.Errorf("invalid manufacturing start time")
		}
		obj["timeStart"] = start
	}
	if end != "" {
		finished, err = time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return fmt.Errorf("invalid manufacturing end time")
		}
		obj["timeEnd"] = end
	}
	if !started.IsZero() && !finished.IsZero() && finished.Before(started) {
		return fmt.Errorf("manufacturing end precedes start")
	}
	return nil
}

type physicalPart struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Model        string `json:"model,omitempty"`
	PartNumber   string `json:"partNumber,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Version      string `json:"version,omitempty"`
}
type physicalEvidence struct {
	Schema      string         `json:"schema"`
	ObservedAt  string         `json:"observedAt"`
	Observation string         `json:"observation"`
	Product     physicalPart   `json:"product"`
	Parts       []physicalPart `json:"parts"`
	Steps       []struct {
		Name       string   `json:"name"`
		Action     string   `json:"action"`
		InputIDs   []string `json:"inputIds,omitempty"`
		StartedOn  string   `json:"startedOn,omitempty"`
		FinishedOn string   `json:"finishedOn,omitempty"`
	} `json:"steps"`
}

func physicalManufacturing(ctx context.Context, input ProvenanceInput, raw []byte, sum string, d *document) error {
	var s physicalEvidence
	if strict(raw, &s) != nil || s.Schema != "koda-manufacturing-1" || (s.Observation != "declared" && s.Observation != "reported") || len(s.Parts) > maxItems || len(s.Steps) == 0 || len(s.Steps) > 1000 {
		return fmt.Errorf("invalid physical manufacturing evidence")
	}
	if _, err := time.Parse(time.RFC3339Nano, s.ObservedAt); err != nil {
		return fmt.Errorf("physical manufacturing evidence requires observedAt")
	}
	if input.Artifact != "" {
		return fmt.Errorf("physical manufacturing evidence uses product identity; an artifact argument is unsupported")
	}
	if d.seen[ref("physical-part", sum, s.Product.ID)] {
		return nil
	}
	parts := append([]physicalPart{s.Product}, s.Parts...)
	ids := map[string]string{}
	targets := []string{}
	for _, part := range parts {
		if !textOK(part.ID, true) || ids[part.ID] != "" || !textOK(part.Name, true) || !textOK(part.Model, false) || !textOK(part.PartNumber, false) || !textOK(part.Manufacturer, false) || !textOK(part.Version, false) {
			return fmt.Errorf("invalid or duplicated manufacturing part identity")
		}
		id := ref("physical-part", sum, part.ID)
		ids[part.ID] = id
		props := []property{prop("source-sha256", sum), prop("observation", s.Observation), prop("observed-at", s.ObservedAt)}
		if part.Model != "" {
			props = append(props, prop("model", part.Model))
		}
		if part.PartNumber != "" {
			props = append(props, prop("part-number", part.PartNumber))
		}
		item := object{"type": "device", "bom-ref": id, "name": part.Name, "properties": props}
		if part.Version != "" {
			item["version"] = part.Version
		}
		if part.Manufacturer != "" {
			item["manufacturer"] = object{"name": part.Manufacturer}
		}
		d.add(&d.components, item)
		if part.ID != s.Product.ID {
			targets = append(targets, id)
		}
	}
	product := ids[s.Product.ID]
	tasks := []object{}
	taskEdges := []object{}
	previous := ""
	for i, step := range s.Steps {
		if !textOK(step.Name, true) || (step.Action != "assembly" && step.Action != "inspection" && step.Action != "test" && step.Action != "packaging") {
			return fmt.Errorf("invalid manufacturing step")
		}
		id := ref("physical-step", sum, strconv.Itoa(i))
		kind := "other"
		if step.Action == "test" || step.Action == "inspection" {
			kind = "test"
		}
		task := object{"bom-ref": id, "uid": id, "name": step.Name, "taskTypes": []string{kind}, "properties": []property{prop("action", step.Action), prop("observation", s.Observation)}, "outputs": []object{{"type": "artifact", "resource": object{"ref": product}}}}
		refs := []object{}
		seen := map[string]bool{}
		for _, key := range step.InputIDs {
			if ids[key] == "" || key == s.Product.ID {
				return fmt.Errorf("manufacturing step input references an unknown part")
			}
			if !seen[key] {
				refs = append(refs, object{"resource": object{"ref": ids[key]}})
				seen[key] = true
			}
		}
		if len(refs) > 0 {
			task["inputs"] = refs
		}
		if err := times(task, step.StartedOn, step.FinishedOn); err != nil {
			return err
		}
		tasks = append(tasks, task)
		if previous != "" {
			taskEdges = append(taskEdges, object{"ref": id, "dependsOn": []string{previous}})
		}
		previous = id
	}
	workflow := ref("physical-workflow", sum)
	w := object{"bom-ref": workflow, "uid": workflow, "name": "Manufacturing process", "taskTypes": []string{"other"}, "tasks": tasks, "properties": []property{prop("source-sha256", sum), prop("observation", s.Observation), prop("observed-at", s.ObservedAt)}}
	if len(taskEdges) > 0 {
		w["taskDependencies"] = taskEdges
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.formulas = append(d.formulas, object{"bom-ref": ref("physical-formula", sum), "workflows": []object{w}})
	d.edge(product, targets)
	return nil
}
