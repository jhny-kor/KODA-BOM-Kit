package domainbom

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type serviceInput struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Version       string     `json:"version,omitempty"`
	Provider      string     `json:"provider,omitempty"`
	Endpoints     []string   `json:"endpoints,omitempty"`
	Authenticated *bool      `json:"authenticated,omitempty"`
	TrustBoundary *bool      `json:"trustBoundary,omitempty"`
	TrustZone     string     `json:"trustZone,omitempty"`
	Data          []dataFlow `json:"data,omitempty"`
	DependsOn     []string   `json:"dependsOn,omitempty"`
}
type dataFlow struct {
	Flow           string `json:"flow"`
	Classification string `json:"classification"`
	Name           string `json:"name,omitempty"`
}
type serviceEvidence struct {
	Schema   string         `json:"schema"`
	Services []serviceInput `json:"services"`
}

func (d *document) source(sum string) bool {
	for _, p := range d.sources {
		if p.Value == sum {
			return false
		}
	}
	d.sources = append(d.sources, prop("source-sha256", sum))
	return true
}
func loadServices(ctx context.Context, path string, d *document) error {
	raw, sum, err := readEvidence(ctx, path)
	if err != nil {
		return err
	}
	if !d.source(sum) {
		return nil
	}
	var head struct{ Schema, OpenAPI string }
	if json.Unmarshal(raw, &head) != nil {
		return fmt.Errorf("invalid service evidence")
	}
	var input serviceEvidence
	if head.Schema == "koda-services-1" {
		if strict(raw, &input) != nil {
			return fmt.Errorf("invalid koda-services-1 evidence")
		}
	} else if strings.HasPrefix(head.OpenAPI, "3.") {
		services, err := openAPI(raw)
		if err != nil {
			return err
		}
		input.Services = services
	} else {
		return fmt.Errorf("expected koda-services-1 or OpenAPI 3.x JSON")
	}
	if len(input.Services) == 0 || len(input.Services) > maxItems {
		return fmt.Errorf("service count outside supported bounds")
	}
	ids := map[string]bool{}
	for _, s := range input.Services {
		if !textOK(s.ID, true) || !textOK(s.Name, true) || !textOK(s.Version, false) || !textOK(s.Provider, false) || !textOK(s.TrustZone, false) || ids[s.ID] {
			return fmt.Errorf("invalid or duplicated service identity")
		}
		ids[s.ID] = true
	}
	for _, s := range input.Services {
		r := ref("service", sum, s.ID)
		item := object{"bom-ref": r, "name": s.Name, "properties": []property{prop("source-sha256", sum), prop("observation", "declared-service")}}
		if s.Version != "" {
			item["version"] = s.Version
		}
		if s.Provider != "" {
			item["provider"] = object{"name": s.Provider}
		}
		if s.Authenticated != nil {
			item["authenticated"] = *s.Authenticated
		}
		if s.TrustBoundary != nil {
			item["x-trust-boundary"] = *s.TrustBoundary
		}
		if s.TrustZone != "" {
			item["trustZone"] = s.TrustZone
		}
		if len(s.Endpoints) > maxItems || len(s.Data) > maxItems || len(s.DependsOn) > maxItems {
			return fmt.Errorf("service field count exceeds limit")
		}
		endpoints := map[string]bool{}
		for _, ep := range s.Endpoints {
			if !safeURI(ep) {
				return fmt.Errorf("service endpoint must be an absolute URL without credentials, query, fragment or template")
			}
			endpoints[ep] = true
		}
		if len(endpoints) > 0 {
			list := make([]string, 0, len(endpoints))
			for ep := range endpoints {
				list = append(list, ep)
			}
			sort.Strings(list)
			item["endpoints"] = list
		}
		for _, f := range s.Data {
			if (f.Flow != "inbound" && f.Flow != "outbound" && f.Flow != "bi-directional" && f.Flow != "unknown") || !textOK(f.Classification, true) || !textOK(f.Name, false) {
				return fmt.Errorf("invalid service data classification")
			}
		}
		if len(s.Data) > 0 {
			item["data"] = s.Data
		}
		targets := []string{}
		seen := map[string]bool{}
		for _, id := range s.DependsOn {
			if !ids[id] {
				return fmt.Errorf("service dependency references an unknown ID")
			}
			if !seen[id] {
				targets = append(targets, ref("service", sum, id))
				seen[id] = true
			}
		}
		d.add(&d.services, item)
		d.edge(r, targets)
	}
	return nil
}

type apiServer struct {
	URL string `json:"url"`
}
type apiOperation struct {
	Security []map[string]json.RawMessage `json:"security"`
	Servers  []apiServer                  `json:"servers"`
}

func openAPI(raw []byte) ([]serviceInput, error) {
	var api struct {
		Info     struct{ Title, Version string }
		Servers  []apiServer
		Security []map[string]json.RawMessage
		Paths    map[string]json.RawMessage
	}
	if json.Unmarshal(raw, &api) != nil || !textOK(api.Info.Title, true) || len(api.Paths) > maxItems {
		return nil, fmt.Errorf("invalid OpenAPI inventory fields")
	}
	service := serviceInput{ID: "openapi-service", Name: api.Info.Title, Version: api.Info.Version}
	servers := append([]apiServer{}, api.Servers...)
	// OpenAPI security is OR across requirements. An empty requirement permits
	// anonymous access. Operations inherit root security unless they override it.
	authKnown, allAuthenticated, unknownAuthentication := false, true, false
	consume := func(req []map[string]json.RawMessage) {
		if req == nil {
			unknownAuthentication = true
			return
		}
		authKnown = true
		if len(req) == 0 {
			allAuthenticated = false
		}
		for _, r := range req {
			if len(r) == 0 {
				allAuthenticated = false
			}
		}
	}
	operationCount := 0
	for _, path := range api.Paths {
		var fields map[string]json.RawMessage
		if json.Unmarshal(path, &fields) != nil {
			return nil, fmt.Errorf("invalid OpenAPI path item")
		}
		var pathServers []apiServer
		if raw := fields["servers"]; raw != nil {
			if json.Unmarshal(raw, &pathServers) != nil {
				return nil, fmt.Errorf("invalid OpenAPI path servers")
			}
			servers = append(servers, pathServers...)
		}
		for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
			value, ok := fields[method]
			if !ok {
				continue
			}
			operationCount++
			if operationCount > maxItems {
				return nil, fmt.Errorf("OpenAPI operation limit exceeded")
			}
			var op apiOperation
			if json.Unmarshal(value, &op) != nil {
				return nil, fmt.Errorf("invalid OpenAPI operation")
			}
			if op.Security == nil {
				consume(api.Security)
			} else {
				consume(op.Security)
			}
			servers = append(servers, op.Servers...)
		}
	}
	if operationCount == 0 {
		consume(api.Security)
	}
	if authKnown && (!allAuthenticated || !unknownAuthentication) {
		service.Authenticated = &allAuthenticated
	}
	for _, s := range servers {
		// A relative/default server has no known deployment authority. Preserve only
		// declared absolute endpoints, never resolve against a local evidence path.
		if strings.HasPrefix(s.URL, "/") {
			continue
		}
		if !safeURI(s.URL) {
			return nil, fmt.Errorf("OpenAPI server requires a concrete absolute URL without credentials or query")
		}
		service.Endpoints = append(service.Endpoints, s.URL)
	}
	return []serviceInput{service}, nil
}
