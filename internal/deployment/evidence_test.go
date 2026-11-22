package deployment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJoinOnlyObservedPodsAndDeclaredRoutes(t *testing.T) {
	const containerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const objects = `{"kind":"List","items":[
	{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"d","name":"app","namespace":"test"}},
	{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"uid":"r","name":"replica","namespace":"test","ownerReferences":[{"uid":"d","controller":true}]}},
	{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"p","name":"pod","namespace":"test","labels":{"app":"a"},"ownerReferences":[{"uid":"r","controller":true}]},"status":{"containerStatuses":[{"containerID":"containerd://` + containerID + `"}]},"spec":{"containers":[{"env":[{"value":"private-fixture-value"}]}]}},
	{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"q","name":"remote","namespace":"other","labels":{"app":"a"}}},
	{"apiVersion":"v1","kind":"Service","metadata":{"uid":"s","name":"web","namespace":"test"},"spec":{"selector":{"app":"a"}}},
	{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"uid":"i","name":"site","namespace":"test"},"spec":{"rules":[{"http":{"paths":[{"backend":{"service":{"name":"web"}}}]}}]}}
	]}`
	dir := t.TempDir()
	p := filepath.Join(dir, "export.json")
	if err := os.WriteFile(p, []byte(objects), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(context.Background(), "test", "deployment-1", []string{p})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EnrichJSON([]byte(`{"metadata":{},"components":[{"type":"container","bom-ref":"container","properties":[{"name":"koda:container:id","value":"`+containerID+`"}]}]}`), e)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components, Services []struct {
			Name string
			Ref  string `json:"bom-ref"`
		}
		Dependencies []struct {
			Ref       string
			DependsOn []string
		}
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ref := map[string]string{"": "container"}
	for _, obj := range append(doc.Components, doc.Services...) {
		ref[obj.Name] = obj.Ref
	}
	edges := map[string]string{}
	for _, d := range doc.Dependencies {
		if len(d.DependsOn) != 1 {
			t.Fatal(d)
		}
		edges[d.Ref] = d.DependsOn[0]
	}
	for a, b := range map[string]string{"app": "replica", "replica": "pod", "pod": "", "site": "web", "web": "pod"} {
		if ref[a] == "" || edges[ref[a]] != ref[b] {
			t.Fatalf("missing %s -> %s", a, b)
		}
	}
	encoded, _ := json.Marshal(e)
	if strings.Contains(string(encoded), "private-fixture-value") || ref["remote"] != "" {
		t.Fatal("exposed unrelated metadata")
	}
	if _, err = Merge(e, &Evidence{Environment: "prod"}); err == nil {
		t.Fatal("accepted conflicting environment")
	}
}
