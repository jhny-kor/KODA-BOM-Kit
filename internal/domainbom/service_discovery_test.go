package domainbom

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOpenAPIYAML(t *testing.T) {
	yamlAPI := "openapi: 3.1.0\ninfo:\n  title: Orders\n  version: 1.0\nservers:\n  - url: https://orders.example.invalid/v1\nsecurity:\n  - bearer: []\npaths:\n  /orders:\n    get:\n      responses:\n        200:\n          description: ok\n"
	docs, err := Generate(context.Background(), Options{SaaS: []string{temporary(t, []byte(yamlAPI))}})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services []struct {
			Name          string
			Version       string
			Endpoints     []string
			Authenticated *bool
		}
	}
	if err := json.Unmarshal(docs["saasbom.cdx.json"], &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Services
	if len(s) != 1 || s[0].Name != "Orders" || s[0].Version != "1.0" || len(s[0].Endpoints) != 1 || s[0].Authenticated == nil || !*s[0].Authenticated {
		t.Fatalf("services %+v", s)
	}
	for _, bad := range []string{
		"openapi: 3.0.0\ninfo:\n  title: a\n  title: b\npaths: {}\n",         // duplicate key
		"openapi: 3.0.0\ninfo: {title: a}\npaths: {}\n---\nopenapi: 3.0.0\n", // two documents
		"a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d]\nf: &f [*e, *e, *e, *e, *e, *e, *e, *e, *e]\ng: [*f, *f, *f, *f, *f, *f, *f, *f, *f]\n",
	} {
		if _, err := Generate(context.Background(), Options{SaaS: []string{temporary(t, []byte(bad))}}); err == nil {
			t.Fatalf("accepted %q", bad[:20])
		}
	}
}

func TestDiscoveredProxyBackends(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "etc/nginx/conf.d/upstreams.conf", "upstream api_pool {\n  server 10.0.0.5:8080 weight=5;\n  server api-2.internal:8080;\n  server unix:/run/api.sock;\n}\n")
	modelFixture(t, root, "etc/nginx/sites-enabled/default", "server {\n  listen 443 ssl;\n  location /api/ { proxy_pass http://api_pool/v1/; }\n  # proxy_pass http://commented.invalid;\n  location /grpc { grpc_pass 10.0.0.9:50051; }\n  location /x { proxy_pass http://user:secret@auth.internal:9000/login?token=t; }\n  location /y { proxy_pass http://$backend; }\n}\n")
	modelFixture(t, root, "etc/httpd/conf.d/proxy.conf", "<Proxy \"balancer://web\">\n  BalancerMember https://web1.internal:8443\n  BalancerMember http://web2.internal:8080\n</Proxy>\nProxyPass /app balancer://web/\nProxyPass /static !\nProxyPass /legacy ajp://legacy.internal:8009/\n")
	modelFixture(t, root, "etc/haproxy/haproxy.cfg", "global\n  daemon\nfrontend fe\n  bind *:80\n  default_backend be_db\nbackend be_db\n  server db1 10.0.1.10:5432 check\n  server db2 ipv4@10.0.1.11:5432 check\n  server local /run/sock\n")
	found, err := DiscoverServices(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]object{}
	for _, s := range found.Services {
		byName[s["name"].(string)] = s
	}
	endpoints := func(name string) []string {
		eps, _ := byName[name]["endpoints"].([]string)
		return eps
	}
	want := map[string][]string{
		"api_pool":             {"http://10.0.0.5:8080", "http://api-2.internal:8080"},
		"10.0.0.9:50051":       {"grpc://10.0.0.9:50051"},
		"auth.internal:9000":   {"http://auth.internal:9000"},
		"web":                  {"http://web2.internal:8080", "https://web1.internal:8443"},
		"legacy.internal:8009": {"ajp://legacy.internal:8009"},
		"be_db":                {"tcp://10.0.1.10:5432", "tcp://10.0.1.11:5432"},
	}
	if len(byName) != len(want) {
		t.Fatalf("services %+v", byName)
	}
	for name, eps := range want {
		if !reflect.DeepEqual(endpoints(name), eps) {
			t.Fatalf("%s: got %v want %v", name, endpoints(name), eps)
		}
	}
	raw, _ := json.Marshal(found.Services)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "token") || strings.Contains(string(raw), "commented") {
		t.Fatalf("credentials, queries or comments leaked: %s", raw)
	}
	if len(found.Issues) != 1 || found.Issues[0].Code != "proxy_target_unresolved" {
		t.Fatalf("issues %+v", found.Issues)
	}
	docs := map[string][]byte{}
	if err := AddDiscoveredServices(context.Background(), docs, []ServiceDiscovery{found}, true); err != nil {
		t.Fatal(err)
	}
	if len(docs["saasbom.cdx.json"]) == 0 || len(docs["saasbom.cdx-1.7.json"]) == 0 || !strings.Contains(string(docs["saasbom.cdx.json"]), `"koda:domain:kind"`) {
		t.Fatalf("documents %v", docs)
	}
}

func TestDisabledDebianConfigIsIgnored(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "etc/apache2/sites-available/old.conf", "ProxyPass /old http://old.internal:8080/\n")
	modelFixture(t, root, "etc/apache2/sites-available/live.conf", "ProxyPass /live http://live.internal:8080/\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/apache2/sites-enabled"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/live.conf", filepath.Join(root, "etc/apache2/sites-enabled/live.conf")); err != nil {
		t.Fatal(err)
	}
	found, err := DiscoverServices(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Services) != 1 || found.Services[0]["name"] != "live.internal:8080" {
		t.Fatalf("only enabled sites count: %+v", found.Services)
	}
}

func TestAbsoluteEnabledLinkInDirectoryScanKeepsConfig(t *testing.T) {
	root := t.TempDir()
	modelFixture(t, root, "etc/nginx/sites-available/app.conf", "server { location / { proxy_pass http://10.0.0.5:8080; } }\n")
	if err := os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0700); err != nil {
		t.Fatal(err)
	}
	// ln -s /etc/nginx/sites-available/app.conf: a directory scan cannot follow it.
	if err := os.Symlink("/etc/nginx/sites-available/app.conf", filepath.Join(root, "etc/nginx/sites-enabled/app.conf")); err != nil {
		t.Fatal(err)
	}
	found, err := DiscoverServices(context.Background(), testPlan(t, root, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Services) != 1 || found.Services[0]["name"] != "10.0.0.5:8080" {
		t.Fatalf("enablement unknown: the configuration must still be read: %+v", found.Services)
	}
	if len(found.Issues) != 1 || found.Issues[0].Code != "config_enablement_unresolved" {
		t.Fatalf("issues %+v", found.Issues)
	}
}
