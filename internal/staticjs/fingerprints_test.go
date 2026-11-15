package staticjs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestFingerprintIndexKeepsEveryPublishedVersion(t *testing.T) {
	index := fancytreeFingerprintIndex()
	entries := map[string][]string{
		"444660119bd6718c377a0a8e1bb3f65d8951c2b19c5ce3ba5f926cbf0610958c": {"2.38.5"},
		"2ba477097c3727ba95dddf974e86fd84852b4d412fafc2bab6f6c6be3c436390": {"2.5.0", "2.5.1-0"},
	}
	for digest, expected := range entries {
		var key [sha256.Size]byte
		if _, err := hex.Decode(key[:], []byte(digest)); err != nil {
			t.Fatal(err)
		}
		if versions := index[key]; !reflect.DeepEqual(versions, expected) {
			t.Errorf("%s: versions %v, want %v", digest, versions, expected)
		}
	}
}

func TestFingerprintRequiresExactWholeFileAndUnambiguousVersion(t *testing.T) {
	unique := []byte("/* fixture without a recognizable banner */")
	ambiguous := []byte("/*! jQuery Fancytree Plugin - 2.5.0 | https://github.com/mar10/fancytree */")
	conflict := []byte("/*! jQuery Fancytree Plugin - 2.18.0 | https://github.com/mar10/fancytree */")
	truncated := bytes.Repeat([]byte(" "), probeBytes)
	index := fingerprintIndex{
		sha256.Sum256(unique):    {"2.38.5"},
		sha256.Sum256(ambiguous): {"2.5.0", "2.5.1-0"},
		sha256.Sum256(conflict):  {"2.17.0"},
		sha256.Sum256(truncated): {"2.38.4"},
	}
	c := collector{ctx: context.Background(), components: map[string]*Component{}, fingerprints: index}
	c.probe(bytes.NewReader(unique), "web.ear!/app.war!/renamed.js")
	c.probe(bytes.NewReader(append(bytes.Clone(unique), '\n')), "jquery.fancytree.modified.min.js")
	c.probe(bytes.NewReader(ambiguous), "vendor/old.js")
	c.probe(bytes.NewReader(conflict), "vendor/conflict.js")
	c.probe(bytes.NewReader(append(truncated, '\n')), "vendor/large.js")

	const purl = "pkg:npm/jquery.fancytree@2.38.5"
	component, ok := c.components[purl]
	if !ok || len(c.components) != 1 || !reflect.DeepEqual(component.Locations, []string{"web.ear!/app.war!/renamed.js"}) {
		t.Fatalf("unexpected components: %+v", c.components)
	}
	hash := sha256.Sum256(unique)
	if !reflect.DeepEqual(component.Fingerprints, []Fingerprint{{Path: component.Locations[0], PURL: purl, SHA256: hex.EncodeToString(hash[:])}}) {
		t.Fatalf("unexpected evidence: %+v", component.Fingerprints)
	}
	want := []string{"static_js_identity_unconfirmed", "static_js_fingerprint_ambiguous", "static_js_fingerprint_conflict", "static_js_probe_truncated"}
	var got []string
	for _, issue := range c.issues {
		got = append(got, issue.Code)
	}
	if !reflect.DeepEqual(got, want) || !strings.Contains(c.issues[1].Message, "2.5.0, 2.5.1-0") {
		t.Fatalf("unexpected issues: %+v", c.issues)
	}
}
