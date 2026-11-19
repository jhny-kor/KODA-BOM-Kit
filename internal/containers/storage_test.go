package containers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func put(t *testing.T, root, p, v string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(v), 0644); err != nil {
		t.Fatal(err)
	}
}

func h(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func TestDockerAndPodmanStorage(t *testing.T) {
	root := t.TempDir()
	meta := "var/lib/docker/image/overlay2/"
	// Two images: "app" (layers d1, d2) used by a stopped container and a
	// running one; "tool" (layer d1 only) used by nothing.
	d1, d2 := "sha256:"+h("d1"), "sha256:"+h("d2")
	chain2 := h(d1 + " " + d2)
	app, tool := h("app"), h("tool")
	put(t, root, meta+"imagedb/content/sha256/"+app, `{"rootfs":{"diff_ids":["`+d1+`","`+d2+`"]}}`)
	put(t, root, meta+"imagedb/content/sha256/"+tool, `{"rootfs":{"diff_ids":["`+d1+`"]}}`)
	put(t, root, meta+"layerdb/sha256/"+h("d1")+"/cache-id", h("cache1"))
	put(t, root, meta+"layerdb/sha256/"+chain2+"/cache-id", h("cache2")+"\n")
	put(t, root, meta+"repositories.json", `{"Repositories":{"app":{"app:1.0":"sha256:`+app+`","app@sha256:`+h("x")+`":"sha256:`+app+`"},"tool":{"tool:latest":"sha256:`+tool+`"}}}`)
	stopped, running := h("stopped"), h("running")
	put(t, root, "var/lib/docker/containers/"+stopped+"/config.v2.json", `{"Name":"/web","Image":"sha256:`+app+`","Config":{"Image":"app:1.0"},"State":{"Running":false}}`)
	put(t, root, meta+"layerdb/mounts/"+stopped+"/mount-id", h("rw"))
	put(t, root, "var/lib/docker/containers/"+running+"/config.v2.json", `{"Name":"/live","Image":"sha256:`+app+`","Config":{"Image":"app:1.0"}}`)
	put(t, root, meta+"layerdb/mounts/"+running+"/mount-id", h("rw2"))
	// containers-storage: image "pod" with layers p1 <- p2, unused.
	cs := "var/lib/containers/storage/"
	put(t, root, cs+"overlay-layers/layers.json", `[{"id":"`+h("p1")+`"},{"id":"`+h("p2")+`","parent":"`+h("p1")+`"}]`)
	put(t, root, cs+"overlay-images/images.json", `[{"id":"`+h("pod")+`","names":["docker.io/library/pod:2"],"layer":"`+h("p2")+`"}]`)
	put(t, root, cs+"overlay-containers/containers.json", `[]`)

	images, stoppedList, issues := Storage(context.Background(), root, []Container{{ID: running, ImageID: "sha256:" + app}})
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	if len(stoppedList) != 1 || stoppedList[0].ID != stopped || stoppedList[0].Names[0] != "web" || stoppedList[0].Image != "app:1.0" {
		t.Fatalf("stopped %+v", stoppedList)
	}
	wantLayers := []string{
		filepath.Join(root, "var/lib/docker/overlay2", h("cache1"), "diff"),
		filepath.Join(root, "var/lib/docker/overlay2", h("cache2"), "diff"),
		filepath.Join(root, "var/lib/docker/overlay2", h("rw"), "diff"),
	}
	if !reflect.DeepEqual(stoppedList[0].Layers, wantLayers) {
		t.Fatalf("layers %v", stoppedList[0].Layers)
	}
	var names []string
	for _, image := range images {
		names = append(names, strings.Join(image.Names, ","))
	}
	if len(images) != 2 || !reflect.DeepEqual(names, []string{"docker.io/library/pod:2", "tool:latest"}) && !reflect.DeepEqual(names, []string{"tool:latest", "docker.io/library/pod:2"}) {
		t.Fatalf("images used by a container must be omitted: %v", names)
	}
	for _, image := range images {
		if image.Names[0] == "docker.io/library/pod:2" && !reflect.DeepEqual(image.Layers, []string{
			filepath.Join(root, cs+"overlay", h("p1"), "diff"), filepath.Join(root, cs+"overlay", h("p2"), "diff"),
		}) {
			t.Fatalf("pod layers %v", image.Layers)
		}
	}
}

func TestFlattenAppliesWhiteoutsAndStaysInside(t *testing.T) {
	base := t.TempDir()
	lower, upper, dest := filepath.Join(base, "lower"), filepath.Join(base, "upper"), filepath.Join(base, "dest")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{lower, upper, dest, outside} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	put(t, lower, "usr/bin/tool", "old")
	put(t, lower, "usr/bin/removed", "x")
	put(t, lower, "opt/app/keep", "lower")
	put(t, lower, "var/cache/a", "a")
	if err := os.Symlink(outside, filepath.Join(lower, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(lower, "bin")); err != nil {
		t.Fatal(err)
	}
	put(t, upper, "usr/bin/tool", "new")
	put(t, upper, "usr/bin/.wh.removed", "")
	put(t, upper, "var/cache/.wh..wh..opq", "")
	put(t, upper, "var/cache/b", "b")
	put(t, upper, "etc/passwd", "root:x:0:0")
	put(t, upper, "usr/sbin/su", "su")
	if err := os.Chmod(filepath.Join(upper, "usr/sbin/su"), 04755); err != nil {
		t.Fatal(err)
	}
	if err := Flatten(context.Background(), []string{lower, upper}, dest, &Budget{Bytes: 1 << 20, Files: 1000}); err != nil {
		t.Fatal(err)
	}
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(dest, p)); return string(b) }
	if read("usr/bin/tool") != "new" || read("opt/app/keep") != "lower" || read("var/cache/b") != "b" || read("etc/passwd") != "root:x:0:0" {
		t.Fatal("upper layer content not merged")
	}
	for _, gone := range []string{"usr/bin/removed", "var/cache/a"} {
		if _, err := os.Lstat(filepath.Join(dest, gone)); err == nil {
			t.Fatalf("%s must be hidden by a whiteout", gone)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("a lower-layer symlink redirected a write outside the destination")
	}
	if target, err := os.Readlink(filepath.Join(dest, "bin")); err != nil || target != "usr/bin" {
		t.Fatalf("symlink not preserved: %q %v", target, err)
	}
	if st, _ := os.Stat(filepath.Join(dest, "usr/sbin/su")); st == nil || st.Mode()&os.ModeSetuid != 0 {
		t.Fatal("set-ID bits must be dropped")
	}
	if err := Flatten(context.Background(), []string{lower}, t.TempDir(), &Budget{Bytes: 1, Files: 1000}); !errors.Is(err, ErrFlattenBudget) || !strings.Contains(err.Error(), "size") {
		t.Fatalf("budget not enforced: %v", err)
	}
}
