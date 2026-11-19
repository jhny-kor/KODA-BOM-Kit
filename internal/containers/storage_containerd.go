package containers

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// containerd roots: the system daemon (Kubernetes, nerdctl, Docker 29 image
// store), a dockerd-managed daemon, and k3s/RKE2.
var containerdRoots = []string{
	"var/lib/containerd",
	"var/lib/docker/containerd/daemon",
	"var/lib/rancher/k3s/agent/containerd",
	"var/lib/rancher/rke2/agent/containerd",
	"var/lib/desktop-containerd/daemon", // Docker Desktop VM
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// containerdStore reads image, container and overlayfs snapshot metadata
// from containerd's bolt databases and its content store. Containers are
// those in containerd's metadata; for Docker they keep Docker's container ID.
func containerdStore(ctx context.Context, root string, issue func(string, string, string)) (images, containers []Stored) {
	for _, rel := range containerdRoots {
		base := filepath.Join(root, rel)
		db, err := openBolt(filepath.Join(base, "io.containerd.metadata.v1.bolt/meta.db"))
		if err != nil {
			continue
		}
		snapshots, err := openBolt(filepath.Join(base, "io.containerd.snapshotter.v1.overlayfs/metadata.db"))
		if err != nil {
			db.Close()
			if !os.IsNotExist(err) { // absent: this containerd unpacks no images (dockerd with a graph driver)
				issue("incomplete", rel, "containerd overlayfs snapshot metadata unreadable; images and stopped containers not collected")
			}
			continue
		}
		s := containerdReader{ctx: ctx, base: base, rel: rel, db: db, snapshots: snapshots, issue: issue, docker: dockerDataRoot(root)}
		i, c := s.read()
		images, containers = append(images, i...), append(containers, c...)
		db.Close()
		snapshots.Close()
	}
	return images, containers
}

type containerdReader struct {
	ctx           context.Context
	base, rel     string
	db, snapshots *boltDB
	issue         func(string, string, string)
	docker        string // Docker data root, for containers in the "moby" namespace
}

func (r containerdReader) read() (images, containers []Stored) {
	v1, ok := r.db.Root().Bucket("v1")
	if !ok {
		r.issue("incomplete", r.rel, "containerd metadata has no v1 bucket")
		return nil, nil
	}
	for _, namespace := range v1.Keys() {
		ns, _ := v1.Bucket(namespace)
		byTarget := map[string]*Stored{}
		targetOf := map[string]string{}
		imageBucket, _ := ns.Bucket("images")
		for _, name := range imageBucket.Keys() {
			if r.ctx.Err() != nil {
				return images, containers
			}
			target, _ := imageBucket.Path(name, "target")
			digest := string(target.Get("digest"))
			if !digestPattern.MatchString(digest) {
				continue
			}
			targetOf[name] = digest
			if existing := byTarget[digest]; existing != nil {
				existing.Names = append(existing.Names, name)
				continue
			}
			layers, ok := r.imageLayers(ns, digest)
			if !ok {
				r.issue("incomplete", r.rel, "image "+name+" layers are not unpacked locally")
				continue
			}
			byTarget[digest] = &Stored{ID: trimDigest(digest), Names: []string{name}, Runtime: "containerd/" + namespace, ImageID: trimDigest(digest), Layers: layers}
		}
		for _, image := range byTarget {
			sort.Strings(image.Names)
			images = append(images, *image)
		}
		if namespace == "moby" {
			containers = append(containers, r.dockerContainers(ns, byTarget)...)
			continue
		}
		containerBucket, _ := ns.Bucket("containers")
		for _, id := range containerBucket.Keys() {
			c, _ := containerBucket.Bucket(id)
			if string(c.Get("snapshotter")) != "overlayfs" {
				continue
			}
			name := string(c.Get("image"))
			image := byTarget[targetOf[name]]
			upper, ok := r.snapshotDir(ns, string(c.Get("snapshotKey")))
			if image == nil || !ok {
				continue // sandbox or image removed; not a scannable container
			}
			stored := Stored{ID: id, Names: []string{id}, Runtime: "containerd/" + namespace, Image: name, ImageID: image.ID}
			if labels, ok := c.Bucket("labels"); ok {
				if n := string(labels.Get("nerdctl/name")); n != "" {
					stored.Names = []string{n}
				} else if n := string(labels.Get("io.kubernetes.container.name")); n != "" {
					stored.Names = []string{string(labels.Get("io.kubernetes.pod.namespace")) + "_" + string(labels.Get("io.kubernetes.pod.name")) + "_" + n}
				}
				if string(labels.Get("io.cri-containerd.kind")) == "sandbox" {
					continue
				}
			}
			stored.Layers = append(append([]string{}, image.Layers...), upper)
			containers = append(containers, stored)
		}
	}
	return images, containers
}

// dockerContainers finds Docker containers on the containerd image store.
// containerd keeps no record of a stopped Docker container; its writable
// snapshot is keyed by the container ID, above an "<id>-init" snapshot and
// the image's top layer.
func (r containerdReader) dockerContainers(ns boltBucket, byTarget map[string]*Stored) []Stored {
	tops := map[string]*Stored{}
	for _, image := range byTarget {
		tops[image.Layers[len(image.Layers)-1]] = image
	}
	snapshots, _ := ns.Path("snapshots", "overlayfs")
	var out []Stored
	for _, key := range snapshots.Keys() {
		if !hex64.MatchString(key) || r.ctx.Err() != nil {
			continue
		}
		var config struct {
			Name   string
			Image  string
			Config struct{ Image string }
		}
		if !readJSON(filepath.Join(r.docker, "containers", key, "config.v2.json"), &config) {
			continue
		}
		snapshot, _ := snapshots.Bucket(key)
		backend := string(snapshot.Get("name"))
		var own []string
		for depth := 0; backend != "" && depth < 4; depth++ {
			info, ok := r.snapshots.Root().Path("v1", "snapshots", backend)
			id, n := binary.Uvarint(info.Get("id"))
			if !ok || n <= 0 {
				break
			}
			dir := filepath.Join(r.base, "io.containerd.snapshotter.v1.overlayfs/snapshots", strconv.FormatUint(id, 10), "fs")
			if image := tops[dir]; image != nil {
				if exact := byTarget["sha256:"+trimDigest(config.Image)]; exact != nil && exact.Layers[len(exact.Layers)-1] == dir {
					image = exact // several tags can share a top layer
				}
				layers := append([]string{}, image.Layers...)
				for i := len(own) - 1; i >= 0; i-- {
					layers = append(layers, own[i])
				}
				out = append(out, Stored{ID: key, Names: []string{strings.TrimPrefix(config.Name, "/")}, Runtime: "docker", Image: config.Config.Image, ImageID: image.ID, Layers: layers})
				break
			}
			own = append(own, dir)
			backend = string(info.Get("parent"))
		}
	}
	return out
}

// imageLayers resolves an image target (index or manifest) to the snapshot
// directories of its layers, lowest first. An index may list platforms that
// were never pulled; the first unpacked Linux manifest is used, this
// machine's architecture first (Docker Desktop also runs amd64 images on arm64).
func (r containerdReader) imageLayers(ns boltBucket, digest string) ([]string, bool) {
	return r.manifestLayers(ns, digest, 0)
}

func (r containerdReader) manifestLayers(ns boltBucket, digest string, depth int) ([]string, bool) {
	var doc struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if depth > 2 || !r.blob(digest, &doc) {
		return nil, false
	}
	if doc.Config.Digest == "" {
		sort.SliceStable(doc.Manifests, func(i, j int) bool {
			return doc.Manifests[i].Platform.Architecture == runtime.GOARCH && doc.Manifests[j].Platform.Architecture != runtime.GOARCH
		})
		for _, m := range doc.Manifests {
			if m.Platform.OS != "linux" || !r.hasBlob(m.Digest) {
				continue
			}
			if layers, ok := r.manifestLayers(ns, m.Digest, depth+1); ok {
				return layers, true
			}
		}
		return nil, false
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if !r.blob(doc.Config.Digest, &config) || len(config.RootFS.DiffIDs) == 0 {
		return nil, false
	}
	var layers []string
	chain := ""
	for _, diff := range config.RootFS.DiffIDs {
		if chain == "" {
			chain = diff
		} else {
			sum := sha256.Sum256([]byte(chain + " " + diff))
			chain = "sha256:" + hex.EncodeToString(sum[:])
		}
		dir, ok := r.snapshotDir(ns, chain)
		if !ok {
			return nil, false
		}
		layers = append(layers, dir)
	}
	return layers, true
}

// snapshotDir maps a namespaced snapshot key to the overlayfs directory.
func (r containerdReader) snapshotDir(ns boltBucket, key string) (string, bool) {
	snapshot, ok := ns.Path("snapshots", "overlayfs", key)
	if !ok || key == "" {
		return "", false
	}
	backend := string(snapshot.Get("name"))
	info, ok := r.snapshots.Root().Path("v1", "snapshots", backend)
	if !ok || backend == "" {
		return "", false
	}
	id, n := binary.Uvarint(info.Get("id"))
	if n <= 0 {
		return "", false
	}
	return filepath.Join(r.base, "io.containerd.snapshotter.v1.overlayfs/snapshots", strconv.FormatUint(id, 10), "fs"), true
}

func (r containerdReader) blobPath(digest string) string {
	return filepath.Join(r.base, "io.containerd.content.v1.content/blobs/sha256", strings.TrimPrefix(digest, "sha256:"))
}

func (r containerdReader) hasBlob(digest string) bool {
	return digestPattern.MatchString(digest) && read(r.blobPath(digest), 4<<20) != nil
}

func (r containerdReader) blob(digest string, v any) bool {
	if !digestPattern.MatchString(digest) {
		return false
	}
	data := read(r.blobPath(digest), 4<<20)
	return data != nil && json.Unmarshal(data, v) == nil
}
