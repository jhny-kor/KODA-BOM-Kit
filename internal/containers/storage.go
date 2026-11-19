package containers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"koda.local/security-sbom-linux/internal/model"
)

// Stored is an image or a container that is not running, found in local
// runtime storage. Layers are host directories, lowest first; together they
// form the root filesystem the image or container would start from.
type Stored struct {
	ID      string   `json:"id"`
	Names   []string `json:"names,omitempty"`
	Runtime string   `json:"runtime"`
	Image   string   `json:"image,omitempty"`
	ImageID string   `json:"imageId,omitempty"`
	Layers  []string `json:"-"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var cacheID = regexp.MustCompile(`^[0-9a-f]{64}$|^[0-9a-z]{25,64}$`)

func trimDigest(id string) string { return strings.TrimPrefix(id, "sha256:") }

// Storage lists local images and stopped containers of Docker (overlay2
// graph driver) and containers-storage (Podman, CRI-O; overlay driver).
// running holds the containers found by Discover; they are not listed again.
// Images that any container uses are omitted: that container's scan covers them.
func Storage(ctx context.Context, root string, running []Container) (images, stopped []Stored, issues []model.Issue) {
	issue := func(status, p, message string) {
		if len(issues) < 200 {
			issues = append(issues, model.Issue{Collector: "container-storage", Status: status, Path: p, Message: message})
		}
	}
	isRunning, usedImages := map[string]bool{}, map[string]bool{}
	for _, c := range running {
		isRunning[c.ID] = true
		if c.ImageID != "" {
			usedImages[trimDigest(c.ImageID)] = true
		}
	}
	var all []Stored
	dockerImages, dockerContainers := docker(ctx, root, issue)
	podImages, podContainers := containersStorage(ctx, root, issue)
	ctrImages, ctrContainers := containerdStore(ctx, root, issue)
	for _, c := range append(append(dockerContainers, podContainers...), ctrContainers...) {
		usedImages[c.ImageID] = true
		if !isRunning[c.ID] {
			stopped = append(stopped, c)
		}
	}
	all = append(append(dockerImages, podImages...), ctrImages...)
	for _, image := range all {
		if !usedImages[image.ID] {
			images = append(images, image)
		}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
	sort.Slice(stopped, func(i, j int) bool { return stopped[i].ID < stopped[j].ID })
	return images, stopped, issues
}

func dockerDataRoot(root string) string {
	var daemon struct {
		DataRoot string `json:"data-root"`
	}
	if readJSON(filepath.Join(root, "etc/docker/daemon.json"), &daemon) && filepath.IsAbs(daemon.DataRoot) {
		return filepath.Join(root, daemon.DataRoot)
	}
	return filepath.Join(root, "var/lib/docker")
}

func docker(ctx context.Context, root string, issue func(string, string, string)) (images, containers []Stored) {
	base := dockerDataRoot(root)
	if _, err := os.Stat(base); err != nil {
		return nil, nil
	}
	meta := filepath.Join(base, "image/overlay2")
	if _, err := os.Stat(meta); err != nil {
		entries, _ := os.ReadDir(filepath.Join(base, "image"))
		for _, e := range entries {
			if _, err := os.Stat(filepath.Join(base, "image", e.Name(), "imagedb")); err == nil {
				issue("not_supported", "var/lib/docker/image/"+e.Name(), "Docker storage driver "+e.Name()+" is not read; its local images and stopped containers are not collected")
			}
		}
		return nil, nil // containerd image store: read through containerdStore
	}
	var repositories struct {
		Repositories map[string]map[string]string
	}
	readJSON(filepath.Join(meta, "repositories.json"), &repositories)
	names := map[string][]string{}
	for _, refs := range repositories.Repositories {
		for ref, id := range refs {
			if !strings.Contains(ref, "@") { // tags; digest references repeat the same image
				names[trimDigest(id)] = append(names[trimDigest(id)], ref)
			}
		}
	}
	layersOf := map[string][]string{}
	entries, _ := os.ReadDir(filepath.Join(meta, "imagedb/content/sha256"))
	for _, e := range entries {
		if ctx.Err() != nil || !hex64.MatchString(e.Name()) {
			continue
		}
		var config struct {
			RootFS struct {
				DiffIDs []string `json:"diff_ids"`
			} `json:"rootfs"`
		}
		if !readJSON(filepath.Join(meta, "imagedb/content/sha256", e.Name()), &config) {
			continue
		}
		layers, ok := dockerLayers(base, meta, config.RootFS.DiffIDs)
		if !ok {
			issue("incomplete", "var/lib/docker/image/overlay2", "image "+e.Name()[:12]+" has a layer that is not stored locally")
			continue
		}
		layersOf[e.Name()] = layers
		sort.Strings(names[e.Name()])
		images = append(images, Stored{ID: e.Name(), Names: names[e.Name()], Runtime: "docker", ImageID: e.Name(), Layers: layers})
	}
	dirs, _ := os.ReadDir(filepath.Join(base, "containers"))
	for _, e := range dirs {
		if ctx.Err() != nil || !hex64.MatchString(e.Name()) {
			continue
		}
		var config struct {
			Name   string
			Image  string
			Config struct{ Image string }
			State  struct{ Running bool }
		}
		if !readJSON(filepath.Join(base, "containers", e.Name(), "config.v2.json"), &config) {
			continue
		}
		c := Stored{ID: e.Name(), Names: []string{strings.TrimPrefix(config.Name, "/")}, Runtime: "docker", Image: config.Config.Image, ImageID: trimDigest(config.Image)}
		mountID := strings.TrimSpace(string(read(filepath.Join(meta, "layerdb/mounts", e.Name(), "mount-id"), 256)))
		image, ok := layersOf[c.ImageID]
		if !ok || !cacheID.MatchString(mountID) {
			issue("incomplete", "var/lib/docker/containers", "container "+e.Name()[:12]+" image or writable layer not found")
			continue
		}
		c.Layers = append(append([]string{}, image...), filepath.Join(base, "overlay2", mountID, "diff"))
		containers = append(containers, c)
	}
	return images, containers
}

// dockerLayers maps diff IDs to overlay2 directories through layer chain IDs.
func dockerLayers(base, meta string, diffIDs []string) ([]string, bool) {
	var layers []string
	chain := ""
	for _, diff := range diffIDs {
		if chain == "" {
			chain = diff
		} else {
			sum := sha256.Sum256([]byte(chain + " " + diff))
			chain = "sha256:" + hex.EncodeToString(sum[:])
		}
		id := trimDigest(chain)
		if !hex64.MatchString(id) {
			return nil, false
		}
		cache := strings.TrimSpace(string(read(filepath.Join(meta, "layerdb/sha256", id, "cache-id"), 256)))
		if !cacheID.MatchString(cache) {
			return nil, false
		}
		layers = append(layers, filepath.Join(base, "overlay2", cache, "diff"))
	}
	return layers, len(layers) > 0
}

// containersStorage reads the rootful containers/storage overlay driver.
func containersStorage(ctx context.Context, root string, issue func(string, string, string)) (images, containers []Stored) {
	base := filepath.Join(root, "var/lib/containers/storage")
	if _, err := os.Stat(filepath.Join(base, "overlay-layers")); err != nil {
		return nil, nil
	}
	type layer struct {
		ID     string `json:"id"`
		Parent string `json:"parent"`
	}
	parents := map[string]string{}
	for _, file := range []string{"layers.json", "volatile-layers.json"} {
		var list []layer
		readJSON(filepath.Join(base, "overlay-layers", file), &list)
		for _, l := range list {
			parents[l.ID] = l.Parent
		}
	}
	chain := func(top string) ([]string, bool) {
		var layers []string
		for id := top; id != ""; id = parents[id] {
			if !hex64.MatchString(id) || len(layers) > 512 {
				return nil, false
			}
			if _, ok := parents[id]; !ok {
				return nil, false
			}
			layers = append([]string{filepath.Join(base, "overlay", id, "diff")}, layers...)
		}
		return layers, len(layers) > 0
	}
	var imageList []struct {
		ID    string   `json:"id"`
		Names []string `json:"names"`
		Layer string   `json:"layer"`
	}
	readJSON(filepath.Join(base, "overlay-images/images.json"), &imageList)
	for _, image := range imageList {
		if ctx.Err() != nil || !hex64.MatchString(image.ID) {
			continue
		}
		layers, ok := chain(image.Layer)
		if !ok {
			issue("incomplete", "var/lib/containers/storage", "image "+image.ID[:12]+" layer chain is incomplete")
			continue
		}
		sort.Strings(image.Names)
		images = append(images, Stored{ID: image.ID, Names: image.Names, Runtime: "containers-storage", ImageID: image.ID, Layers: layers})
	}
	var containerList []struct {
		ID    string   `json:"id"`
		Names []string `json:"names"`
		Image string   `json:"image"`
		Layer string   `json:"layer"`
	}
	readJSON(filepath.Join(base, "overlay-containers/containers.json"), &containerList)
	for _, c := range containerList {
		if ctx.Err() != nil || !hex64.MatchString(c.ID) {
			continue
		}
		layers, ok := chain(c.Layer)
		if !ok {
			issue("incomplete", "var/lib/containers/storage", "container "+c.ID[:12]+" layer chain is incomplete")
			continue
		}
		containers = append(containers, Stored{ID: c.ID, Names: c.Names, Runtime: "containers-storage", ImageID: c.Image, Layers: layers})
	}
	return images, containers
}
