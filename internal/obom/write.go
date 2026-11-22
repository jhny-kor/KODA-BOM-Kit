package obom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"koda.local/security-sbom-linux/internal/containers"
	"koda.local/security-sbom-linux/internal/deployment"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/model"
)

type containerRecord struct {
	containers.Container
	Status string `json:"status"`
	Output string `json:"output"`
}
type collection struct {
	Schema                string               `json:"schema"`
	Status                string               `json:"status"`
	StartedAt             string               `json:"startedAt"`
	Host                  *model.HostIdentity  `json:"host"`
	Containers            []containerRecord    `json:"containers"`
	Images                []containerRecord    `json:"images"`
	Deployment            *deployment.Evidence `json:"deployment,omitempty"`
	RuntimeContainerScope string               `json:"runtimeContainerScope,omitempty"`
	Distribution          json.RawMessage      `json:"distribution,omitempty"`
}
type childCollection struct {
	Container          containers.Container `json:"container"`
	Status             string               `json:"status"`
	ProcessLinks       []model.ProcessLink  `json:"processLinks"`
	RuntimeObservation string               `json:"runtimeObservation,omitempty"`
	ListeningSockets   []struct {
		Executable string         `json:"executable"`
		Sockets    []model.Socket `json:"sockets"`
	} `json:"listeningSockets"`
}

// ArchiveHasRuntime checks the original context and its published checksum.
// KODA imports without a context document have no live operations inventory.
func ArchiveHasRuntime(dir string) (bool, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false, err
	}
	defer root.Close()
	checksum, err := expectedHash(root, "context.json")
	if err != nil {
		return false, err
	}
	if checksum == "" {
		if _, err := root.Lstat("context.json"); os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.New("collection context is missing its checksum")
	}
	var hint struct {
		Mode string `json:"mode"`
	}
	if err = readJSON(root, "context.json", &hint, true); err != nil {
		return false, err
	}
	return hint.Mode == "live-host", nil
}

func readJSON(root *os.Root, name string, out any, verify bool) error {
	f, err := evidencefile.OpenRoot(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 64<<20 {
		return fmt.Errorf("invalid or oversized evidence %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return fmt.Errorf("oversized evidence")
	}
	if verify {
		sum := sha256.Sum256(data)
		if err = verifyHash(root, name, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
	}
	return json.Unmarshal(data, out)
}

// Write exports recorded live-host observations. It reads no live system state.
// Output files are exclusively created; existing output is never replaced.
func Write(ctx context.Context, collectionDir, outputDir string, include17 bool, supplemental ...*deployment.Evidence) error {
	return write(ctx, collectionDir, outputDir, include17, true, supplemental...)
}

// WriteLive accepts root records just written by the current scan before its
// checksum manifest exists. Finalized child collections remain verified.
func WriteLive(ctx context.Context, collectionDir, outputDir string, include17 bool) error {
	return write(ctx, collectionDir, outputDir, include17, false)
}

func write(ctx context.Context, collectionDir, outputDir string, include17, verify bool, supplemental ...*deployment.Evidence) error {
	root, err := os.OpenRoot(collectionDir)
	if err != nil {
		return err
	}
	defer root.Close()
	var source collection
	var hostContext model.Context
	if err = readJSON(root, "collection.json", &source, verify); err != nil {
		return err
	}
	if err = readJSON(root, "context.json", &hostContext, verify); err != nil {
		return err
	}
	if len(supplemental) > 1 {
		return fmt.Errorf("at most one supplemental deployment evidence is supported")
	}
	if len(supplemental) == 1 {
		source.Deployment, err = deployment.Merge(source.Deployment, supplemental[0])
		if err != nil {
			return err
		}
	}
	if source.Schema != "koda-sbom-collection-v1" || source.Status == "failed" || hostContext.Mode != "live-host" {
		return fmt.Errorf("OBOM requires a successful or partial live-host collection")
	}
	if source.Status != "completed" && source.Status != "partial" {
		return fmt.Errorf("unsupported collection status %q", source.Status)
	}
	g := newGraph()
	identity := ""
	if source.Host != nil {
		identity = source.Host.MachineIDSHA256
		if identity == "" {
			identity = source.Host.ProductUUIDSHA256
		}
	}
	if identity == "" {
		identity = "collection:" + source.StartedAt
	}
	host := reference("host", identity)
	hostProps := []property{prop("role", "host"), prop("collection-status", source.Status)}
	name := "Observed host"
	if source.Host != nil {
		if source.Host.AssetTag != "" {
			name = source.Host.AssetTag
		}
		b, _ := json.Marshal(source.Host)
		hostProps = append(hostProps, prop("host-identity", string(b)))
	}
	g.components[host] = component{Type: "device", Ref: host, Name: name, Properties: hostProps}
	hostRecord := g.components[host]
	for _, entry := range []struct {
		name  string
		value any
	}{{"distribution", source.Distribution}, {"running-kernel", hostContext.RunningKernel}, {"kernel-flavor", hostContext.KernelFlavor}, {"loaded-modules", hostContext.LoadedModules}, {"settings", hostContext.Settings}, {"livepatch", hostContext.Livepatch}, {"firewall-declarations", hostContext.Firewall}} {
		raw, marshalErr := json.Marshal(entry.value)
		if marshalErr != nil {
			return marshalErr
		}
		if len(raw) > 4<<20 {
			return fmt.Errorf("runtime context exceeds OBOM property limit")
		}
		if string(raw) != "null" && string(raw) != "\"\"" {
			hostRecord.Properties = append(hostRecord.Properties, prop(entry.name, string(raw)))
		}
	}
	g.components[host] = hostRecord
	g.firewall = hostContext.Firewall
	g.processes(host, hostContext.ProcessLinks)
	g.units(host, hostContext.EnabledServices)
	g.jobs(host, hostContext.ScheduledJobs)
	for _, s := range hostContext.UnattributedSockets {
		g.socket(host, "", s)
	}
	properties := []property{prop("source-status", source.Status), prop("context-status", hostContext.Status), prop("coverage", "observed runtime relationships; missing observations remain unknown"), prop("package-version-semantics", "installed owner version; loaded memory version is unverified"), prop("network-semantics", "local binds and established outbound TCP at collection time; firewall values are file declarations, the loaded ruleset is unverified")}
	scope := source.RuntimeContainerScope
	if scope == "" {
		scope = "legacy-unspecified"
	}
	properties = append(properties, prop("container-scope", scope))
	for index, c := range append(source.Containers, source.Images...) {
		if err = ctx.Err(); err != nil {
			return err
		}
		kind := "container"
		if index >= len(source.Containers) {
			kind = "image"
		}
		ref := reference(host, kind, c.ID)
		if _, exists := g.components[ref]; exists {
			return fmt.Errorf("duplicate %s identity %s", kind, c.ID)
		}
		state := c.State
		if state == "" && c.PID > 0 {
			state = "running"
		}
		if state == "" {
			state = "unknown"
		}
		props := []property{{"koda:container:id", c.ID}, prop("scope", host), prop("state", state), prop("collection-status", c.Status), prop("image", c.Image), prop("image-id", c.ImageID)}
		props = append(props, prop("runtime", c.Runtime), prop("pod", c.Pod), prop("pod-namespace", c.PodNamespace))
		containerName := c.Name
		if containerName == "" {
			containerName = c.ID
		}
		g.components[ref] = component{Type: "container", Ref: ref, Name: containerName, Properties: props}
		g.edge(host, ref)
		if state != "running" || c.Output == "" || c.Status == "failed" || c.Status == "not_collected" {
			continue
		}
		if !filepath.IsLocal(c.Output) {
			return fmt.Errorf("container output escapes collection")
		}
		var child childCollection
		if err = readJSON(root, filepath.Join(c.Output, "collection.json"), &child, true); err != nil {
			return fmt.Errorf("container %s: %w", c.ID, err)
		}
		if child.Container.ID != c.ID {
			return fmt.Errorf("container evidence identity mismatch")
		}
		if child.Status != "completed" && child.Status != "partial" {
			continue
		}
		if child.Container.State != "" && child.Container.State != "running" {
			return fmt.Errorf("container runtime state mismatch")
		}
		if child.RuntimeObservation != "" {
			row := g.components[ref]
			row.Properties = append(row.Properties, prop("runtime-observation", child.RuntimeObservation))
			g.components[ref] = row
		}
		if len(child.ProcessLinks) > 0 || child.RuntimeObservation != "" {
			g.processes(ref, child.ProcessLinks)
			continue
		}
		// Older archives retain executable sockets and package annotations only.
		properties = append(properties, prop("legacy-container-runtime", c.ID+": listening executables only"))
		if err = g.legacyContainer(ctx, root, c.Output, ref, child); err != nil {
			return err
		}
	}
	versions := []string{"1.6"}
	if include17 {
		versions = append(versions, "1.7")
	}
	var created []string
	for _, v := range versions {
		if err = ctx.Err(); err != nil {
			break
		}
		name := "obom.cdx.json"
		if v == "1.7" {
			name = "obom.cdx-1.7.json"
		}
		var raw []byte
		raw, err = json.MarshalIndent(g.document(v, source.StartedAt, host, properties), "", "  ")
		if err != nil {
			break
		}
		if source.Deployment != nil {
			raw, err = deployment.EnrichJSON(raw, source.Deployment)
			if err != nil {
				break
			}
		}
		err = writeExclusive(outputDir, name, raw)
		if err != nil {
			break
		}
		created = append(created, filepath.Join(outputDir, name))
	}
	if err != nil {
		for _, p := range created {
			_ = os.Remove(p)
		}
	}
	return err
}

func writeExclusive(dir, name string, doc []byte) error {
	f, err := os.CreateTemp(dir, ".obom-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	_, err = f.Write(append(doc, '\n'))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Link(temporary, filepath.Join(dir, name))
}

func (g *graph) legacyContainer(ctx context.Context, root *os.Root, dir, scope string, child childCollection) error {
	owners := map[model.Socket][]string{}
	executables := map[model.Socket]map[string]bool{}
	for _, exe := range child.ListeningSockets {
		for _, s := range exe.Sockets {
			if executables[s] == nil {
				executables[s] = map[string]bool{}
			}
			executables[s][exe.Executable] = true
		}
	}
	err := streamComponents(ctx, root, filepath.Join(dir, "sbom.cdx.json"), func(c component) error {
		var sockets []model.Socket
		for _, p := range c.Properties {
			if p.Name == "koda:runtime:listening" {
				s, err := parseSocketLabel(p.Value)
				if err != nil {
					return err
				}
				sockets = append(sockets, s)
			}
		}
		if len(sockets) == 0 {
			return nil
		}
		ref := reference(scope, "source-component", c.Ref)
		old := c.Ref
		c.Ref = ref
		c.Properties = append(c.Properties, prop("source-bom-ref", old), prop("scope", scope), prop("version-evidence", "installed-owner"))
		g.components[ref] = c
		for _, s := range sockets {
			owners[s] = append(owners[s], ref)
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, errMissingComponentFile) {
			return err
		}
		expected, manifestErr := expectedHash(root, filepath.Join(dir, "sbom.cdx.json"))
		if manifestErr != nil {
			return manifestErr
		}
		if expected != "" {
			return fmt.Errorf("manifest-declared component evidence is missing")
		}
		c := g.components[scope]
		c.Properties = append(c.Properties, prop("package-attribution", "missing-cyclonedx-evidence"))
		g.components[scope] = c
	}
	for _, exe := range child.ListeningSockets {
		ref := reference(scope, "executable", exe.Executable)
		g.components[ref] = component{Type: "application", Ref: ref, Name: exe.Executable, Properties: []property{prop("scope", scope), prop("state", "running"), prop("observation", "listening-executable")}}
		g.edge(scope, ref)
		for _, s := range exe.Sockets {
			// A package-to-socket annotation is attributable only when unique.
			if len(owners[s]) == 1 && len(executables[s]) == 1 {
				g.edge(ref, owners[s][0])
			}
			g.socket(scope, ref, s)
		}
	}
	return nil
}

func streamComponents(ctx context.Context, root *os.Root, name string, visit func(component) error) error {
	f, err := evidencefile.OpenRoot(root, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", errMissingComponentFile, name)
		}
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 8<<30 {
		return fmt.Errorf("invalid or oversized component evidence")
	}
	hash := sha256.New()
	input := &jsonBudgetReader{reader: io.TeeReader(io.LimitReader(f, 8<<30+1), hash), ctx: ctx}
	d := &boundedJSON{decoder: json.NewDecoder(input), input: input}
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return fmt.Errorf("invalid component document")
	}
	for d.More() {
		if err = ctx.Err(); err != nil {
			return err
		}
		key, err := d.Token()
		if err != nil {
			return err
		}
		if key != "components" {
			if err = skipJSON(d); err != nil {
				return err
			}
			continue
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('[') {
			return fmt.Errorf("invalid components")
		}
		for d.More() {
			if err = ctx.Err(); err != nil {
				return err
			}
			var c component
			if err = d.Decode(&c); err != nil {
				return err
			}
			if err = visit(c); err != nil {
				return err
			}
		}
		if _, err = d.Token(); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return fmt.Errorf("trailing component data")
	}
	return verifyHash(root, name, hex.EncodeToString(hash.Sum(nil)))
}

var errMissingComponentFile = errors.New("component evidence file missing")

func verifyHash(root *os.Root, name, digest string) error {
	expected, err := expectedHash(root, name)
	if err != nil {
		return err
	}
	if expected == "" {
		return fmt.Errorf("missing checksum for %s", name)
	}
	if expected != digest {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}

func expectedHash(root *os.Root, name string) (string, error) {
	manifest := filepath.Join(filepath.Dir(name), "SHA256SUMS")
	f, err := evidencefile.OpenRoot(root, manifest)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return "", err
	}
	if len(data) > 1<<20 {
		return "", fmt.Errorf("checksum manifest too large")
	}
	wanted := filepath.Base(name)
	found := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("invalid checksum manifest")
		}
		if strings.TrimPrefix(fields[1], "*") != wanted {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("duplicate checksum for %s", name)
		}
		found = fields[0]
	}
	return found, nil
}
func skipJSON(d *boundedJSON) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if !strings.ContainsRune("[{", rune(delim)) {
		return fmt.Errorf("unexpected JSON delimiter")
	}
	for d.More() {
		if delim == '{' {
			if _, err = d.Token(); err != nil {
				return err
			}
		}
		if err = skipJSON(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

// Each decoder operation has a separate byte budget. This bounds a single
// component or skipped scalar while permitting large streamed BOM documents.
const maxJSONRecordBytes int64 = 16 << 20

type jsonBudgetReader struct {
	reader          io.Reader
	ctx             context.Context
	read, remaining int64
}

func (r *jsonBudgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		return 0, fmt.Errorf("JSON evidence record exceeds %d bytes", maxJSONRecordBytes)
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.read += int64(n)
	r.remaining -= int64(n)
	return n, err
}

type boundedJSON struct {
	decoder *json.Decoder
	input   *jsonBudgetReader
}

func (d *boundedJSON) reset() {
	d.input.remaining = maxJSONRecordBytes - (d.input.read - d.decoder.InputOffset())
}
func (d *boundedJSON) Token() (json.Token, error) { d.reset(); return d.decoder.Token() }
func (d *boundedJSON) Decode(v any) error         { d.reset(); return d.decoder.Decode(v) }
func (d *boundedJSON) More() bool                 { d.reset(); return d.decoder.More() }
