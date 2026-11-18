package collect

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"koda.local/security-sbom-linux/internal/model"
)

const (
	HostPropertyPrefix       = "koda:host:"
	RuntimeListeningProperty = "koda:runtime:listening"
	RuntimeBindScopeProperty = "koda:runtime:bind-scope"
	annotationTool           = "Tool: koda-sbom"
)

// Exposure is the listening sockets of processes whose executable belongs to
// exactly one installed package, keyed by that package's PURL.
type Exposure map[string][]model.Socket

// ListeningByPURL joins listening sockets to the package that owns the
// executable file. The installed package is not proof of the loaded version.
func ListeningByPURL(context model.Context) Exposure {
	out := Exposure{}
	for _, process := range context.ProcessLinks {
		if len(process.ListeningSockets) == 0 || !process.FilesystemComparable {
			continue
		}
		for _, file := range process.RuntimeFiles {
			if file.Path == process.Executable && file.PURL != "" {
				for _, socket := range process.ListeningSockets {
					if !slices.Contains(out[file.PURL], socket) {
						out[file.PURL] = append(out[file.PURL], socket)
					}
				}
				break
			}
		}
	}
	return out
}

func socketLabel(s model.Socket) string {
	return s.Protocol + "/" + net.JoinHostPort(s.Address, strconv.Itoa(s.Port)) + " (" + s.BindScope + ")"
}

// widestScope orders bind scopes by how many interfaces they accept.
func widestScope(list []model.Socket) string {
	rank := map[string]int{"loopback": 1, "address": 2, "all-interfaces": 3}
	best := ""
	for _, s := range list {
		if rank[s.BindScope] > rank[best] {
			best = s.BindScope
		}
	}
	return best
}

func hostPairs(host model.HostIdentity) [][2]string {
	var pairs [][2]string
	for _, p := range [][2]string{
		{"asset-tag", host.AssetTag}, {"machine-id-sha256", host.MachineIDSHA256},
		{"product-uuid-sha256", host.ProductUUIDSHA256}, {"product-serial-sha256", host.ProductSerialSHA256},
		{"board-serial-sha256", host.BoardSerialSHA256}, {"observation-scope", host.ObservationScope},
	} {
		if p[1] != "" {
			pairs = append(pairs, [2]string{HostPropertyPrefix + p[0], p[1]})
		}
	}
	return pairs
}

// AnnotateSBOMs adds host identity and runtime exposure to the SBOM files
// already written in dir. It must run before Checksums.
func AnnotateSBOMs(dir string, host model.HostIdentity, exposure Exposure) error {
	pairs := hostPairs(host)
	if len(pairs) == 0 && len(exposure) == 0 {
		return nil
	}
	for _, name := range []string{"sbom.cdx.json", CycloneDX17Filename, "sbom.spdx.json"} {
		p := filepath.Join(dir, name)
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		if name == "sbom.spdx.json" {
			err = annotateSPDX(doc, pairs, exposure)
		} else {
			err = annotateCycloneDX(doc, pairs, exposure)
		}
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(p, append(out, '\n'), 0600); err != nil {
			return err
		}
	}
	return nil
}

type namedValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func annotateCycloneDX(doc map[string]json.RawMessage, pairs [][2]string, exposure Exposure) error {
	if len(pairs) > 0 {
		metadata := map[string]json.RawMessage{}
		if raw := doc["metadata"]; len(raw) > 0 {
			if err := json.Unmarshal(raw, &metadata); err != nil {
				return err
			}
		}
		var props []namedValue
		for _, p := range pairs {
			props = append(props, namedValue{p[0], p[1]})
		}
		if err := appendRecords(metadata, "properties", props); err != nil {
			return err
		}
		var err error
		if doc["metadata"], err = json.Marshal(metadata); err != nil {
			return err
		}
	}
	if len(exposure) == 0 || len(doc["components"]) == 0 {
		return nil
	}
	var components []map[string]json.RawMessage
	if err := json.Unmarshal(doc["components"], &components); err != nil {
		return err
	}
	for _, component := range components {
		var purl string
		_ = json.Unmarshal(component["purl"], &purl)
		sockets := exposure[purl]
		if len(sockets) == 0 {
			continue
		}
		props := []namedValue{{RuntimeBindScopeProperty, widestScope(sockets)}}
		for _, s := range sockets {
			props = append(props, namedValue{RuntimeListeningProperty, socketLabel(s)})
		}
		if err := appendRecords(component, "properties", props); err != nil {
			return err
		}
	}
	var err error
	doc["components"], err = json.Marshal(components)
	return err
}

type spdxAnnotation struct {
	AnnotationDate string `json:"annotationDate"`
	AnnotationType string `json:"annotationType"`
	Annotator      string `json:"annotator"`
	Comment        string `json:"comment"`
}

func annotateSPDX(doc map[string]json.RawMessage, pairs [][2]string, exposure Exposure) error {
	var creation struct {
		Created string `json:"created"`
	}
	_ = json.Unmarshal(doc["creationInfo"], &creation)
	note := func(name, value string) spdxAnnotation {
		return spdxAnnotation{creation.Created, "OTHER", annotationTool, name + " " + value}
	}
	var notes []spdxAnnotation
	for _, p := range pairs {
		notes = append(notes, note(p[0], p[1]))
	}
	if len(notes) > 0 {
		if err := appendRecords(doc, "annotations", notes); err != nil {
			return err
		}
	}
	if len(exposure) == 0 || len(doc["packages"]) == 0 {
		return nil
	}
	var packages []map[string]json.RawMessage
	if err := json.Unmarshal(doc["packages"], &packages); err != nil {
		return err
	}
	for _, item := range packages {
		var refs []struct {
			Type    string `json:"referenceType"`
			Locator string `json:"referenceLocator"`
		}
		_ = json.Unmarshal(item["externalRefs"], &refs)
		var sockets []model.Socket
		for _, ref := range refs {
			if ref.Type == "purl" && len(exposure[ref.Locator]) > 0 {
				sockets = exposure[ref.Locator]
				break
			}
		}
		if len(sockets) == 0 {
			continue
		}
		notes := []spdxAnnotation{note(RuntimeBindScopeProperty, widestScope(sockets))}
		for _, s := range sockets {
			notes = append(notes, note(RuntimeListeningProperty, socketLabel(s)))
		}
		if err := appendRecords(item, "annotations", notes); err != nil {
			return err
		}
	}
	var err error
	doc["packages"], err = json.Marshal(packages)
	return err
}
