package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/evidencefile"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

// An operator supplies a point-in-time connectivity observation with a host identity.
// No connection is made by the collector.
type NetworkReport struct {
	HostField string                  `json:"hostField"`
	HostValue string                  `json:"hostValue"`
	SHA256    string                  `json:"sourceSha256"`
	Tests     []ConnectionObservation `json:"observations"`
}

type ConnectionObservation struct {
	Scope         string `json:"scope"`
	BindAddress   string `json:"bindAddress"`
	TargetAddress string `json:"targetAddress"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	Vantage       string `json:"vantage"`
	ObservedAt    string `json:"observedAt"`
	Result        string `json:"result"`
}

func LoadNetworkReports(ctx context.Context, paths []string) ([]NetworkReport, error) {
	if len(paths) > 8 {
		return nil, errors.New("at most eight network observation files are supported")
	}
	var reports []NetworkReport
	seen := map[string]bool{}
	total := 0
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := readNetworkReport(path)
		if err != nil {
			return nil, err
		}
		if seen[report.SHA256] {
			continue
		}
		seen[report.SHA256] = true
		total += len(report.Tests)
		if total > 4096 {
			return nil, errors.New("network observation count exceeds 4096")
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func readNetworkReport(path string) (NetworkReport, error) {
	var out NetworkReport
	path, err := localfs.ResolveLocal(path)
	if err != nil {
		return out, err
	}
	f, err := evidencefile.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	info, err := f.Stat()
	const limit = 2 << 20
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return out, errors.New("network evidence must be a regular file at most 2 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) > limit {
		return out, errors.New("cannot read network evidence within size limit")
	}
	var input struct {
		Schema    string                  `json:"schema"`
		HostField string                  `json:"hostField"`
		HostValue string                  `json:"hostValue"`
		Tests     []ConnectionObservation `json:"observations"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&input); err != nil || d.Decode(new(any)) != io.EOF || input.Schema != "koda-network-observations-1" {
		return out, errors.New("invalid network observation document")
	}
	out = NetworkReport{HostField: input.HostField, HostValue: input.HostValue, Tests: input.Tests, SHA256: fmt.Sprintf("%x", sha256.Sum256(b))}
	return out, out.validate()
}

func (r NetworkReport) validate() error {
	validHost := false
	switch r.HostField {
	case "machineIdSha256", "productUuidSha256":
		validHost = hexID.MatchString(r.HostValue)
	case "assetTag":
		validHost = uidText.MatchString(r.HostValue)
	}
	if !validHost || !hexID.MatchString(r.SHA256) || len(r.Tests) == 0 || len(r.Tests) > 4096 {
		return errors.New("network evidence requires a valid host identity, digest and observations")
	}
	for _, v := range r.Tests {
		bind, err1 := netip.ParseAddr(v.BindAddress)
		target, err2 := netip.ParseAddr(v.TargetAddress)
		_, errTime := time.Parse(time.RFC3339Nano, v.ObservedAt)
		if err1 != nil || err2 != nil || bind.Zone() != "" || target.Zone() != "" || target.IsUnspecified() || target.IsMulticast() || bind.BitLen() != target.BitLen() || (!bind.IsUnspecified() && bind != target) || v.Protocol != "tcp" || v.Port < 1 || v.Port > 65535 || (v.Scope != "host" && !hexID.MatchString(v.Scope)) || !uidText.MatchString(v.Vantage) || errTime != nil || !slices.Contains([]string{"connected", "refused", "timed-out"}, v.Result) {
			return errors.New("invalid TCP observation scope, endpoint, vantage, timestamp or result")
		}
	}
	return nil
}

type networkProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type socketKey struct {
	scope, bind string
	port        int
}

func attachNetwork(reports []NetworkReport, hostRaw json.RawMessage, containers map[string]string, services []json.RawMessage) (int, int, error) {
	var host struct {
		Ref        string `json:"bom-ref"`
		Properties []networkProperty
	}
	if err := json.Unmarshal(hostRaw, &host); err != nil {
		return 0, 0, errors.New("OBOM host identity missing")
	}
	var identity model.HostIdentity
	for _, p := range host.Properties {
		if p.Name == "koda:obom:host-identity" {
			if err := json.Unmarshal([]byte(p.Value), &identity); err != nil {
				return 0, 0, err
			}
		}
	}
	identities := map[string]string{"assetTag": identity.AssetTag, "machineIdSha256": identity.MachineIDSHA256, "productUuidSha256": identity.ProductUUIDSHA256}
	indices := map[socketKey][]int{}
	for i, raw := range services {
		var row struct{ Properties []networkProperty }
		if err := json.Unmarshal(raw, &row); err != nil {
			return 0, 0, err
		}
		p := map[string]string{}
		for _, v := range row.Properties {
			p[v.Name] = v.Value
		}
		if p["koda:obom:observation"] != "listening-socket" || strings.TrimSuffix(p["koda:obom:protocol"], "6") != "tcp" {
			continue
		}
		addr, err := netip.ParseAddr(p["koda:obom:bind-address"])
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(p["koda:obom:port"])
		if err != nil {
			continue
		}
		k := socketKey{p["koda:obom:scope"], addr.String(), port}
		indices[k] = append(indices[k], i)
	}
	additions := map[int][]networkProperty{}
	matched, unmatched := 0, 0
	total := 0
	if len(reports) > 8 {
		return 0, 0, errors.New("too many network reports")
	}
	for _, r := range reports {
		if err := r.validate(); err != nil {
			return 0, 0, err
		}
		if identities[r.HostField] != r.HostValue {
			return 0, 0, errors.New("network evidence refers to a different or unknown host")
		}
		total += len(r.Tests)
		if total > 4096 {
			return 0, 0, errors.New("too many network observations")
		}
		for _, observation := range r.Tests {
			scope := host.Ref
			if observation.Scope != "host" {
				scope = containers[observation.Scope]
			}
			bind, _ := netip.ParseAddr(observation.BindAddress)
			ids := indices[socketKey{scope, bind.String(), observation.Port}]
			if len(ids) != 1 || scope == "" {
				unmatched++
				continue
			}
			value, _ := json.Marshal(struct {
				ConnectionObservation
				SourceSHA256 string `json:"sourceSha256"`
			}{observation, r.SHA256})
			i := ids[0]
			additions[i] = append(additions[i], networkProperty{"koda:network:reported-test", string(value)})
			matched++
		}
	}
	for i, extra := range additions {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(services[i], &row); err != nil {
			return 0, 0, err
		}
		var existing []networkProperty
		if err := json.Unmarshal(row["properties"], &existing); err != nil {
			return 0, 0, err
		}
		row["properties"], _ = json.Marshal(append(existing, extra...))
		services[i], _ = json.Marshal(row)
	}
	return matched, unmatched, nil
}
