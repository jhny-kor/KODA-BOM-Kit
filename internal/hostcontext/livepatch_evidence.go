package hostcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
)

const maxLivepatchReportBytes = 1 << 20
const livepatchEvidenceSchema = "koda-sbom-livepatch-evidence-v1"

var livepatchKernelToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var livepatchCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var installedKspliceLine = regexp.MustCompile(`^\s*\[([A-Za-z0-9]{1,64})\]\s+(.+)$`)
var kspliceFixPrefix = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}):`)
var canonicalKernelBuild = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)(?:\.[0-9]+)?(-[A-Za-z0-9._+-]+)$`)

type livepatchIdentity struct {
	Kernel     string
	BootIDHash string
	Now        time.Time
}

type livepatchEvidence struct {
	Schema          string                `json:"schema"`
	Provider        string                `json:"provider"`
	CapturedAt      string                `json:"capturedAt"`
	Kernel          string                `json:"kernel"`
	BootIDHash      string                `json:"bootIDHash"`
	RawReportSHA256 string                `json:"rawReportSHA256,omitempty"`
	QueryStatus     string                `json:"queryStatus,omitempty"`
	Report          model.LivepatchStatus `json:"report"`
}

func livepatchProvider(provider string) bool {
	return provider == "canonical-livepatch" || provider == "ksplice" || provider == "uptrack"
}

func livepatchQueryReason(reason string) bool {
	return reason == "not_installed" || reason == "query_failed" || reason == "query_timed_out" || reason == "invalid_report"
}

func clientLivepatchStatus(provider string) model.LivepatchStatus {
	return model.LivepatchStatus{Provider: provider, EvidenceKind: "imported-client-status", Source: "provided-client-status", Status: "observed", Patches: []model.LivepatchPatch{}, Limitations: []string{"Client-reported state is not an independent CVE remediation verdict", "Evidence is bound to the capturing kernel and boot ID, but is not authenticated or an atomic snapshot", "A client report cannot establish coverage of all vulnerabilities or other patch mechanisms"}}
}

// CaptureLivepatchEvidence sanitizes an explicitly supplied client status report.
// It never starts the client, invokes another command, or contacts a service.
func CaptureLivepatchEvidence(provider string, report []byte, effectiveKernel string) ([]byte, error) {
	identity, err := livepatchHostIdentity()
	if err != nil {
		return nil, err
	}
	return captureLivepatchEvidence(provider, report, effectiveKernel, identity)
}

// CaptureUnavailableLivepatchEvidence records an unavailable explicit client
// query without retaining command stderr, account details or configuration.
func CaptureUnavailableLivepatchEvidence(provider, reason string) ([]byte, error) {
	identity, err := livepatchHostIdentity()
	if err != nil {
		return nil, err
	}
	if !livepatchProvider(provider) || !livepatchQueryReason(reason) {
		return nil, errors.New("unsupported livepatch provider or query status")
	}
	status := clientLivepatchStatus(provider)
	status.Status = "unknown"
	if reason == "not_installed" {
		status.Status = "not_observed"
	}
	status.CapturedAt = identity.Now.UTC().Format(time.RFC3339)
	status.ReportedKernel = identity.Kernel
	return json.MarshalIndent(livepatchEvidence{Schema: livepatchEvidenceSchema, Provider: provider, CapturedAt: status.CapturedAt, Kernel: identity.Kernel, BootIDHash: identity.BootIDHash, QueryStatus: reason, Report: status}, "", "  ")
}

func captureLivepatchEvidence(provider string, raw []byte, effectiveKernel string, identity livepatchIdentity) ([]byte, error) {
	if !livepatchProvider(provider) || len(raw) == 0 || len(raw) > maxLivepatchReportBytes {
		return nil, errors.New("unsupported livepatch provider or invalid report size")
	}
	if effectiveKernel != "" && !livepatchKernelToken.MatchString(strings.TrimSpace(effectiveKernel)) {
		return nil, errors.New("invalid effective kernel version")
	}
	status := clientLivepatchStatus(provider)
	var err error
	if provider == "canonical-livepatch" {
		err = parseCanonicalLivepatch(raw, &status)
	} else {
		err = parseKspliceReport(raw, &status)
	}
	if err != nil {
		return nil, err
	}
	if provider == "canonical-livepatch" && !canonicalKernelMatches(status.ReportedKernel, identity.Kernel) {
		return nil, errors.New("Canonical report running kernel differs from capturing host")
	}
	if effectiveKernel != "" {
		status.EffectiveKernel = strings.TrimSpace(effectiveKernel)
	}
	status.CapturedAt = identity.Now.UTC().Format(time.RFC3339)
	if status.ReportedKernel == "" {
		status.ReportedKernel = identity.Kernel
	}
	hash := sha256.Sum256(raw)
	evidence := livepatchEvidence{Schema: livepatchEvidenceSchema, Provider: provider, CapturedAt: status.CapturedAt, Kernel: identity.Kernel, BootIDHash: identity.BootIDHash, RawReportSHA256: hex.EncodeToString(hash[:]), Report: status}
	return json.MarshalIndent(evidence, "", "  ")
}

func parseCanonicalLivepatch(raw []byte, status *model.LivepatchStatus) error {
	var report struct {
		LastCheck string `json:"Last-Check"`
		Status    []struct {
			Running   bool
			Kernel    string
			Livepatch struct {
				State      string
				CheckState string
				Version    string
				Fixes      []struct {
					Name    string
					Patched bool
				}
			}
		}
	}
	if err := json.Unmarshal(raw, &report); err != nil || len(report.Status) > maxLivepatchEntries {
		return errors.New("invalid Canonical Livepatch JSON report")
	}
	if report.LastCheck != "" {
		lastCheck, err := time.Parse(time.RFC3339Nano, report.LastCheck)
		if err != nil {
			return errors.New("invalid Canonical last-check timestamp")
		}
		status.ClientReportedAt = lastCheck.UTC().Format(time.RFC3339)
	}
	count := 0
	for _, kernel := range report.Status {
		if !kernel.Running {
			continue
		}
		count++
		if !livepatchKernelToken.MatchString(kernel.Kernel) || len(kernel.Livepatch.Fixes) > maxLivepatchEntries {
			return errors.New("invalid running-kernel Livepatch entry")
		}
		status.ReportedKernel = kernel.Kernel
		switch kernel.Livepatch.CheckState {
		case "checked", "check-failed", "needs-check":
			status.ClientCheckState = kernel.Livepatch.CheckState
		default:
			status.ClientCheckState = "unknown"
		}
		applied := kernel.Livepatch.State == "applied"
		if !applied && kernel.Livepatch.State != "nothing-to-apply" {
			status.Status = "unknown"
		}
		for _, fix := range kernel.Livepatch.Fixes {
			if !livepatchCVE.MatchString(fix.Name) {
				continue
			}
			patch := model.LivepatchPatch{ID: fix.Name, State: "not-reported-patched", CVEs: []string{fix.Name}}
			if applied && fix.Patched {
				patch.State, patch.ReportedState = "reported-applied", "applied"
			}
			status.Patches = append(status.Patches, patch)
		}
		if len(status.Patches) == 0 && simpleToken.MatchString(kernel.Livepatch.Version) {
			patch := model.LivepatchPatch{ID: kernel.Livepatch.Version, State: "unknown"}
			if applied {
				patch.State, patch.ReportedState = "reported-applied", "applied"
			}
			status.Patches = append(status.Patches, patch)
		}
	}
	if count != 1 {
		return errors.New("Canonical report must identify exactly one running kernel")
	}
	return nil
}

func parseKspliceReport(raw []byte, status *model.LivepatchStatus) error {
	installed, seenInstalled, kernelHeader, recognizedInstalled := false, false, false, false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "Ksplice kernel updates:":
			kernelHeader = true
		case "Installed updates:":
			installed = status.Provider == "uptrack" || kernelHeader
			seenInstalled = seenInstalled || installed
		case "Available updates:", "Ksplice userspace updates:", "Userspace updates:":
			installed = false
			if trimmed != "Available updates:" {
				kernelHeader = false
			}
		}
		if strings.HasPrefix(trimmed, "Effective kernel version is ") {
			version := strings.TrimSpace(strings.TrimPrefix(trimmed, "Effective kernel version is "))
			if livepatchKernelToken.MatchString(version) {
				status.EffectiveKernel = version
			}
			installed = false
		}
		if !installed {
			continue
		}
		if trimmed == "None" || trimmed == "None." {
			recognizedInstalled = true
			continue
		}
		match := installedKspliceLine.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		if len(status.Patches) >= maxLivepatchEntries {
			return errors.New("Ksplice report patch limit exceeded")
		}
		patch := model.LivepatchPatch{ID: match[1], State: "reported-applied", ReportedState: "applied"}
		recognizedInstalled = true
		if cve := kspliceFixPrefix.FindStringSubmatch(match[2]); len(cve) > 0 {
			patch.CVEs = []string{cve[1]}
		}
		status.Patches = append(status.Patches, patch)
	}
	if !seenInstalled || !recognizedInstalled || status.Provider == "ksplice" && !kernelHeader {
		return errors.New("Ksplice report lacks an installed kernel update section")
	}
	return nil
}

// LoadLivepatchEvidence imports only a bounded regular local file. It rechecks
// kernel, boot and capture time; stale or foreign evidence loses applied state.
func LoadLivepatchEvidence(ctx context.Context, filename string) (model.LivepatchStatus, error) {
	if err := ctx.Err(); err != nil {
		return model.LivepatchStatus{}, err
	}
	resolved, err := localfs.ResolveLocal(filename)
	if err != nil {
		return model.LivepatchStatus{}, errors.New("livepatch evidence must be on a verified local filesystem")
	}
	if info, err := os.Lstat(filename); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return model.LivepatchStatus{}, errors.New("livepatch evidence must be a regular non-symlink file")
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return model.LivepatchStatus{}, errors.New("cannot open livepatch evidence root")
	}
	defer root.Close()
	f, err := openNoFollow(root, strings.TrimPrefix(filepath.ToSlash(resolved), "/"))
	if err != nil {
		return model.LivepatchStatus{}, errors.New("cannot safely open livepatch evidence")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return model.LivepatchStatus{}, errors.New("livepatch evidence must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLivepatchReportBytes+1))
	if err != nil || len(data) > maxLivepatchReportBytes {
		return model.LivepatchStatus{}, errors.New("livepatch evidence read failed or exceeded limit")
	}
	identity, err := livepatchHostIdentity()
	if err != nil {
		return model.LivepatchStatus{}, err
	}
	return loadLivepatchEvidenceBytes(ctx, data, identity)
}

func loadLivepatchEvidenceBytes(ctx context.Context, raw []byte, identity livepatchIdentity) (model.LivepatchStatus, error) {
	if err := ctx.Err(); err != nil {
		return model.LivepatchStatus{}, err
	}
	if len(raw) > maxLivepatchReportBytes {
		return model.LivepatchStatus{}, errors.New("livepatch evidence size limit exceeded")
	}
	var evidence livepatchEvidence
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil || decoder.Decode(new(any)) != io.EOF {
		return model.LivepatchStatus{}, errors.New("invalid livepatch evidence JSON")
	}
	if evidence.Schema != livepatchEvidenceSchema || !livepatchProvider(evidence.Provider) || !livepatchKernelToken.MatchString(evidence.Kernel) || !validSHA256(evidence.BootIDHash) || evidence.RawReportSHA256 != "" && !validSHA256(evidence.RawReportSHA256) || evidence.QueryStatus != "" && !livepatchQueryReason(evidence.QueryStatus) {
		return model.LivepatchStatus{}, errors.New("invalid livepatch evidence identity or schema")
	}
	captured, err := time.Parse(time.RFC3339, evidence.CapturedAt)
	if err != nil || !validClientLivepatchStatus(evidence.Report, evidence.Provider) {
		return model.LivepatchStatus{}, errors.New("invalid livepatch evidence report")
	}
	status := evidence.Report
	// Reconstruct explanatory fields rather than trusting imported arbitrary text.
	status.Limitations = clientLivepatchStatus(evidence.Provider).Limitations
	status.CapturedAt = evidence.CapturedAt
	status.ObservedAt = identity.Now.UTC().Format(time.RFC3339)
	status.EvidenceSHA256 = ""
	status.Source = "provided-client-status"
	if evidence.QueryStatus != "" {
		status.Status = "unknown"
		status.Patches = []model.LivepatchPatch{}
		if evidence.QueryStatus == "not_installed" {
			status.Status = "not_observed"
		}
		status.Limitations = append(status.Limitations, "Explicit client query status: "+evidence.QueryStatus)
	}
	if evidence.Kernel != identity.Kernel || evidence.BootIDHash != identity.BootIDHash {
		status.Status = "identity_mismatch"
		status.Limitations = append(status.Limitations, "Capture kernel or boot identity differs from the collecting host")
	} else if identity.Now.Sub(captured) > 24*time.Hour || captured.Sub(identity.Now) > 5*time.Minute {
		status.Status = "stale"
		status.Limitations = append(status.Limitations, "Evidence is older than 24 hours or more than five minutes in the future")
	}
	if evidence.Provider == "canonical-livepatch" && evidence.QueryStatus == "" && !canonicalKernelMatches(status.ReportedKernel, evidence.Kernel) {
		status.Status = "identity_mismatch"
		status.Limitations = append(status.Limitations, "Canonical running-kernel report differs from capture identity")
	}
	if evidence.Provider == "canonical-livepatch" && evidence.QueryStatus == "" {
		lastCheck, err := time.Parse(time.RFC3339, status.ClientReportedAt)
		if err != nil || status.ClientCheckState != "checked" {
			if status.Status == "observed" {
				status.Status = "unknown"
			}
			status.Limitations = append(status.Limitations, "Canonical report lacks a successful timestamped last check")
		} else if identity.Now.Sub(lastCheck) > 24*time.Hour || lastCheck.Sub(identity.Now) > 5*time.Minute {
			if status.Status != "identity_mismatch" {
				status.Status = "stale"
			}
			status.Limitations = append(status.Limitations, "Canonical cached last-check time is outside the evidence freshness window")
		}
	}
	if status.Status == "identity_mismatch" || status.Status == "stale" || status.Status == "unknown" {
		for i := range status.Patches {
			status.Patches[i].State = "unknown"
			status.Patches[i].Enabled, status.Patches[i].Transition = nil, nil
		}
	}
	hash := sha256.Sum256(raw)
	status.EvidenceSHA256 = hex.EncodeToString(hash[:])
	return status, nil
}

func canonicalKernelMatches(reported, running string) bool {
	if reported == running {
		return true
	}
	// Canonical may report the Debian package ABI.build while uname omits build.
	normalize := func(kernel string) string {
		parts := canonicalKernelBuild.FindStringSubmatch(kernel)
		if len(parts) != 3 {
			return kernel
		}
		return parts[1] + parts[2]
	}
	return normalize(reported) == normalize(running)
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validClientLivepatchStatus(status model.LivepatchStatus, provider string) bool {
	if status.Provider != provider || status.EvidenceKind != "imported-client-status" || status.Source != "provided-client-status" || len(status.Patches) > maxLivepatchEntries {
		return false
	}
	if status.Status != "observed" && status.Status != "unknown" && status.Status != "not_observed" {
		return false
	}
	if status.ReportedKernel != "" && !livepatchKernelToken.MatchString(status.ReportedKernel) || status.EffectiveKernel != "" && !livepatchKernelToken.MatchString(status.EffectiveKernel) {
		return false
	}
	if status.ClientReportedAt != "" {
		if _, err := time.Parse(time.RFC3339, status.ClientReportedAt); err != nil {
			return false
		}
	}
	if status.ClientCheckState != "" && status.ClientCheckState != "checked" && status.ClientCheckState != "check-failed" && status.ClientCheckState != "needs-check" && status.ClientCheckState != "unknown" {
		return false
	}
	for _, patch := range status.Patches {
		if !simpleToken.MatchString(patch.ID) || patch.Enabled != nil || patch.Transition != nil || len(patch.CVEs) > maxLivepatchEntries {
			return false
		}
		if patch.State != "reported-applied" && patch.State != "not-reported-patched" && patch.State != "unknown" || patch.ReportedState != "" && patch.ReportedState != "applied" {
			return false
		}
		for _, cve := range patch.CVEs {
			if !livepatchCVE.MatchString(cve) {
				return false
			}
		}
	}
	return true
}
