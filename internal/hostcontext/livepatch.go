package hostcontext

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/model"
)

const (
	maxLivepatchEntries        = 128
	maxLivepatchAttributeBytes = 128
	maxLivepatchModules        = 4096
)

// Read only the kernel's explicitly documented livepatch attributes. A missing
// source is not evidence that no vendor client, patch or vulnerable code exists.
func collectLivepatch(ctx context.Context, root *os.Root, out *model.Context) {
	linux := model.LivepatchStatus{Provider: "linux-livepatch", EvidenceKind: "live-kernel-sysfs", Source: "sys/kernel/livepatch", Status: "not_observed", ObservedAt: time.Now().UTC().Format(time.RFC3339), Patches: []model.LivepatchPatch{}, Limitations: []string{"Kernel patch state is a point-in-time observation, not a CVE coverage verdict", "Missing sysfs entries do not establish that a vendor client or patch is absent"}}
	collectPatchDirectory(ctx, root, out, &linux, false)
	out.Livepatch = append(out.Livepatch, linux)
	ksplice := model.LivepatchStatus{Provider: "ksplice-legacy", EvidenceKind: "live-kernel-sysfs", Source: "sys/kernel/ksplice", Status: "not_observed", ObservedAt: linux.ObservedAt, Patches: []model.LivepatchPatch{}, Limitations: []string{"Legacy Ksplice stage ABI only; modern Uptrack/Enhanced Client coverage requires a client status report", "Ksplice update identifiers are not mapped to CVEs by this source"}}
	collectPatchDirectory(ctx, root, out, &ksplice, true)
	out.Livepatch = append(out.Livepatch, ksplice)
	standalone := model.LivepatchStatus{Provider: "ksplice-legacy", EvidenceKind: "live-kernel-sysfs", Source: "sys/module/*/ksplice", Status: "not_observed", ObservedAt: linux.ObservedAt, Patches: []model.LivepatchPatch{}, Limitations: ksplice.Limitations}
	collectStandaloneKsplice(ctx, root, out, &standalone)
	out.Livepatch = append(out.Livepatch, standalone)
}

func livepatchRead(root *os.Root, name string) (string, error) {
	f, err := openNoFollow(root, name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("not a regular attribute")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLivepatchAttributeBytes+1))
	if err != nil || len(data) > maxLivepatchAttributeBytes {
		return "", errors.New("attribute read failed or exceeded limit")
	}
	return strings.TrimSpace(string(data)), nil
}

func livepatchEntries(root *os.Root, name string, limit int) ([]os.DirEntry, bool, error) {
	f, err := openNoFollow(root, name)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	entries, err := f.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	limited := len(entries) > limit
	if limited {
		entries = entries[:limit]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, limited, nil
}

func livepatchProblem(out *model.Context, status *model.LivepatchStatus, name, message string, err error) {
	status.Status = "partial"
	kind := "incomplete"
	if os.IsPermission(err) {
		kind = "permission_denied"
		if len(status.Patches) == 0 {
			status.Status = "permission_denied"
		}
	}
	issue(out, kind, name, message)
}

func collectPatchDirectory(ctx context.Context, root *os.Root, out *model.Context, status *model.LivepatchStatus, legacy bool) {
	entries, limited, err := livepatchEntries(root, status.Source, maxLivepatchEntries)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		livepatchProblem(out, status, status.Source, "livepatch source unavailable", err)
		return
	}
	if limited {
		livepatchProblem(out, status, status.Source, "livepatch directory entry limit reached", nil)
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			livepatchProblem(out, status, status.Source, "livepatch observation cancelled", ctx.Err())
			break
		}
		name := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !simpleToken.MatchString(name) {
			livepatchProblem(out, status, status.Source, "unsupported livepatch directory entry", nil)
			continue
		}
		patch := model.LivepatchPatch{ID: name, State: "unknown"}
		base := status.Source + "/" + name
		var patchErr error
		if legacy {
			patch, patchErr = readLegacyStage(root, base+"/stage", name)
		} else {
			patch, patchErr = readLinuxPatch(root, base, name)
		}
		status.Patches = append(status.Patches, patch)
		if patch.State == "unknown" {
			livepatchProblem(out, status, base, "livepatch attributes unavailable, invalid or changed during observation", patchErr)
		}
	}
	if len(status.Patches) > 0 && status.Status == "not_observed" {
		status.Status = "observed"
	}
}

func readLinuxPatch(root *os.Root, base, id string) (model.LivepatchPatch, error) {
	patch := model.LivepatchPatch{ID: id, State: "unknown"}
	enabled, err1 := livepatchRead(root, base+"/enabled")
	transition, err2 := livepatchRead(root, base+"/transition")
	enabledAgain, err3 := livepatchRead(root, base+"/enabled")
	transitionAgain, err4 := livepatchRead(root, base+"/transition")
	for _, err := range []error{err1, err2, err3, err4} {
		if err != nil {
			return patch, err
		}
	}
	if enabled != enabledAgain || transition != transitionAgain || (enabled != "0" && enabled != "1") || (transition != "0" && transition != "1") {
		return patch, errors.New("invalid or changing patch attributes")
	}
	e, t := enabled == "1", transition == "1"
	patch.Enabled, patch.Transition = &e, &t
	switch {
	case t:
		patch.State = "transitioning"
	case e:
		patch.State = "applied"
	default:
		patch.State = "disabled"
	}
	return patch, nil
}

func readLegacyStage(root *os.Root, name, id string) (model.LivepatchPatch, error) {
	patch := model.LivepatchPatch{ID: id, State: "unknown"}
	stage, err := livepatchRead(root, name)
	if err != nil {
		return patch, err
	}
	again, err := livepatchRead(root, name)
	if err != nil {
		return patch, err
	}
	if stage != again {
		return patch, errors.New("changing Ksplice stage")
	}
	// Oracle's raw Ksplice utilities expose exactly these stage strings.
	switch stage {
	case "applied":
		patch.State = "applied"
	case "preparing":
		patch.State = "transitioning"
	case "reversed":
		patch.State = "disabled"
	}
	return patch, nil
}

func collectStandaloneKsplice(ctx context.Context, root *os.Root, out *model.Context, status *model.LivepatchStatus) {
	entries, limited, err := livepatchEntries(root, "sys/module", maxLivepatchModules)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		livepatchProblem(out, status, "sys/module", "standalone Ksplice source unavailable", err)
		return
	}
	if limited {
		livepatchProblem(out, status, "sys/module", "kernel module directory limit reached", nil)
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			livepatchProblem(out, status, "sys/module", "Ksplice observation cancelled", ctx.Err())
			break
		}
		name := entry.Name()
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !simpleToken.MatchString(name) {
			continue
		}
		attribute := "sys/module/" + name + "/ksplice/stage"
		if _, err := livepatchRead(root, attribute); os.IsNotExist(err) {
			continue
		}
		if len(status.Patches) >= maxLivepatchEntries {
			livepatchProblem(out, status, "sys/module", "Ksplice patch entry limit reached", nil)
			break
		}
		patch, patchErr := readLegacyStage(root, attribute, name)
		status.Patches = append(status.Patches, patch)
		if patch.State == "unknown" {
			livepatchProblem(out, status, attribute, "Ksplice stage unavailable or invalid", patchErr)
		}
	}
	if len(status.Patches) > 0 && status.Status == "not_observed" {
		status.Status = "observed"
	}
}
