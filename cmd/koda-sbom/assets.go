package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"slices"
	"time"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"koda.local/security-sbom-linux/internal/assetimport"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
	"koda.local/security-sbom-linux/internal/platforminventory"
)

func loadAssetEvidence(ctx context.Context, paths []string) ([]model.Asset, []model.Issue, error) {
	assets := []model.Asset{}
	issues := []model.Issue{}
	seen := map[string]model.Asset{}
	if len(paths) > 8 {
		return nil, nil, errors.New("at most eight asset evidence files are supported")
	}
	for i, path := range paths {
		found, limitations, err := assetimport.Load(ctx, path)
		if err != nil {
			return nil, nil, fmt.Errorf("asset evidence input %d: %w", i+1, err)
		}
		issues = append(issues, limitations...)
		for _, a := range found {
			if previous, ok := seen[a.ID]; ok {
				if !reflect.DeepEqual(previous, a) {
					return nil, nil, errors.New("asset evidence has conflicting observation identifiers")
				}
				continue
			}
			if len(assets) >= 8192 {
				return nil, nil, errors.New("combined asset evidence exceeds 8192 observations")
			}
			seen[a.ID] = a
			assets = append(assets, a)
		}
	}
	return assets, issues, nil
}

func writeAssets(dir string, assets []model.Asset) error {
	return collect.WriteJSON(dir, "assets.json", struct {
		Schema string        `json:"schema"`
		Assets []model.Asset `json:"assets"`
	}{Schema: "koda-asset-observations-v1", Assets: assets})
}

func appendHardwareSettings(snapshot *model.Context, assets []model.Asset) {
	for _, a := range assets {
		if a.Source != "sys/firmware/efi" || a.Properties["observationScope"] == "container-visible" {
			continue
		}
		for _, key := range []string{"secureBoot", "setupMode"} {
			if value := a.Properties[key]; value == "true" || value == "false" {
				snapshot.Settings = append(snapshot.Settings, model.Setting{Product: "UEFI", Name: key, Value: value, Path: a.Source, State: "observed"})
			}
		}
	}
}

func importAssetEvidence(args []string) int {
	return exportInventory(args, false)
}

func exportInventory(args []string, native bool) int {
	command := "asset-import"
	if native {
		command = "platform-inventory"
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	var inputs stringsFlag
	flags.Var(&inputs, "asset-evidence", "local report path (repeatable)")
	output := flags.String("output-dir", "", "parent directory for new results")
	format := flags.String("format", "both", "both, cyclonedx, spdx")
	cyclonedx17 := flags.Bool("cyclonedx-17", false, cyclonedx17Help)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum import time")
	if flags.Parse(args) != nil || flags.NArg() != 0 || (!native && len(inputs) == 0) || *output == "" ||
		!slices.Contains([]string{"both", "cyclonedx", "spdx"}, *format) || *timeout < 0 {
		return 2
	}
	if !validCycloneDXSelection(*format, *cyclonedx17) {
		return 2
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(parent, *timeout)
	defer cancel()
	if err := exportAssetEvidence(ctx, inputs, *output, *format, native, *cyclonedx17); err != nil {
		if errors.Is(err, errPartialAssetImport) {
			return 3
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

var errPartialAssetImport = errors.New("asset import incomplete")

func exportAssetEvidence(ctx context.Context, inputs []string, output, format string, native, cyclonedx17 bool) error {
	start := time.Now().UTC()
	assets, issues, err := loadAssetEvidence(ctx, inputs)
	if err != nil {
		return err
	}
	label := "external asset evidence"
	if native {
		observed, limitations, err := platforminventory.Collect(ctx)
		if err != nil {
			return err
		}
		assets, issues = append(assets, observed...), append(issues, limitations...)
		label = "native platform evidence"
	}
	if len(assets) == 0 {
		issues = append(issues, model.Issue{Collector: "asset-import", Code: "no_asset_evidence", Status: "incomplete", Message: "no components observed"})
	}
	out, err := localfs.ResolveLocal(output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(out, "koda-sbom-assets-"+start.Format("20060102T150405Z")+"-")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(dir)
		}
	}()
	// These are observations read from files. The source path label identifies
	// their provenance while using the existing filesystem coverage vocabulary.
	origin := sourceInfo{Type: "filesystem", Path: label}
	status := collectionStatus(issues)
	coverage := collect.NewCollectionCoverage(status, origin.Type, len(assets), 0, 0, issues)
	inventory := &sbom.SBOM{Artifacts: sbom.Artifacts{Packages: pkg.NewCollection()},
		Source:     source.Description{Name: "local-filesystem", Metadata: source.DirectoryMetadata{Path: "."}},
		Descriptor: sbom.Descriptor{Name: "koda-sbom", Version: version}}
	if err := collect.WriteSBOMsWithAssets(ctx, dir, format, inventory, status == "partial", &coverage, assets, cyclonedx17); err != nil {
		return err
	}
	if err := writeAssets(dir, assets); err != nil {
		return err
	}
	report := summary{Schema: "koda-sbom-collection-v1", Status: status, Source: origin,
		Tool: toolInfo{version, revision, builtAt, collect.SyftVersion}, StartedAt: start.Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339), AssetCount: len(assets), Issues: issues,
		Limitations: []string{"Imported reports are observations and may be incomplete or stale."}}
	if err := collect.WriteJSON(dir, "collection.json", report); err != nil {
		return err
	}
	if err := collect.Checksums(dir); err != nil {
		return err
	}
	complete = true
	fmt.Println(dir)
	if status == "partial" {
		return errPartialAssetImport
	}
	return nil
}
