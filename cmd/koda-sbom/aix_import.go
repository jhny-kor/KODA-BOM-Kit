package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"koda.local/security-sbom-linux/internal/aixevidence"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/localfs"
)

func importAIXEvidence(args []string) int {
	flags := flag.NewFlagSet("aix-import", flag.ContinueOnError)
	evidence := flags.String("evidence", "", "directory from collect-aix-evidence.sh")
	output := flags.String("output-dir", "", "parent directory for new results")
	format := flags.String("format", "both", "both, cyclonedx, spdx")
	cyclonedx17 := flags.Bool("cyclonedx-17", false, cyclonedx17Help)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum import time; 0 disables the time limit")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *evidence == "" || *output == "" ||
		(*format != "both" && *format != "cyclonedx" && *format != "spdx") || *timeout < 0 {
		fmt.Fprintln(os.Stderr, "use aix-import --evidence DIR --output-dir DIR [--format both|cyclonedx|spdx] [--cyclonedx-17] [--timeout 30m|0]")
		return 2
	}
	if !validCycloneDXSelection(*format, *cyclonedx17) {
		return 2
	}
	start := time.Now()
	interrupt, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(interrupt, *timeout)
	defer cancel()

	evidenceDir, err := localfs.ResolveLocal(*evidence)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot resolve local AIX evidence directory")
		return 2
	}
	inventory, err := aixevidence.Load(ctx, evidenceDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot import AIX evidence: invalid, unreadable or cancelled")
		return 2
	}
	bom, err := collect.AIXSBOM(inventory, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid Oracle identity in AIX evidence")
		return 2
	}
	if bom.Artifacts.Packages.PackageCount() == 0 || ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "AIX evidence did not produce an identifiable component")
		return 2
	}
	out, err := localfs.ResolveLocal(*output)
	if err != nil || os.MkdirAll(out, 0700) != nil {
		fmt.Fprintln(os.Stderr, "cannot create result parent")
		return 2
	}
	dir, err := os.MkdirTemp(out, "koda-sbom-aix-"+start.UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create result directory")
		return 2
	}
	saved := false
	defer func() {
		if !saved {
			os.RemoveAll(dir)
		}
	}()

	catalogers := []string{collect.AIXFilesetsCollector, collect.AIXOracleCollector}
	report := summary{
		Schema: "koda-sbom-collection-v1", Status: "completed", Source: sourceInfo{Type: "aix-evidence", Path: "."},
		Tool: toolInfo{version, revision, builtAt, collect.SyftVersion}, StartedAt: start.UTC().Format(time.RFC3339),
		PackageCount: bom.Artifacts.Packages.PackageCount(), PackageTypes: map[string]int{},
		Catalogers: catalogers, Issues: inventory.Issues, AIXEvidence: &inventory,
		Limitations: []string{
			"Imported AIX command output for one capture; no live filesystem scan",
			"Oracle inventory describes only the selected homes; Listener installation does not prove it is running",
			"No vulnerability matching or patch-to-CVE verdict",
		},
		Limits: scanLimits{Timeout: timeout.String(), TimeoutSeconds: timeout.Seconds()},
	}
	counts := map[string]int{}
	for _, component := range bom.Artifacts.Packages.Sorted() {
		counts[component.FoundBy]++
		report.PackageTypes[component.Type.String()]++
	}
	partialCollectors := map[string]bool{}
	for _, issue := range inventory.Issues {
		if issue.Status == "not_observed" || issue.Status == "not_supported" {
			continue
		}
		report.Status = "partial"
		switch issue.Path {
		case "oslevel.txt", "lslpp.txt", "emgr.txt":
			partialCollectors[collect.AIXFilesetsCollector] = true
		default:
			partialCollectors[collect.AIXOracleCollector] = true
		}
	}
	for _, name := range catalogers {
		state := "not_observed"
		if counts[name] > 0 {
			state = "completed"
		}
		if partialCollectors[name] {
			state = "partial"
		}
		report.Collectors = append(report.Collectors, collectorResult{Name: name, Status: state, PackageCount: counts[name]})
	}
	coverage := collect.NewCollectionCoverage(report.Status, report.Source.Type, report.PackageCount, 0, 0, report.Issues)
	if err = collect.WriteSBOMsWithAssets(ctx, dir, *format, bom, true, &coverage, nil, *cyclonedx17); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode AIX SBOM")
		return 2
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	report.ElapsedSeconds = time.Since(start).Seconds()
	if err = collect.WriteJSON(dir, "collection.json", report); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write AIX collection report")
		return 2
	}
	if err = collect.Checksums(dir); err != nil || ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "AIX import did not finish")
		return 2
	}
	saved = true
	fmt.Println(dir)
	if report.Status == "partial" {
		return 3
	}
	return 0
}
