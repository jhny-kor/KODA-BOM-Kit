// koda-sbom collects local inventory and correlates it with supplied offline evidence.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/aixevidence"
	"koda.local/security-sbom-linux/internal/certs"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/hardware"
	"koda.local/security-sbom-linux/internal/hostcontext"
	"koda.local/security-sbom-linux/internal/imagearchive"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
	"koda.local/security-sbom-linux/internal/products"
	"koda.local/security-sbom-linux/internal/reconcile"
	"koda.local/security-sbom-linux/internal/staticjs"
)

var version = "0.1.6-dev"
var revision = "uncommitted"
var builtAt = "unknown"

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type sourceInfo struct {
	Type string `json:"type"`
	Path string `json:"path"`
}
type toolInfo struct {
	Version     string `json:"version"`
	Revision    string `json:"revision"`
	BuiltAt     string `json:"builtAt"`
	SyftVersion string `json:"syftVersion"`
}
type collectorResult struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	PackageCount int    `json:"packageCount"`
}
type summary struct {
	Schema                             string                   `json:"schema"`
	Status                             string                   `json:"status"`
	Source                             sourceInfo               `json:"source"`
	Tool                               toolInfo                 `json:"tool"`
	StartedAt                          string                   `json:"startedAt"`
	FinishedAt                         string                   `json:"finishedAt"`
	PackageCount                       int                      `json:"packageCount"`
	AssetCount                         int                      `json:"assetCount,omitempty"`
	Host                               *model.HostIdentity      `json:"host,omitempty"`
	Integrity                          *collect.IntegrityResult `json:"integrity,omitempty"`
	PackageOrigin                      *collect.OriginResult    `json:"packageOrigin,omitempty"`
	ImageIdentity                      *imagearchive.Identity   `json:"imageIdentity,omitempty"`
	PackageTypes                       map[string]int           `json:"packageTypes"`
	Distribution                       any                      `json:"distribution,omitempty"`
	Products                           []model.Product          `json:"products"`
	Catalogers                         []string                 `json:"catalogers"`
	Collectors                         []collectorResult        `json:"collectorResults"`
	ExcludedPaths                      []string                 `json:"excludedPaths"`
	ExcludedDirectories                []string                 `json:"excludedDirectories,omitempty"`
	Issues                             []model.Issue            `json:"issues"`
	Limitations                        []string                 `json:"limitations"`
	ElapsedSeconds                     float64                  `json:"elapsedSeconds"`
	PhaseSeconds                       map[string]float64       `json:"phaseSeconds,omitempty"`
	Limits                             scanLimits               `json:"limits"`
	FilesystemFileCount                int64                    `json:"filesystemFileCount"`
	AIXEvidence                        *aixevidence.Inventory   `json:"aixEvidence,omitempty"`
	Targets                            []targetSummary          `json:"targets,omitempty"`
	JavaScriptFingerprintCatalogSHA256 string                   `json:"javascriptFingerprintCatalogSha256,omitempty"`
	JavaScriptFingerprints             []staticjs.Fingerprint   `json:"javascriptFingerprints,omitempty"`
	Containers                         []containerSummary       `json:"containers,omitempty"`
}

func main() { os.Exit(run(os.Args[1:])) }

// validAssetTag accepts an empty tag (unset) or a short single-line label.
func validAssetTag(tag string) bool {
	if tag == "" {
		return true
	}
	if !utf8.ValidString(tag) || utf8.RuneCountInString(tag) > 128 || strings.TrimSpace(tag) != tag {
		return false
	}
	for _, r := range tag {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
func usage() {
	fmt.Fprintln(os.Stderr, "koda-sbom: offline standalone inventory collector\n  koda-sbom doctor\n  koda-sbom version\n  koda-sbom scan [--target DIRECTORY | --image-archive image.tar] --output-dir DIR\n    [--format both|cyclonedx|spdx] [--cyclonedx-17] [--timeout 30m|0] [--max-files 1000000|0]\n    [--exclude PATH_OR_GLOB] [--exclude-dir DIRECTORY] [--no-context]\n    [--livepatch-evidence FILE] (repeatable, live host only) [--asset-tag LABEL] [--no-containers]\n  koda-sbom livepatch-evidence --provider canonical-livepatch|ksplice|uptrack\n    --input FILE --output FILE [--effective-kernel-file FILE]\nZero timeout/max-files removes that scan limit; Ctrl+C still interrupts.\nExit codes: 0 complete, 3 partial, 2 failed.")
	fmt.Fprintln(os.Stderr, "  koda-sbom aix-import --evidence DIR --output-dir DIR [--format both|cyclonedx|spdx] [--cyclonedx-17] [--timeout 30m|0]")
	fmt.Fprintln(os.Stderr, "  koda-sbom reconcile --artifact FILE.war|FILE.ear --supplier-sbom FILE.json --output-dir DIR [--format both|cyclonedx|spdx] [--cyclonedx-17] [--timeout 30m|0]")
	fmt.Fprintln(os.Stderr, "  koda-sbom scan --target DIRECTORY --target DIRECTORY --output-dir DIR [--exclude-dir ABSOLUTE_DIRECTORY]...")
	fmt.Fprintln(os.Stderr, "  koda-sbom scan --output-dir DIR [--asset-evidence FILE]...\n  koda-sbom asset-import --asset-evidence FILE [--asset-evidence FILE]... --output-dir DIR\n  koda-sbom assess --sbom FILE --advisories FILE [--context FILE] [--kev FILE] --output FILE")
	fmt.Fprintln(os.Stderr, "  koda-sbom platform-inventory --output-dir DIR (macOS or Windows)")
}
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version", "--version":
		json.NewEncoder(os.Stdout).Encode(toolInfo{version, revision, builtAt, collect.SyftVersion})
		return 0
	case "doctor":
		return doctor()
	case "livepatch-evidence":
		return captureLivepatchEvidence(args[1:])
	case "aix-import":
		return importAIXEvidence(args[1:])
	case "asset-import":
		return importAssetEvidence(args[1:])
	case "platform-inventory":
		return exportInventory(args[1:], true)
	case "assess":
		return assessEvidence(args[1:])
	case "validate-scan-options":
		return validateScanOptions(args[1:])
	case "reconcile":
		return reconcileDeployment(args[1:])
	case "help", "--help", "-h":
		usage()
		return 0
	case "scan":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runScan(ctx, args[1:], nil)
	default:
		usage()
		return 2
	}
}

const cyclonedx17Help = "also write CycloneDX 1.7 JSON alongside 1.6"

func validCycloneDXSelection(format string, cyclonedx17 bool) bool {
	if cyclonedx17 && format == "spdx" {
		fmt.Fprintln(os.Stderr, "--cyclonedx-17 requires --format both or cyclonedx")
		return false
	}
	return true
}

type scanCompletion func(dir string, report summary, coverage collect.CollectionCoverage, observed []reconcile.Component) error

func runScan(parent context.Context, args []string, onComplete scanCompletion) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	var target, image, output, format, assetTag string
	var timeout time.Duration
	var maxFiles int64
	var targets, excludes, excludedDirs stringsFlag
	var livepatchEvidence, assetEvidence stringsFlag
	var noContext, cyclonedx17, noContainers bool
	flags.Var(&targets, "target", "local directory (repeatable); default /")
	flags.StringVar(&image, "image-archive", "", "local single-image Docker/OCI tar")
	flags.StringVar(&output, "output-dir", "", "parent directory for new results")
	flags.StringVar(&format, "format", "both", "both, cyclonedx, spdx")
	flags.BoolVar(&cyclonedx17, "cyclonedx-17", false, cyclonedx17Help)
	flags.DurationVar(&timeout, "timeout", 30*time.Minute, "maximum total collection time; 0 disables the time limit")
	flags.Int64Var(&maxFiles, "max-files", localfs.DefaultMaxFiles, "maximum eligible filesystem files; 0 disables the file-count limit")
	flags.Var(&excludes, "exclude", "root-relative path/glob to exclude (repeatable)")
	flags.Var(&excludedDirs, "exclude-dir", "literal directory below --target, absolute or target-relative (repeatable)")
	flags.BoolVar(&noContext, "no-context", false, "skip runtime/configuration context")
	flags.BoolVar(&noContainers, "no-containers", false, "skip per-container SBOMs of running containers (live host only)")
	flags.Var(&livepatchEvidence, "livepatch-evidence", "local sanitized client status evidence (repeatable, live host only)")
	flags.Var(&assetEvidence, "asset-evidence", "local supplementary hardware/software evidence (repeatable)")
	flags.StringVar(&assetTag, "asset-tag", "", "operator label stored in the SBOM to identify this host (max 128 characters)")
	if e := flags.Parse(args); e != nil {
		return 2
	}
	if !validAssetTag(assetTag) {
		fmt.Fprintln(os.Stderr, "--asset-tag must be 1-128 printable characters without leading or trailing spaces")
		return 2
	}
	if len(targets) == 1 {
		target = targets[0]
	}
	multiple := len(targets) > 1
	if flags.NArg() != 0 || output == "" || (len(targets) > 0 && image != "") || (len(targets) == 1 && strings.TrimSpace(target) == "") ||
		(format != "both" && format != "cyclonedx" && format != "spdx") || timeout < 0 || maxFiles < 0 {
		usage()
		return 2
	}
	if !validCycloneDXSelection(format, cyclonedx17) {
		return 2
	}
	configuredExcludePatternCount := len(excludes)
	if len(livepatchEvidence) > 3 || (len(livepatchEvidence) > 0 && (multiple || noContext || image != "" || (target != "" && filepath.Clean(target) != "/"))) {
		fmt.Fprintln(os.Stderr, "livepatch evidence requires the live host / with context enabled; at most three reports")
		return 2
	}
	if !multiple && len(excludedDirs) > 0 && (target == "" || image != "" || filepath.Clean(target) == "/") {
		fmt.Fprintln(os.Stderr, "--exclude-dir requires an explicit directory target below /")
		return 2
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		fmt.Fprintln(os.Stderr, "scan requires Linux x86_64 or ARM64; use platform-inventory on macOS or Windows")
		return 2
	}
	collect.DisableHTTP()
	runtime.GOMAXPROCS(2)
	ctx, cancel := scanContext(parent, timeout)
	defer cancel()
	assets, assetIssues, err := loadAssetEvidence(ctx, assetEvidence)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	assetScope := len(assetEvidence) > 0
	var scopes []scanTarget
	if multiple {
		var err error
		scopes, err = validateScanTargets(ctx, targets, excludes, excludedDirs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "target validation failed:", err)
			return 2
		}
		noContext = true
	}
	var importedLivepatch []model.LivepatchStatus
	providers := map[string]bool{}
	for _, filename := range livepatchEvidence {
		status, err := hostcontext.LoadLivepatchEvidence(ctx, filename)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid or unreadable livepatch evidence")
			return 2
		}
		if providers[status.Provider] {
			fmt.Fprintln(os.Stderr, "duplicate livepatch provider evidence")
			return 2
		}
		providers[status.Provider] = true
		importedLivepatch = append(importedLivepatch, status)
	}
	if !multiple && target == "" && image == "" {
		target = "/"
	}
	host := model.HostIdentity{AssetTag: assetTag}
	if target != "" {
		validation, e := localfs.BuildWithOptions(ctx, target, []string{"/**"}, localfs.Options{ExcludeDirs: excludedDirs})
		if e != nil {
			fmt.Fprintln(os.Stderr, "target validation failed:", e)
			return 2
		}
		if len(excludedDirs) > 0 && validation.Root == "/" {
			fmt.Fprintln(os.Stderr, "--exclude-dir requires an explicit directory target below /")
			return 2
		}
		target = validation.Root
	}
	var hostIssues []model.Issue
	if target == "/" && image == "" {
		// Only the live root is this machine; a directory may be a foreign mount.
		host, hostIssues = hardware.HostIdentity(ctx, "/")
		host.AssetTag = assetTag
	}
	out, e := localfs.ResolveLocal(output)
	if e != nil {
		return 2
	}
	if targetMatchesOutput(scopes, out) {
		fmt.Fprintln(os.Stderr, "output parent must not equal scan target")
		return 2
	}
	if e = os.MkdirAll(out, 0700); e != nil {
		fmt.Fprintln(os.Stderr, "cannot create result parent")
		return 2
	}
	out, e = localfs.ResolveLocal(out)
	if e != nil {
		return 2
	}
	if targetMatchesOutput(scopes, out) {
		fmt.Fprintln(os.Stderr, "output parent must not equal scan target")
		return 2
	}
	if target != "" {
		abs, _ := localfs.ResolveLocal(target)
		if abs == out {
			fmt.Fprintln(os.Stderr, "output parent must not equal scan target")
			return 2
		}
	}
	prefix := "koda-sbom-" + time.Now().UTC().Format("20060102T150405Z") + "-"
	if multiple {
		prefix = "." + prefix
	}
	dir, e := os.MkdirTemp(out, prefix)
	if e != nil {
		return 2
	}
	if multiple {
		defer os.RemoveAll(dir)
	}
	start := time.Now()
	catalogers := append(append([]string{}, collect.Catalogers...), "koda-product-metadata", staticjs.Collector)
	report := summary{Schema: "koda-sbom-collection-v1", Status: "failed", Tool: toolInfo{version, revision, builtAt, collect.SyftVersion}, StartedAt: start.UTC().Format(time.RFC3339), PackageTypes: map[string]int{}, Products: []model.Product{}, Catalogers: catalogers, Issues: assetIssues, Limitations: []string{"Scan produces observations for later advisory correlation", "Missing metadata and unreadable paths cannot establish absence", "Installed and observed context do not prove active exploitability", "Hardware coverage depends on local kernel attributes and supplied evidence; imported assets are reported observations", "JEUS product/patch identification is unverified; bundled JAR discovery is separate", "Patch observations are not proof that a patch is applied", "Static JavaScript identification covers selected libraries and bounded archive inspection"}}
	if host != (model.HostIdentity{}) {
		report.Host = &host
	}
	report.Issues = append(report.Issues, hostIssues...)
	report.Limits = scanLimits{MaxFiles: maxFiles, Timeout: timeout.String(), TimeoutSeconds: timeout.Seconds()}
	report.JavaScriptFingerprintCatalogSHA256 = staticjs.FingerprintCatalogSHA256()
	report.PhaseSeconds = map[string]float64{}
	phaseStart := start
	finishPhase := func(phase string) {
		now := time.Now()
		report.PhaseSeconds[phase] += now.Sub(phaseStart).Seconds()
		phaseStart = now
	}
	contextData := model.Context{Mode: "disabled", Status: "disabled", Settings: []model.Setting{}, Issues: []model.Issue{}}
	var scratch string
	finish := func(code int) int {
		if multiple && scratch != "" {
			if err := os.RemoveAll(scratch); err != nil {
				fmt.Fprintln(os.Stderr, "cannot clean collection staging directory")
				return 2
			}
		}
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		report.ElapsedSeconds = time.Since(start).Seconds()
		if e := collect.WriteJSON(dir, "context.json", contextData); e != nil {
			fmt.Fprintln(os.Stderr, "context output failed")
			return 2
		}
		if assetScope {
			if e := writeAssets(dir, assets); e != nil {
				fmt.Fprintln(os.Stderr, "asset evidence output failed")
				return 2
			}
		}
		if e := collect.WriteJSON(dir, "collection.json", report); e != nil {
			fmt.Fprintln(os.Stderr, "collection output failed")
			return 2
		}
		if e := collect.Checksums(dir); e != nil {
			fmt.Fprintln(os.Stderr, "checksums failed")
			return 2
		}
		if multiple {
			if code != 2 && ctx.Err() != nil {
				fmt.Fprintln(os.Stderr, failureIssue("collection", ctx.Err(), ctx.Err()).Message)
				return 2
			}
			result := filepath.Join(out, strings.TrimPrefix(filepath.Base(dir), "."))
			if _, err := os.Lstat(result); !os.IsNotExist(err) || os.Rename(dir, result) != nil {
				fmt.Fprintln(os.Stderr, "cannot publish collection results")
				return 2
			}
			dir = result
		}
		if onComplete == nil {
			fmt.Println(dir)
		}
		return code
	}
	var currentTarget string
	fail := func(stage string, err error) int {
		issue := failureIssue(stage, err, ctx.Err())
		issue.Target = currentTarget
		report.Issues = append(report.Issues, issue)
		if onComplete == nil {
			fmt.Fprintf(os.Stderr, "%s failed (%s): %s; see collection.json (no success SBOM is claimed)\n", stage, issue.Code, issue.Message)
		} else {
			fmt.Fprintf(os.Stderr, "%s failed (%s): %s\n", stage, issue.Code, issue.Message)
		}
		return finish(2)
	}
	root := target
	work := ""
	if image != "" {
		report.Source = sourceInfo{Type: "image-archive", Path: filepath.Base(image)}
		work, e = os.MkdirTemp(dir, ".work-")
		if e != nil {
			return fail("image", e)
		}
		defer os.RemoveAll(work)
		var identity imagearchive.Identity
		root, identity, e = imagearchive.ExtractWithIdentity(ctx, image, work)
		finishPhase("imageExtraction")
		if e != nil {
			return fail("image", e)
		}
		report.ImageIdentity = &identity
	} else {
		report.Source = sourceInfo{Type: "filesystem", Path: "."}
	}
	if !multiple {
		scopes = []scanTarget{{root: root, excludedDirs: excludedDirs}}
	} else {
		for _, scope := range scopes {
			report.Targets = append(report.Targets, targetSummary{ID: scope.id, Status: "not_collected", ExcludedPaths: []string{}, ExcludedDirectories: []string{}})
		}
	}
	tempRoot := os.TempDir()
	if resolved, err := localfs.ResolveLocal(tempRoot); err == nil {
		tempRoot = resolved
	}
	scratch, e = os.MkdirTemp(dir, ".scratch-")
	if e != nil {
		return fail("temporary-storage", e)
	}
	defer os.RemoveAll(scratch)
	for _, key := range []string{"TMPDIR", "TMP", "TEMP", "SYFT_TEMP_DIR"} {
		if previous, set := os.LookupEnv(key); set {
			defer os.Setenv(key, previous)
		} else {
			defer os.Unsetenv(key)
		}
		os.Setenv(key, scratch)
	}
	var inventory *sbom.SBOM
	var observed []reconcile.Component
	var combined collect.DirectoryInventory
	var catalogIssues, javascriptIssues, tempExcluded bool
	var integrity collect.IntegrityResult
	var origins collect.OriginResult
	deployedIssues := map[string]bool{}
	for i, scope := range scopes {
		currentTarget = scope.id
		progress := targetSummary{ID: scope.id}
		phaseStart = time.Now()
		patterns := append([]string{}, excludes...)
		patterns = excludeScanPath(patterns, scope.root, out)
		beforeTemp := len(patterns)
		patterns = excludeScanPath(patterns, scope.root, tempRoot)
		if len(patterns) > beforeTemp && !tempExcluded {
			report.Limitations = append(report.Limitations, "System temporary directory is excluded")
			tempExcluded = true
		}
		plan, err := localfs.BuildWithOptions(ctx, scope.root, patterns, localfs.Options{
			MaxFiles: maxFiles, FilesAlreadyCounted: report.FilesystemFileCount, ExcludeDirs: scope.excludedDirs,
		})
		finishPhase("filesystemPreflight")
		progress.FilesystemFileCount = int64(len(plan.Paths))
		progress.ExcludedPaths = append([]string{}, plan.Excluded...)
		sort.Strings(progress.ExcludedPaths)
		progress.ExcludedDirectories = append([]string{}, plan.ExcludedDirs...)
		report.FilesystemFileCount += progress.FilesystemFileCount
		report.ExcludedPaths = appendScopedPaths(report.ExcludedPaths, scope.id, plan.Excluded)
		report.ExcludedDirectories = appendScopedPaths(report.ExcludedDirectories, scope.id, plan.ExcludedDirs)
		issues := plan.Issues
		record := func(status string) {
			report.Issues = append(report.Issues, markTargetIssues(issues, scope.id)...)
			if multiple {
				progress.Status = status
				report.Targets[i] = progress
			}
		}
		if err != nil {
			record("failed")
			return fail("filesystem", err)
		}
		productList, productIssues := products.Collect(ctx, plan.Root, plan.Paths)
		finishPhase("productEvidence")
		issues = append(issues, productIssues...)
		javascript, jsIssues := staticjs.Collect(ctx, plan.Root, plan.Paths)
		finishPhase("staticJavaScript")
		issues = append(issues, jsIssues...)
		for _, component := range javascript {
			for _, match := range component.Fingerprints {
				if scope.id != "" {
					match.Path = scope.id + "/" + match.Path
				}
				report.JavaScriptFingerprints = append(report.JavaScriptFingerprints, match)
			}
		}
		javascriptIssues = javascriptIssues || len(jsIssues) > 0
		certificates, certificateIssues := certs.Collect(ctx, plan.Root, plan.Paths)
		finishPhase("certificates")
		issues = append(issues, certificateIssues...)
		for _, a := range certificates {
			if scope.id != "" && a.Source != "x509" {
				a.Source = scope.id + "/" + a.Source
				a.Properties["path"] = a.Source
			}
			assets = append(assets, a)
		}
		assetScope = assetScope || len(certificates) > 0
		if err := ctx.Err(); err != nil {
			record("failed")
			return fail("static-javascript", err)
		}
		if !noContext {
			live := image == "" && plan.Root == "/"
			contextData = collectScanContext(ctx, plan, live, importedLivepatch)
			issues = append(issues, contextData.Issues...)
			finishPhase("hostContext")
			if live {
				assetScope = true
				localAssets, hardwareIssues := hardware.Collect(ctx, plan.Root)
				assets = append(assets, localAssets...)
				appendHardwareSettings(&contextData, localAssets)
				issues = append(issues, hardwareIssues...)
				finishPhase("hardwareEvidence")
			}
		}
		collected, auditIssue, err := catalogScanTarget(ctx, plan)
		finishPhase("packageCatalog")
		if err != nil {
			record("failed")
			return fail("cataloging", err)
		}
		if auditIssue != nil {
			catalogIssues = true
			issues = append(issues, *auditIssue)
		}
		if !multiple {
			// Before Scrub: verification needs the package file lists.
			integrity = collect.VerifyPackageFiles(ctx, collected, plan, collect.DefaultIntegrityBudget)
			finishPhase("packageIntegrity")
			origins = collect.PackageOrigins(ctx, collected, plan)
			if integrity.Status == "partial" {
				issues = append(issues, model.Issue{Collector: "package-integrity", Status: "incomplete", Message: "package file verification stopped at its time or size budget"})
			}
		}
		for _, issue := range collect.DeployedCollectionIssues(collected, plan.Root) {
			issues = append(issues, issue)
			deployedIssues[issue.Collector] = true
		}
		collect.AddProducts(collected, productList)
		collect.AddStaticJavaScript(collected, javascript)
		for _, product := range productList {
			report.Products = append(report.Products, collect.ScopeProduct(product, scope.id))
		}
		if onComplete != nil {
			// Compare before scrub can remove private PURL qualifiers.
			for _, p := range collected.Artifacts.Packages.Sorted() {
				observed = append(observed, reconcile.Component{Name: p.Name, Version: p.Version, PURL: p.PURL})
			}
		}
		var identities map[artifact.ID]string
		if multiple {
			identities = collect.MergeableDirectoryPackages(ctx, collected, plan)
		}
		collect.Scrub(collected)
		if integrity.Status != "not_applicable" && integrity.Status != "" {
			integrity.ResolvePURLs(collected)
			report.Integrity = &integrity
		}
		if origins.Status == "completed" {
			origins.ResolvePURLs(collected)
			report.PackageOrigin = &origins
		}
		progress.PackageCount = collected.Artifacts.Packages.PackageCount()
		progress.Distribution = collected.Artifacts.LinuxDistribution
		if progress.PackageCount == 0 {
			issues = append(issues, model.Issue{Collector: "inventory", Status: "incomplete", Message: "no identifiable installed package metadata observed; this is not proof of absence"})
		}
		record(collectionStatus(issues))
		if multiple {
			combined.Add(scope.id, collected, identities)
		} else {
			inventory = collected
		}
	}
	currentTarget = ""
	if multiple {
		inventory = combined.BOM()
	}
	if ctx.Err() != nil {
		return fail("cataloging", ctx.Err())
	}
	report.PackageCount = inventory.Artifacts.Packages.PackageCount()
	report.AssetCount = len(assets)
	collect.LinkRuntimePackages(&contextData, inventory)
	var services collect.ComponentProperties
	if !multiple {
		services = collect.LinkServices(&contextData, inventory, target)
	}
	collect.UnidentifiedExecutables(&contextData, inventory, report.Products)
	report.Distribution = inventory.Artifacts.LinuxDistribution
	for _, p := range inventory.Artifacts.Packages.Sorted() {
		report.PackageTypes[string(p.Type)]++
	}
	counts := map[string]int{}
	for _, p := range inventory.Artifacts.Packages.Sorted() {
		counts[p.FoundBy]++
	}
	for _, name := range catalogers {
		state := "not_observed"
		if counts[name] > 0 {
			state = "completed"
		}
		if (name == staticjs.Collector && javascriptIssues) || (name != staticjs.Collector && catalogIssues) || deployedIssues[name] {
			state = "partial"
		}
		report.Collectors = append(report.Collectors, collectorResult{Name: name, Status: state, PackageCount: counts[name]})
	}
	report.Status = collectionStatus(report.Issues)
	phaseStart = time.Now()
	coverage := collect.NewCollectionCoverage(report.Status, report.Source.Type, report.PackageCount+report.AssetCount, len(report.ExcludedDirectories), configuredExcludePatternCount, report.Issues)
	coverage.IncludeAllOccurrences = multiple
	e = collect.WriteSBOMsWithAssets(ctx, dir, format, inventory, report.Status == "partial", &coverage, assets, cyclonedx17)
	if e == nil {
		e = collect.AnnotateSBOMs(dir, collect.HostProperties(host), collect.MergeProperties(collect.ListeningByPURL(contextData).Properties(), integrity.Properties(), origins.Properties(), services))
	}
	if e != nil {
		finishPhase("sbomOutput")
		report.Status = "failed"
		if multiple || cyclonedx17 {
			for _, name := range []string{"inventory.syft.json", "sbom.cdx.json", "sbom.spdx.json", collect.CycloneDX17Filename} {
				if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
					fmt.Fprintln(os.Stderr, "cannot remove incomplete SBOM from staging directory")
					return 2
				}
			}
		}
		return fail("encoding", e)
	}
	finishPhase("sbomOutput")
	// Runs before scratch removal: Syft's temporary files live there.
	if !multiple && image == "" && target == "/" && !noContext && !noContainers {
		var discoveryIssues []model.Issue
		report.Containers, discoveryIssues = scanContainers(ctx, containerOptions{dir: dir, format: format, cyclonedx17: cyclonedx17, maxFiles: maxFiles, host: host})
		report.Issues = append(report.Issues, discoveryIssues...)
		for _, c := range report.Containers {
			if c.Status != "completed" {
				report.Status = "partial"
			}
		}
		if len(discoveryIssues) > 0 {
			report.Status = "partial"
		}
		finishPhase("containers")
	}
	sort.Strings(report.ExcludedPaths)
	os.RemoveAll(scratch)
	if work != "" {
		os.RemoveAll(work)
	}
	if onComplete != nil {
		if err := onComplete(dir, report, coverage, observed); err != nil {
			report.Status = "failed"
			return fail("reconciliation", err)
		}
	}
	if report.Status == "partial" {
		return finish(3)
	}
	return finish(0)
}
