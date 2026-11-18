package main

import (
	"context"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"koda.local/security-sbom-linux/internal/certs"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/containers"
	"koda.local/security-sbom-linux/internal/hostcontext"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
	"koda.local/security-sbom-linux/internal/products"
	"koda.local/security-sbom-linux/internal/staticjs"
)

const containerPropertyPrefix = "koda:container:"

// containerSummary is the entry for one container in the host collection.json.
// Full issues are in the container's own collection.json.
type containerSummary struct {
	containers.Container
	Status              string `json:"status"`
	Output              string `json:"output,omitempty"`
	PackageCount        int    `json:"packageCount"`
	FilesystemFileCount int64  `json:"filesystemFileCount"`
	IssueCount          int    `json:"issueCount"`
	Reason              string `json:"reason,omitempty"`
}

type containerCollection struct {
	Schema              string                   `json:"schema"`
	Status              string                   `json:"status"`
	Container           containers.Container     `json:"container"`
	Host                *model.HostIdentity      `json:"host,omitempty"`
	Tool                toolInfo                 `json:"tool"`
	StartedAt           string                   `json:"startedAt"`
	FinishedAt          string                   `json:"finishedAt"`
	PackageCount        int                      `json:"packageCount"`
	FilesystemFileCount int64                    `json:"filesystemFileCount"`
	ListeningSockets    []executableSockets      `json:"listeningSockets,omitempty"`
	Integrity           *collect.IntegrityResult `json:"integrity,omitempty"`
	Issues              []model.Issue            `json:"issues"`
	Limitations         []string                 `json:"limitations"`
}

// executableSockets lists the sockets one container executable holds; the
// path is inside the container's root filesystem.
type executableSockets struct {
	Executable string         `json:"executable"`
	Sockets    []model.Socket `json:"sockets"`
}

type containerOptions struct {
	dir, format string
	cyclonedx17 bool
	maxFiles    int64
	host        model.HostIdentity
}

// scanContainers writes containers/<name>/ for each running container. A
// container that cannot be collected is reported, never fatal to the host scan.
func scanContainers(ctx context.Context, options containerOptions) ([]containerSummary, []model.Issue) {
	found, issues := containers.Discover(ctx, "/", os.Getpid())
	used := map[string]bool{}
	summaries := []containerSummary{}
	for _, c := range found {
		s := containerSummary{Container: c, Status: "not_collected"}
		switch {
		case ctx.Err() != nil:
			s.Reason = "collection time limit reached before this container"
		case c.RootFS == "":
			s.Reason = "container root filesystem is not visible from the collector's mount namespace"
		default:
			name := c.FileName()
			if used[name] {
				name += "-" + c.ID[:12]
			}
			used[name] = true
			s.Output = path.Join("containers", name)
			scanContainer(ctx, &s, filepath.Join(options.dir, "containers", name), options)
		}
		summaries = append(summaries, s)
	}
	return summaries, issues
}

func containerProperties(c containers.Container) [][2]string {
	var pairs [][2]string
	for _, p := range [][2]string{
		{"name", c.Name}, {"id", c.ID}, {"runtime", c.Runtime}, {"image", c.Image}, {"image-id", c.ImageID},
		{"pod", c.Pod}, {"pod-namespace", c.PodNamespace},
	} {
		if p[1] != "" {
			pairs = append(pairs, [2]string{containerPropertyPrefix + p[0], p[1]})
		}
	}
	return pairs
}

func scanContainer(ctx context.Context, s *containerSummary, out string, options containerOptions) {
	report := containerCollection{
		Schema: "koda-sbom-container-collection-v1", Status: "failed", Container: s.Container,
		Tool: toolInfo{version, revision, builtAt, collect.SyftVersion}, StartedAt: time.Now().UTC().Format(time.RFC3339),
		Issues: []model.Issue{},
		Limitations: []string{
			"Only the container root filesystem is collected; volumes and bind mounts are not included",
			"Listening sockets are linked to a package only when the executable maps to exactly one component",
		},
	}
	if options.host != (model.HostIdentity{}) {
		report.Host = &options.host
	}
	finish := func(failure error) {
		if failure != nil {
			report.Status = "failed"
			report.Issues = append(report.Issues, failureIssue("container", failure, ctx.Err()))
		}
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		s.Status, s.PackageCount, s.FilesystemFileCount, s.IssueCount = report.Status, report.PackageCount, report.FilesystemFileCount, len(report.Issues)
		if err := os.MkdirAll(out, 0700); err != nil {
			s.Status, s.Reason = "failed", "container result directory could not be created"
			return
		}
		if collect.WriteJSON(out, "collection.json", report) != nil || collect.Checksums(out) != nil {
			s.Status, s.Reason = "failed", "container results could not be written"
		}
	}
	plan, err := localfs.BuildWithOptions(ctx, s.RootFS, nil, localfs.Options{MaxFiles: options.maxFiles, RootFilesystem: true})
	report.FilesystemFileCount = int64(len(plan.Paths))
	report.Issues = append(report.Issues, plan.Issues...)
	if err != nil {
		finish(err)
		return
	}
	productList, productIssues := products.Collect(ctx, plan.Root, plan.Paths)
	javascript, javascriptIssues := staticjs.Collect(ctx, plan.Root, plan.Paths)
	certificates, certificateIssues := certs.Collect(ctx, plan.Root, plan.Paths)
	report.Issues = append(append(append(report.Issues, productIssues...), javascriptIssues...), certificateIssues...)
	inventory, auditIssue, err := catalogScanTarget(ctx, plan)
	if err != nil {
		finish(err)
		return
	}
	if auditIssue != nil {
		report.Issues = append(report.Issues, *auditIssue)
	}
	// ponytail: fixed per-container budget; share one budget across containers if fleets get large.
	integrity := collect.VerifyPackageFiles(ctx, inventory, plan, collect.DefaultIntegrityBudget/8)
	report.Issues = append(report.Issues, collect.DeployedCollectionIssues(inventory, plan.Root)...)
	collect.AddProducts(inventory, productList)
	collect.AddStaticJavaScript(inventory, javascript)
	collect.Scrub(inventory)
	if integrity.Status != "not_applicable" {
		integrity.ResolvePURLs(inventory)
		report.Integrity = &integrity
	}
	report.PackageCount = inventory.Artifacts.Packages.PackageCount()
	// Read the container's own network namespace through its processes.
	byExecutable, socketIssues := hostcontext.NamespaceSockets(ctx, s.PIDs)
	report.Issues = append(report.Issues, socketIssues...)
	for _, exe := range slices.Sorted(maps.Keys(byExecutable)) {
		report.ListeningSockets = append(report.ListeningSockets, executableSockets{Executable: exe, Sockets: byExecutable[exe]})
	}
	exposure := collect.ExposureByExecutable(inventory, s.RootFS, byExecutable)
	report.Status = collectionStatus(report.Issues)
	if err := os.MkdirAll(out, 0700); err != nil {
		finish(err)
		return
	}
	coverage := collect.NewCollectionCoverage(report.Status, "container-filesystem", report.PackageCount, 0, 0, report.Issues)
	err = collect.WriteSBOMsWithAssets(ctx, out, options.format, inventory, report.Status == "partial", &coverage, certificates, options.cyclonedx17)
	if err == nil {
		err = collect.AnnotateSBOMs(out, append(collect.HostProperties(options.host), containerProperties(s.Container)...), collect.MergeProperties(exposure.Properties(), integrity.Properties()))
	}
	if err != nil {
		for _, name := range []string{"inventory.syft.json", "sbom.cdx.json", "sbom.spdx.json", collect.CycloneDX17Filename} {
			os.Remove(filepath.Join(out, name)) // never leave a partial SBOM that looks complete
		}
	}
	finish(err)
}
