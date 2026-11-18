package collect

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/model"
	_ "modernc.org/sqlite"
)

const SyftVersion = "v1.57.1"

// Only installed metadata and known binary parsers; no SBOM or lockfile import.
var syftCatalogers = []string{
	"rpm-db-cataloger", "dpkg-db-cataloger", "apk-db-cataloger", "python-installed-package-cataloger",
	npmPackageCataloger, "php-composer-installed-cataloger", "php-pear-serialized-cataloger",
	"php-interpreter-cataloger", javaArchiveCataloger, "java-jvm-cataloger", "binary-classifier-cataloger",
	"elf-binary-package-cataloger", GoBinaryCollector,
}

var Catalogers = append(append([]string{}, syftCatalogers...), kernelCollector, RustBinaryCollector, DotnetCollector, RubyCollector, pythonZipappCollector)

type deniedTransport struct{}

func (deniedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("outbound HTTP disabled by koda-sbom")
}
func DisableHTTP() {
	http.DefaultTransport = deniedTransport{}
	http.DefaultClient = &http.Client{Transport: deniedTransport{}}
}
func Config(version string) *syft.CreateSBOMConfig {
	c := syft.DefaultCreateSBOMConfig().WithTool("koda-sbom", version).WithParallelism(2).WithoutFiles()
	// Make WithoutFiles explicit to the task selector too. Otherwise Syft
	// auto-adds the file tag and emits a warning even for complete scans.
	c.CatalogerSelection = cataloging.NewSelectionRequest().WithDefaults(syftCatalogers...).WithRemovals("file")
	// Use our bounded ELF reader for Rust audit sections. The built-in Rust
	// parser inflates the section without a size limit.
	c.WithCatalogers(
		pkgcataloging.NewAlwaysEnabledCatalogerReference(newKernelCataloger()),
		pkgcataloging.NewAlwaysEnabledCatalogerReference(newRustBinaryCataloger()),
		pkgcataloging.NewAlwaysEnabledCatalogerReference(newDotnetCataloger()),
		pkgcataloging.NewAlwaysEnabledCatalogerReference(newRubyCataloger()),
	)
	// Retain coordinate errors even if another cataloger recognizes the file.
	c.Unknowns.RemoveWhenPackagesDefined = false
	c.DataGeneration.GenerateCPEs = false
	c.Packages.JavaArchive.UseNetwork = false
	c.Packages.JavaArchive.UseMavenLocalRepository = false
	c.Packages.JavaArchive.ResolveTransitiveDependencies = false
	c.Packages.Python.SearchRemoteLicenses = false
	c.Packages.Python.GuessUnpinnedRequirements = false
	c.Packages.JavaScript.SearchRemoteLicenses = false
	c.Packages.JavaScript.IncludeDevDependencies = true
	c.Packages.Golang.UsePackagesLib = false
	c.Packages.Golang.SearchRemoteLicenses = false
	c.Packages.Golang.SearchLocalModCacheLicenses = false
	c.Packages.Golang.SearchLocalVendorLicenses = false
	c.Packages.Golang.MainModuleVersion.FromLDFlags = false
	c.Packages.Golang.MainModuleVersion.FromContents = false
	c.Packages.Golang.MainModuleVersion.FromBuildSettings = false
	return c
}
func Scan(ctx context.Context, plan localfs.Plan, version string) (*sbom.SBOM, error) {
	DisableHTTP()
	patterns := make([]string, 0, len(plan.Excluded))
	for _, p := range plan.Excluded {
		patterns = append(patterns, "./"+strings.TrimPrefix(strings.TrimPrefix(p, "/"), "./"))
	}
	src, e := directorysource.New(directorysource.Config{Path: plan.Root, Exclude: source.ExcludeConfig{Paths: patterns}, Alias: source.Alias{Name: "local-filesystem"}})
	if e != nil {
		return nil, e
	}
	defer src.Close()
	s, e := syft.CreateSBOM(ctx, src, Config(version))
	if e != nil {
		return nil, e
	}
	// Never retain the host absolute source path or arbitrary file contents.
	s.Source.Name = "local-filesystem"
	// ScrubMetadata uses the original source root to relativize all evidence paths.
	s.Artifacts.FileContents = nil
	normalizeDeployedPackages(s)
	collectJavaDeployments(ctx, s, plan)
	if err := collectPythonZipapps(ctx, s, plan); err != nil {
		return nil, err
	}
	resolver, e := src.FileResolver(source.SquashedScope)
	if e != nil {
		return nil, e
	}
	if e = addInstalledNPMDependencies(ctx, s, resolver, plan); e != nil {
		return nil, e
	}
	return s, nil
}
func AddProducts(s *sbom.SBOM, products []model.Product) {
	for _, p := range products {
		if p.Version == "" || p.Confidence == "unknown" || p.Confidence == "conflicting" {
			continue
		}
		loc := file.NewLocationSet()
		for _, e := range p.Evidence {
			loc.Add(file.NewLocation("/" + strings.TrimPrefix(e.Path, "/")))
		}
		entry := pkg.Package{Name: p.Name, Version: p.Version, Type: pkg.BinaryPkg, FoundBy: "koda-product-metadata", Locations: loc, Metadata: p}
		entry.SetID()
		s.Artifacts.Packages.Add(entry)
	}
}
