package collect

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/mikelolasagasti/xz"
)

const (
	kernelCollector     = "linux-kernel-cataloger"
	xzKernelModuleGlob  = "**/lib/modules/**/*.ko.xz"
	maxFastKernelModule = 4 << 20
	maxFastXZDictionary = 16 << 20
)

type kernelCataloger struct{ upstream pkg.Cataloger }

func newKernelCataloger() pkg.Cataloger {
	return kernelCataloger{upstream: kernel.NewLinuxKernelCataloger(kernel.DefaultLinuxKernelCatalogerConfig())}
}

func (c kernelCataloger) Name() string { return c.upstream.Name() }

func (c kernelCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// Pool within one catalog run. Both read-ahead and retention are bounded,
	// and a reader is leased to only one parser at a time.
	var pool sync.Pool
	readModule := func(ctx context.Context, _ file.Resolver, _ *generic.Environment, input file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
		module, ok := fastXZKernelModule(ctx, &pool, input)
		if !ok {
			return nil, nil, nil // Syft retries this file through its original parser.
		}
		return []pkg.Package{module}, nil, nil
	}
	modules, _, _ := generic.NewCataloger(c.Name()).WithParserByGlobs(readModule, xzKernelModuleGlob).Catalog(ctx, resolver)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	parsed := file.NewCoordinateSet()
	for _, module := range modules {
		for _, location := range module.Locations.ToSlice() {
			parsed.Add(location.Coordinates)
		}
	}
	packages, relationships, err := c.upstream.Catalog(ctx, withoutParsedKernelModules{Resolver: resolver, parsed: parsed})
	byVersion := map[string][]pkg.Package{}
	for _, entry := range packages {
		if entry.Type == pkg.LinuxKernelPkg {
			byVersion[entry.Version] = append(byVersion[entry.Version], entry)
		}
	}
	for _, module := range modules {
		metadata := module.Metadata.(pkg.LinuxKernelModule)
		for _, release := range byVersion[metadata.KernelVersion] {
			relationships = append(relationships, artifact.Relationship{From: release, To: module, Type: artifact.DependencyOfRelationship})
		}
	}
	return append(packages, modules...), relationships, err
}

type withoutParsedKernelModules struct {
	file.Resolver
	parsed file.CoordinateSet
}

func (r withoutParsedKernelModules) FilesByGlob(patterns ...string) ([]file.Location, error) {
	locations, err := r.Resolver.FilesByGlob(patterns...)
	if err != nil {
		return nil, err
	}
	for _, pattern := range patterns {
		if pattern == xzKernelModuleGlob {
			kept := make([]file.Location, 0, len(locations))
			for _, location := range locations {
				if !r.parsed.Contains(location.Coordinates) {
					kept = append(kept, location)
				}
			}
			return kept, nil
		}
	}
	return locations, nil
}

type xzModuleBuffer struct {
	decoder *xz.Reader
	data    bytes.Buffer
}

func fastXZKernelModule(ctx context.Context, pool *sync.Pool, input file.LocationReadCloser) (pkg.Package, bool) {
	var empty pkg.Package
	state, _ := pool.Get().(*xzModuleBuffer)
	if state == nil {
		decoder, err := xz.NewReader(nil, maxFastXZDictionary)
		if err != nil {
			return empty, false
		}
		state = &xzModuleBuffer{decoder: decoder}
	}
	defer func() {
		state.data.Reset()
		// Reset to a separate reader to release the file referenced by xz.
		_ = state.decoder.Reset(bytes.NewReader(nil))
		pool.Put(state)
	}()
	if err := state.decoder.Reset(input); err != nil {
		return empty, false
	}
	// Verify the entire XZ stream, including its integrity check, before using
	// module metadata. Oversized, unreadable or unusual files use Syft's
	// bounded disk-backed path and existing error reporting.
	for ctx.Err() == nil {
		chunk := state.data.AvailableBuffer()
		if cap(chunk) == 0 {
			state.data.Grow(32 << 10)
			chunk = state.data.AvailableBuffer()
		}
		n, err := state.decoder.Read(chunk[:min(cap(chunk), maxFastKernelModule+1-state.data.Len())])
		state.data.Write(chunk[:n])
		if state.data.Len() > maxFastKernelModule || (err != nil && err != io.EOF) {
			return empty, false
		}
		if err == io.EOF {
			return moduleFromELF(ctx, state.data.Bytes(), input.Location)
		}
	}
	return empty, false
}

func moduleFromELF(ctx context.Context, data []byte, location file.Location) (pkg.Package, bool) {
	var empty pkg.Package
	section, err := rawELFSection(bytes.NewReader(data), 1<<20, false, ".modinfo")
	if err != nil || section == nil {
		return empty, false
	}
	contents, err := io.ReadAll(section)
	if err != nil {
		return empty, false
	}
	metadata, ok := kernelModuleMetadata(string(contents), location.LocalPath())
	if !ok {
		return empty, false
	}
	namespace, name := "", metadata.Name
	if parent, leaf, ok := strings.Cut(name, "/"); ok {
		namespace, name = parent, leaf
	}
	module := pkg.Package{
		Name: metadata.Name, Version: metadata.Version, Type: pkg.LinuxKernelModulePkg, Metadata: metadata,
		PURL:      packageurl.NewPackageURL(packageurl.TypeGeneric, namespace, name, metadata.Version, nil, "").ToString(),
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(ctx, location, metadata.License)...),
	}
	module.SetID()
	return module, true
}

// Keep package identity and modinfo evidence compatible with the Syft parser.
func kernelModuleMetadata(contents, modulePath string) (pkg.LinuxKernelModule, bool) {
	metadata := pkg.LinuxKernelModule{Path: modulePath, Parameters: map[string]pkg.LinuxKernelModuleParameter{}}
	for entry := range strings.SplitSeq(contents, "\x00") {
		key, value, _ := strings.Cut(entry, "=")
		switch key {
		case "name":
			metadata.Name = value
		case "version":
			metadata.Version = value
		case "license":
			metadata.License = value
		case "author":
			metadata.Author = value
		case "srcversion":
			metadata.SourceVersion = value
		case "description":
			metadata.Description = value
		case "vermagic":
			metadata.VersionMagic = value
			if fields := strings.Fields(value); len(fields) > 0 {
				metadata.KernelVersion = fields[0]
			}
		case "parm", "parmtype":
			name, detail, ok := strings.Cut(value, ":")
			if !ok {
				return metadata, false
			}
			if _, exists := metadata.Parameters[name]; !exists {
				if key == "parm" {
					metadata.Parameters[name] = pkg.LinuxKernelModuleParameter{Description: detail}
				} else {
					metadata.Parameters[name] = pkg.LinuxKernelModuleParameter{Type: detail}
				}
			}
		}
	}
	return metadata, metadata.KernelVersion != ""
}
