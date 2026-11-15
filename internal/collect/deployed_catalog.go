package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
)

const (
	DotnetCollector = "dotnet-deps-binary-cataloger"
	RubyCollector   = "ruby-installed-gemspec-cataloger"
	maxDepsJSON     = 8 << 20
	maxGemspec      = 2 << 20
)

var gemSpecBasename = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,239}\.gemspec$`)

type deployedCataloger struct{ pkg.Cataloger }

func newDotnetCataloger() pkg.Cataloger {
	config := dotnet.DefaultCatalogerConfig().WithDepPackagesMustHaveDLL(true).
		WithPropagateDLLClaimsToParents(false).WithRelaxDLLClaimsWhenBundlingDetected(false)
	return deployedCataloger{dotnet.NewDotnetDepsBinaryCataloger(config)}
}

func newRubyCataloger() pkg.Cataloger {
	return deployedCataloger{ruby.NewInstalledGemSpecCataloger()}
}

func (c deployedCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return c.Cataloger.Catalog(ctx, deployedResolver{Resolver: resolver, ctx: ctx, collector: c.Name()})
}

// Restrict upstream catalogers to the deployed files this scanner inventories.
// The underlying resolver retains target, symlink and exclusion boundaries.
type deployedResolver struct {
	file.Resolver
	ctx       context.Context
	collector string
}

func (r deployedResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	if r.collector == DotnetCollector {
		// Limit .NET discovery to loose deployment files. The upstream ELF
		// bundle scan is a separate pass over all executable binaries.
		return nil, nil
	}
	return r.Resolver.FilesByMIMEType(types...)
}

func (r deployedResolver) RelativeFileByPath(loc file.Location, filename string) *file.Location {
	if r.collector == DotnetCollector && path.Base(filename) == "libman.json" {
		return nil
	}
	return r.Resolver.RelativeFileByPath(loc, filename)
}

func (r deployedResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	if r.collector == DotnetCollector {
		for _, pattern := range patterns {
			if pattern == "**/*.dll" {
				return r.dotnetDLLs()
			}
		}
		return r.Resolver.FilesByGlob(patterns...)
	}
	locations, err := r.Resolver.FilesByGlob(patterns...)
	if err != nil || len(patterns) != 1 || patterns[0] != "**/specifications/**/*.gemspec" {
		return locations, err
	}
	var installed []file.Location
	for _, loc := range locations {
		if err := r.ctx.Err(); err != nil {
			return nil, err
		}
		filename, dir := path.Base(loc.RealPath), path.Dir(loc.RealPath)
		if !gemSpecBasename.MatchString(filename) {
			continue
		}
		switch {
		case path.Base(dir) == "default" && path.Base(path.Dir(dir)) == "specifications":
			// Ruby ships default gems as part of its standard library and
			// does not give them the ordinary gems/<name>-<version> path.
			installed = append(installed, loc)
		case path.Base(dir) == "specifications":
			gem := path.Join(path.Dir(dir), "gems", strings.TrimSuffix(filename, ".gemspec"))
			contents, err := r.Resolver.FilesByGlob(gem + "/**/*")
			if err != nil {
				return nil, err
			}
			if len(contents) > 0 {
				installed = append(installed, loc)
			}
		}
	}
	return installed, nil
}

func (r deployedResolver) dotnetDLLs() ([]file.Location, error) {
	locations, err := r.Resolver.FilesByGlob(
		"**/*.dll", "**/*.DLL", "**/*.Dll", "**/*.dLl", "**/*.dlL", "**/*.DLl", "**/*.DlL", "**/*.dLL",
	)
	if err != nil {
		return nil, err
	}
	var candidates []file.Location
	for _, loc := range locations {
		if err := r.ctx.Err(); err != nil {
			return nil, err
		}
		reader, err := r.Resolver.FileContentsByLocation(loc)
		if err != nil {
			// Retain it so the cataloger reports the read failure against the file.
			candidates = append(candidates, loc)
			continue
		}
		var magic [2]byte
		_, err = io.ReadFull(reader, magic[:])
		reader.Close()
		if string(magic[:]) == "MZ" || (err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) {
			candidates = append(candidates, loc)
		}
	}
	return candidates, nil
}

func (r deployedResolver) FileContentsByLocation(loc file.Location) (io.ReadCloser, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	var limit int64
	switch {
	case r.collector == DotnetCollector && strings.HasSuffix(loc.RealPath, ".deps.json"):
		limit = maxDepsJSON
	case r.collector == RubyCollector && strings.HasSuffix(loc.RealPath, ".gemspec"):
		limit = maxGemspec
	}
	if limit > 0 {
		metadata, err := r.Resolver.FileMetadataByLocation(loc)
		if err != nil {
			return nil, err
		}
		if metadata.FileInfo == nil || metadata.Size() > limit {
			return nil, fmt.Errorf("deployment metadata exceeds the file limit or has no size")
		}
	}
	reader, err := r.Resolver.FileContentsByLocation(loc)
	if err != nil || limit == 0 {
		return reader, err
	}
	return struct {
		io.Reader
		io.Closer
	}{Reader: io.LimitReader(reader, limit), Closer: reader}, nil
}
