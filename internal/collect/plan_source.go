package collect

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/zipguard"
)

type planSource struct {
	ctx        context.Context
	plan       localfs.Plan
	root       *os.Root
	tree       *filetree.FileTree
	index      filetree.Index
	search     filetree.Searcher
	unreadable []string
}

func newPlanSource(ctx context.Context, plan localfs.Plan) (*planSource, error) {
	root, err := plan.OpenRoot()
	if err != nil {
		return nil, fmt.Errorf("scan root changed or is unreadable: %w", err)
	}
	src := &planSource{ctx: ctx, plan: plan, root: root, tree: filetree.New(), index: filetree.NewIndex()}
	if err := src.buildIndex(); err != nil {
		src.Close()
		return nil, err
	}
	src.search = filetree.NewSearchContext(src.tree, src.index)
	return src, nil
}

func (s *planSource) buildIndex() error {
	for _, name := range s.plan.Paths {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		f, info, err := s.plan.OpenIndexedRegular(s.root, name)
		if err != nil {
			if len(s.unreadable) < 1000 {
				s.unreadable = append(s.unreadable, name)
			}
			continue
		}
		mime := stereofile.MIMEType(f)
		f.Close()
		key := "/" + name
		ref, err := s.tree.AddFile(stereofile.Path(key))
		if err != nil {
			return err
		}
		s.index.Add(*ref, file.Metadata{FileInfo: info, Path: s.responsePath(key), Type: stereofile.TypeRegular, MIMEType: mime})
	}
	for _, name := range s.plan.IndexedLinks() {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		target, _, err := s.plan.ResolveIndexedPath(name)
		if err != nil {
			continue
		}
		key, destination := "/"+name, path.Join("/", target)
		ref, err := s.tree.AddSymLink(stereofile.Path(key), stereofile.Path(destination))
		if err != nil {
			return err
		}
		s.index.Add(*ref, file.Metadata{Path: s.responsePath(key), Type: stereofile.TypeSymLink, LinkDestination: destination,
			FileInfo: stereofile.ManualInfo{NameValue: path.Base(name), ModeValue: fs.ModeSymlink}})
	}
	return nil
}

func (s *planSource) ID() artifact.ID {
	// Match Syft's stable directory source ID for the existing alias.
	return artifact.ID(fmt.Sprintf("%x", sha256.Sum256([]byte("local-filesystem@"))))
}

func (s *planSource) Describe() source.Description {
	metadata := source.DirectoryMetadata{Path: s.plan.Root}
	if s.plan.RootFilesystem {
		metadata.Base = s.plan.Root
	}
	return source.Description{ID: string(s.ID()), Name: "local-filesystem", Metadata: metadata}
}

func (s *planSource) FileResolver(source.Scope) (file.Resolver, error) { return s, nil }
func (s *planSource) Close() error                                     { return s.root.Close() }

func (s *planSource) responsePath(name string) string {
	if s.plan.RootFilesystem {
		return name
	}
	return strings.TrimPrefix(name, "/")
}

func resolverPath(name string) string {
	return path.Join("/", filepath.ToSlash(name))
}

func (s *planSource) HasPath(name string) bool {
	key := resolverPath(name)
	if s.tree.HasPath(stereofile.Path(key)) {
		return true
	}
	// Package databases may own empty directories, which need no tree entry
	// for content cataloging but still need to be recognized by exact lookup.
	dir, err := s.plan.OpenIndexedDirectory(s.root, strings.TrimPrefix(key, "/"))
	if err != nil {
		return false
	}
	dir.Close()
	return true
}

func (s *planSource) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	for _, name := range paths {
		ref, err := s.search.SearchByPath(resolverPath(name), filetree.FollowBasenameLinks)
		if err != nil || ref == nil {
			continue
		}
		if loc, ok := s.resolvedLocation(*ref); ok {
			out = append(out, loc)
		}
	}
	return out, nil
}

func (s *planSource) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var out []file.Location
	seen := stereofile.NewFileReferenceSet()
	for _, pattern := range patterns {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(pattern, "*") {
			pattern = path.Join("/", pattern)
		}
		refs, err := s.search.SearchByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if loc, ok := s.resolvedLocation(ref); ok && !seen.Contains(*ref.Reference) {
				seen.Add(*ref.Reference)
				out = append(out, loc)
			}
		}
	}
	return out, nil
}

func (s *planSource) FilesByMIMEType(types ...string) ([]file.Location, error) {
	refs, err := s.search.SearchByMIMEType(types...)
	if err != nil {
		return nil, err
	}
	var out []file.Location
	for _, ref := range refs {
		if loc, ok := s.resolvedLocation(ref); ok {
			out = append(out, loc)
		}
	}
	return out, nil
}

func (s *planSource) resolvedLocation(ref stereofile.Resolution) (file.Location, bool) {
	if !ref.HasReference() {
		return file.Location{}, false
	}
	entry, err := s.index.Get(*ref.Reference)
	if err != nil || entry.Type != stereofile.TypeRegular {
		return file.Location{}, false
	}
	return file.NewVirtualLocationFromDirectory(s.responsePath(string(ref.RealPath)), s.responsePath(string(ref.RequestPath)), *ref.Reference), true
}

func (s *planSource) RelativeFileByPath(_ file.Location, name string) *file.Location {
	locations, _ := s.FilesByPath(name)
	if len(locations) == 0 {
		return nil
	}
	return &locations[0]
}

func (s *planSource) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	entry, err := s.index.Get(location.Reference())
	if err != nil || entry.Type != stereofile.TypeRegular {
		return nil, fs.ErrNotExist
	}
	name := strings.TrimPrefix(string(entry.RealPath), "/")
	f, info, err := s.plan.OpenIndexedRegular(s.root, name)
	if err != nil {
		return nil, err
	}
	if !zipguard.IsJavaArchive(name) && !zipguard.IsJavaArchive(location.AccessPath) {
		return f, nil
	}
	reader, err := zipguard.JavaReader(s.ctx, f, info.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	return guardedArchive{reader, f}, nil
}

type guardedArchive struct {
	io.ReadCloser
	source *os.File
}

func (a guardedArchive) Close() error {
	return errors.Join(a.ReadCloser.Close(), a.source.Close())
}

func (s *planSource) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	entry, err := s.index.Get(location.Reference())
	return entry.Metadata, err
}

func (s *planSource) AllLocations(ctx context.Context) <-chan file.Location {
	locations := make(chan file.Location)
	go func() {
		defer close(locations)
		for _, ref := range s.tree.AllFiles(stereofile.AllTypes()...) {
			select {
			case <-ctx.Done():
				return
			case locations <- file.NewLocationFromDirectory(s.responsePath(string(ref.RealPath)), "", ref):
			}
		}
	}()
	return locations
}
