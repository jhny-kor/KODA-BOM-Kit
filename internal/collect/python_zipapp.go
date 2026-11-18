package collect

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"koda.local/security-sbom-linux/internal/localfs"
)

const pythonZipappCollector = "koda-python-zipapp"

var pythonDistributionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
var pythonDistributionVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.!+_-]{0,199}$`)
var pythonNameSeparators = regexp.MustCompile(`[-_.]+`)

func collectPythonZipapps(ctx context.Context, inventory *sbom.SBOM, plan localfs.Plan) error {
	root, err := os.OpenRoot(plan.Root)
	if err != nil {
		recordPythonArchiveIssue(inventory, ".")
		return nil
	}
	defer root.Close()
	for _, name := range plan.Paths {
		extension := strings.ToLower(path.Ext(name))
		if extension != ".pyz" && extension != ".pex" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		f, st, err := localfs.OpenRegularEvidence(root, name)
		if err != nil {
			recordPythonArchiveIssue(inventory, name)
			continue
		}
		if st.Size() > 2<<30 {
			f.Close()
			recordPythonArchiveIssue(inventory, name)
			continue
		}
		entries, err := pythonZipappPackages(ctx, f, st.Size(), name)
		f.Close()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			recordPythonArchiveIssue(inventory, name)
			continue
		}
		for _, entry := range entries {
			inventory.Artifacts.Packages.Add(entry)
		}
	}
	return nil
}

func pythonZipappPackages(ctx context.Context, reader io.ReaderAt, size int64, archive string) ([]pkg.Package, error) {
	z, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, err
	}
	if len(z.File) > 50000 {
		return nil, fmt.Errorf("Python archive member limit exceeded")
	}
	members := map[string]bool{}
	for _, f := range z.File {
		if path.IsAbs(f.Name) || path.Clean(f.Name) != strings.TrimSuffix(f.Name, "/") || strings.ContainsAny(f.Name, "\\\x00") || strings.HasPrefix(f.Name, "../") {
			return nil, fmt.Errorf("unsafe Python archive member")
		}
		if members[f.Name] {
			return nil, fmt.Errorf("duplicate Python archive member")
		}
		members[f.Name] = true
	}
	packages := []pkg.Package{}
	budget := int64(16 << 20)
	for _, f := range z.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path.Base(f.Name) != "METADATA" || !strings.HasSuffix(path.Dir(f.Name), ".dist-info") {
			continue
		}
		if f.UncompressedSize64 > 1<<20 || int64(f.UncompressedSize64) > budget {
			return nil, fmt.Errorf("Python metadata size limit exceeded")
		}
		stream, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(stream, 1<<20+1))
		stream.Close()
		if err != nil || len(data) > 1<<20 {
			return nil, fmt.Errorf("Python metadata could not be read within limit")
		}
		budget -= int64(len(data))
		name, version := "", ""
		for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			if line == "" {
				break
			}
			if strings.HasPrefix(line, "Name:") {
				if name != "" {
					return nil, fmt.Errorf("duplicate Python name")
				}
				name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Version:") {
				if version != "" {
					return nil, fmt.Errorf("duplicate Python version")
				}
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			}
		}
		if !pythonDistributionName.MatchString(name) || !pythonDistributionVersion.MatchString(version) {
			return nil, fmt.Errorf("Python distribution identity unavailable")
		}
		name = strings.ToLower(pythonNameSeparators.ReplaceAllString(name, "-"))
		entry := pkg.Package{Name: name, Version: version, Type: pkg.PythonPkg, FoundBy: pythonZipappCollector, PURL: packageurl.NewPackageURL("pypi", "", name, version, nil, "").ToString(), Locations: file.NewLocationSet(file.NewLocation(archive + "!/" + f.Name))}
		entry.SetID()
		packages = append(packages, entry)
	}
	return packages, nil
}

func recordPythonArchiveIssue(inventory *sbom.SBOM, name string) {
	if inventory.Artifacts.Unknowns == nil {
		inventory.Artifacts.Unknowns = map[file.Coordinates][]string{}
	}
	coordinate := file.NewCoordinates(name, "")
	inventory.Artifacts.Unknowns[coordinate] = append(inventory.Artifacts.Unknowns[coordinate], pythonZipappCollector+": bundled Python metadata unreadable")
}
