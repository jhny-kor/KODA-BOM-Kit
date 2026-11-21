package collect

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/pierrec/lz4/v4"
	"koda.local/security-sbom-linux/internal/localfs"
)

const (
	PackageOriginProperty     = "koda:package:origin"
	PackageRepositoryProperty = "koda:package:repository"
	maxOriginFindings         = 1000
	maxAptIndexBytes          = int64(1) << 30
	maxDnfHistoryBytes        = int64(512) << 20
)

// Origin values. "not-recorded" means no repository index or package manager
// history names the package: installed with dpkg -i or rpm -i, or from a
// repository that was since removed. Such packages miss repository updates.
const (
	OriginRepository  = "repository"
	OriginLocalFile   = "local-file"
	OriginNotRecorded = "not-recorded"
)

type OriginFinding struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	PURL       string `json:"purl,omitempty"`
	Origin     string `json:"origin"`
	Repository string `json:"repository,omitempty"`
	id         artifact.ID
}

// OriginResult records where installed distribution packages came from.
// Findings list only packages outside a repository.
type OriginResult struct {
	Status      string          `json:"status"` // completed, not_applicable
	Sources     []string        `json:"sources,omitempty"`
	Counts      map[string]int  `json:"counts,omitempty"`
	Findings    []OriginFinding `json:"findings,omitempty"`
	Limitations []string        `json:"limitations,omitempty"`
	all         []OriginFinding
}

var repositoryID = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,100}$`)

// PackageOrigins reads apt indexes (var/lib/apt/lists), dnf history
// (var/lib/dnf/history.sqlite) and yumdb (var/lib/yum/yumdb). Repository
// IDs are recorded; repository URLs and local file paths are not. Run it
// before Scrub and resolve PURLs after.
func PackageOrigins(ctx context.Context, inventory *sbom.SBOM, plan localfs.Plan) OriginResult {
	result := OriginResult{Status: "not_applicable"}
	if inventory == nil || inventory.Artifacts.Packages == nil {
		return result
	}
	root, err := plan.OpenRoot()
	if err != nil {
		return result
	}
	defer root.Close()
	var debs, rpms []pkg.Package
	for _, p := range inventory.Artifacts.Packages.Sorted() {
		switch p.Metadata.(type) {
		case pkg.DpkgDBEntry:
			debs = append(debs, p)
		case pkg.RpmDBEntry:
			if p.Name != "gpg-pubkey" { // imported signing keys, never installed from a repository
				rpms = append(rpms, p)
			}
		}
	}
	if len(debs) > 0 {
		if names, sources, limits := aptIndexNames(ctx, root, plan); len(sources) > 0 {
			result.Sources = append(result.Sources, sources...)
			result.Limitations = append(result.Limitations, limits...)
			for _, p := range debs {
				origin := OriginNotRecorded
				if names[p.Name] {
					origin = OriginRepository
				}
				result.record(p, origin, "")
			}
		}
	}
	if len(rpms) > 0 {
		repos, source, limit := rpmRepositories(ctx, root, plan)
		if limit != "" {
			result.Limitations = append(result.Limitations, limit)
		}
		if source != "" {
			result.Sources = append(result.Sources, source)
			for _, p := range rpms {
				repo := repos[rpmKey(p.Metadata.(pkg.RpmDBEntry))]
				switch {
				case repo == "@commandline" || strings.HasPrefix(repo, "/"):
					result.record(p, OriginLocalFile, "")
				case repo == "" || strings.HasPrefix(repo, "@") || !repositoryID.MatchString(repo):
					result.record(p, OriginNotRecorded, "")
				default:
					result.record(p, OriginRepository, repo)
				}
			}
		}
	}
	if len(result.all) > 0 {
		result.Status = "completed"
		result.Limitations = append(result.Limitations,
			"apt indexes list current repository contents: a package counts as from a repository when its name is listed",
			"Packages installed by rpm -i without dnf or yum, and those from removed repositories, are not-recorded",
		)
	}
	return result
}

func (r *OriginResult) record(p pkg.Package, origin, repository string) {
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	r.Counts[origin]++
	r.all = append(r.all, OriginFinding{Package: p.Name, Version: p.Version, Origin: origin, Repository: repository, id: p.ID()})
}

// ResolvePURLs fills PURLs after Scrub and selects the findings to report.
func (r *OriginResult) ResolvePURLs(inventory *sbom.SBOM) {
	r.Findings = nil
	for i := range r.all {
		if item := inventory.Artifacts.Packages.Package(r.all[i].id); item != nil {
			r.all[i].PURL = item.PURL
		}
		if r.all[i].Origin != OriginRepository && len(r.Findings) < maxOriginFindings {
			r.Findings = append(r.Findings, r.all[i])
		}
	}
}

// Properties returns the origin of every classified package.
func (r OriginResult) Properties() ComponentProperties {
	out := ComponentProperties{}
	for _, f := range r.all {
		if f.PURL == "" || len(out[f.PURL]) > 0 {
			continue
		}
		out[f.PURL] = append(out[f.PURL], [2]string{PackageOriginProperty, f.Origin})
		if f.Repository != "" {
			out[f.PURL] = append(out[f.PURL], [2]string{PackageRepositoryProperty, f.Repository})
		}
	}
	return out
}

// aptIndexNames collects package names from downloaded Packages indexes.
// List file names embed mirror host names, so only the directory is reported.
func aptIndexNames(ctx context.Context, root *os.Root, plan localfs.Plan) (map[string]bool, []string, []string) {
	const dir = "var/lib/apt/lists"
	if plan.ExcludesPath(dir) {
		return nil, nil, nil
	}
	f, err := plan.OpenIndexedDirectory(root, dir)
	if err != nil {
		return nil, nil, nil
	}
	entries, _ := f.ReadDir(10000)
	f.Close()
	names := map[string]bool{}
	var limits []string
	budget := maxAptIndexBytes
	found := false
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !(strings.HasSuffix(name, "_Packages") || strings.HasSuffix(name, "_Packages.gz") || strings.HasSuffix(name, "_Packages.lz4")) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		file, _, err := plan.OpenIndexedRegular(root, dir+"/"+name)
		if err != nil {
			continue
		}
		var r io.Reader = file
		switch {
		case strings.HasSuffix(name, ".gz"):
			zr, err := gzip.NewReader(file)
			if err != nil {
				file.Close()
				continue
			}
			r = zr
		case strings.HasSuffix(name, ".lz4"): // container images: Acquire::GzipIndexes with lz4
			r = lz4.NewReader(file)
		}
		counted := &countingReader{r: io.LimitReader(r, budget)}
		scanner := bufio.NewScanner(counted)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			if value, ok := strings.CutPrefix(scanner.Text(), "Package: "); ok {
				names[strings.TrimSpace(value)] = true
			}
		}
		file.Close()
		found = true
		budget -= counted.n
		if budget <= 0 {
			limits = append(limits, "apt index read budget reached; remaining indexes were not read")
			break
		}
	}
	if !found {
		return nil, nil, limits
	}
	return names, []string{dir}, limits
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func rpmKey(m pkg.RpmDBEntry) string {
	return m.Name + "-" + m.Version + "-" + m.Release + "." + m.Arch
}

// rpmRepositories maps name-version-release.arch to the repository ID that
// installed it, from dnf history or, on yum systems, yumdb.
func rpmRepositories(ctx context.Context, root *os.Root, plan localfs.Plan) (map[string]string, string, string) {
	const history = "var/lib/dnf/history.sqlite"
	if !plan.ExcludesPath(history) {
		if _, err := root.Lstat(history); err == nil {
			repos, err := dnfHistory(ctx, root, plan, history)
			if err != nil {
				return nil, "", "dnf history unreadable; RPM origins were not recorded"
			}
			return repos, history, ""
		}
	}
	const yumdb = "var/lib/yum/yumdb"
	if plan.ExcludesPath(yumdb) {
		return nil, "", ""
	}
	repos := map[string]string{}
	letters, err := plan.OpenIndexedDirectory(root, yumdb)
	if err != nil {
		return nil, "", ""
	}
	groups, _ := letters.ReadDir(64)
	letters.Close()
	for _, g := range groups {
		dir, err := plan.OpenIndexedDirectory(root, yumdb+"/"+g.Name())
		if err != nil {
			continue
		}
		items, _ := dir.ReadDir(100000)
		dir.Close()
		for _, item := range items {
			// "<sha1>-name-version-release-arch"
			_, nvra, ok := strings.Cut(item.Name(), "-")
			i := strings.LastIndex(nvra, "-")
			if !ok || i < 0 || ctx.Err() != nil {
				continue
			}
			file, _, err := plan.OpenIndexedRegular(root, yumdb+"/"+g.Name()+"/"+item.Name()+"/from_repo")
			if err != nil {
				continue
			}
			value, _ := io.ReadAll(io.LimitReader(file, 256))
			file.Close()
			repos[nvra[:i]+"."+nvra[i+1:]] = strings.TrimSpace(string(value))
		}
	}
	if len(repos) == 0 {
		return nil, "", ""
	}
	return repos, yumdb, ""
}

// dnfHistory copies the history database (and its WAL) to the scratch
// directory before opening it, so SQLite never writes beside the target.
func dnfHistory(ctx context.Context, root *os.Root, plan localfs.Plan, history string) (map[string]string, error) {
	tmp, err := os.MkdirTemp("", "koda-dnf-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, suffix := range []string{"", "-wal"} {
		src, _, err := plan.OpenIndexedRegular(root, history+suffix)
		if err != nil {
			if suffix == "" {
				return nil, err
			}
			continue
		}
		dst, err := os.Create(filepath.Join(tmp, "history.sqlite"+suffix))
		if err == nil {
			_, err = io.Copy(dst, io.LimitReader(src, maxDnfHistoryBytes))
			dst.Close()
		}
		src.Close()
		if err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(tmp, "history.sqlite")+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// libdnf actions 1 install, 2 downgrade, 6 upgrade, 9 reinstall; state 1 done.
	rows, err := db.QueryContext(ctx, `SELECT r.name, r.version, r.release, r.arch, repo.repoid
		FROM trans_item ti JOIN rpm r ON r.item_id = ti.item_id JOIN repo ON repo.id = ti.repo_id
		WHERE ti.action IN (1, 2, 6, 9) AND ti.state = 1 ORDER BY ti.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	repos := map[string]string{}
	for rows.Next() {
		var name, version, release, arch, repo string
		if err := rows.Scan(&name, &version, &release, &arch, &repo); err != nil {
			return nil, err
		}
		repos[name+"-"+version+"-"+release+"."+arch] = repo // later transactions win
	}
	return repos, rows.Err()
}
