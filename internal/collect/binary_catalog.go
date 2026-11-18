package collect

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/sbom"
	"github.com/rust-secure-code/go-rustaudit"
	"koda.local/security-sbom-linux/internal/model"
)

const (
	GoBinaryCollector        = "go-module-binary-cataloger"
	RustBinaryCollector      = "cargo-auditable-binary-cataloger"
	binarySPDXIDPrefix       = "SPDXRef-KODA-Binary-"
	deployedSPDXIDPrefix     = "SPDXRef-KODA-Deployed-"
	maxRustAuditCompressed   = 4 << 20
	maxRustAuditUncompressed = 8 << 20
	maxRustAuditPackages     = 20000
	maxRustAuditEdges        = 100000
	maxELFSections           = 8192
	maxELFSectionNames       = 1 << 20
	maxDeployedIssues        = 500
)

var cargoName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$`)

func newRustBinaryCataloger() pkg.Cataloger {
	return generic.NewCataloger(RustBinaryCollector).WithParserByMimeTypes(
		parseRustBinary, "application/x-executable", "application/x-elf", "application/x-sharedlib",
	)
}

func parseRustBinary(ctx context.Context, _ file.Resolver, _ *generic.Environment, input file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	reader, ok := input.ReadCloser.(io.ReaderAt)
	if !ok {
		return nil, nil, fmt.Errorf("cannot read binary metadata by offset")
	}
	compressed, err := rustAuditSection(reader)
	if err != nil || compressed == nil {
		return nil, nil, err
	}
	z, err := zlib.NewReader(compressed)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid Rust audit section compression")
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, maxRustAuditUncompressed+1))
	if err != nil || len(data) > maxRustAuditUncompressed {
		return nil, nil, fmt.Errorf("Rust audit payload is unreadable or exceeds the size limit")
	}
	var audit rustaudit.VersionInfo
	if err := json.Unmarshal(data, &audit); err != nil || len(audit.Packages) == 0 || len(audit.Packages) > maxRustAuditPackages {
		return nil, nil, fmt.Errorf("Rust audit package list is invalid or exceeds the count limit")
	}
	return rustPackages(ctx, audit, input.Location)
}

// Read only the ELF section index, raw name table and requested audit section.
// In particular, opening a file must not inflate its ELF section name table.
func rustAuditSection(reader io.ReaderAt) (io.Reader, error) {
	return rawELFSection(reader, maxRustAuditCompressed, true, ".dep-v0", ".rust-deps-v0")
}

func rawELFSection(reader io.ReaderAt, sectionLimit uint64, executable bool, sectionNames ...string) (io.Reader, error) {
	var ident [elf.EI_NIDENT]byte
	if _, err := reader.ReadAt(ident[:4], 0); err != nil || string(ident[:4]) != elf.ELFMAG {
		return nil, nil
	}
	if _, err := reader.ReadAt(ident[4:], 4); err != nil {
		return nil, fmt.Errorf("cannot read ELF identification")
	}
	var order binary.ByteOrder
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		order = binary.LittleEndian
	case elf.ELFDATA2MSB:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("invalid ELF byte order")
	}

	var header elf.Header64
	var sectionSize int
	is64 := elf.Class(ident[elf.EI_CLASS]) == elf.ELFCLASS64
	switch elf.Class(ident[elf.EI_CLASS]) {
	case elf.ELFCLASS64:
		sectionSize = binary.Size(elf.Section64{})
		if err := binary.Read(io.NewSectionReader(reader, 0, int64(binary.Size(header))), order, &header); err != nil {
			return nil, fmt.Errorf("cannot read ELF header")
		}
	case elf.ELFCLASS32:
		sectionSize = binary.Size(elf.Section32{})
		var short elf.Header32
		if err := binary.Read(io.NewSectionReader(reader, 0, int64(binary.Size(short))), order, &short); err != nil {
			return nil, fmt.Errorf("cannot read ELF header")
		}
		header.Type, header.Shoff, header.Shentsize = short.Type, uint64(short.Shoff), short.Shentsize
		header.Shnum, header.Shstrndx = short.Shnum, short.Shstrndx
	default:
		return nil, fmt.Errorf("unsupported ELF class")
	}
	elfType := elf.Type(header.Type)
	if (executable && elfType != elf.ET_EXEC && elfType != elf.ET_DYN) ||
		(!executable && elfType != elf.ET_REL) || header.Shstrndx == uint16(elf.SHN_UNDEF) {
		return nil, nil
	}
	if header.Shnum > maxELFSections || header.Shstrndx >= header.Shnum || header.Shoff == 0 ||
		int(header.Shentsize) != sectionSize || header.Shoff > math.MaxInt64-uint64(header.Shentsize)*uint64(header.Shnum) {
		return nil, fmt.Errorf("invalid ELF section table or section count exceeds limit")
	}
	table := make([]byte, int(header.Shentsize)*int(header.Shnum))
	if _, err := reader.ReadAt(table, int64(header.Shoff)); err != nil {
		return nil, fmt.Errorf("cannot read ELF section table")
	}
	sectionAt := func(index int) (section elf.Section64) {
		data := table[index*sectionSize:][:sectionSize]
		if is64 {
			_, _ = binary.Decode(data, order, &section)
			return section
		}
		var short elf.Section32
		_, _ = binary.Decode(data, order, &short)
		return elf.Section64{Name: short.Name, Type: short.Type, Flags: uint64(short.Flags), Off: uint64(short.Off), Size: uint64(short.Size)}
	}
	validRange := func(section elf.Section64, limit uint64) bool {
		return section.Size > 0 && section.Size <= limit && section.Off <= math.MaxInt64-section.Size &&
			elf.SectionFlag(section.Flags)&elf.SHF_COMPRESSED == 0
	}
	stringTable := sectionAt(int(header.Shstrndx))
	if elf.SectionType(stringTable.Type) != elf.SHT_STRTAB || !validRange(stringTable, maxELFSectionNames) {
		return nil, fmt.Errorf("invalid ELF section name table or size exceeds limit")
	}
	names := make([]byte, int(stringTable.Size))
	if _, err := reader.ReadAt(names, int64(stringTable.Off)); err != nil {
		return nil, fmt.Errorf("cannot read ELF section names")
	}
	var result io.Reader
	for index := range int(header.Shnum) {
		candidate := sectionAt(index)
		if uint64(candidate.Name) >= uint64(len(names)) {
			return nil, fmt.Errorf("invalid ELF section name offset")
		}
		name := names[candidate.Name:]
		name, _, _ = bytes.Cut(name, []byte{0})
		if !slices.Contains(sectionNames, string(name)) {
			continue
		}
		if result != nil || elf.SectionType(candidate.Type) != elf.SHT_PROGBITS || !validRange(candidate, sectionLimit) {
			return nil, fmt.Errorf("duplicate, unsupported or oversized ELF section")
		}
		result = io.NewSectionReader(reader, int64(candidate.Off), int64(candidate.Size))
	}
	return result, nil
}

func rustPackages(ctx context.Context, audit rustaudit.VersionInfo, location file.Location) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package
	byIndex := make(map[int]pkg.Package)
	edgeCount := 0
	for index, dependency := range audit.Packages {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		edgeCount += len(dependency.Dependencies)
		if edgeCount > maxRustAuditEdges {
			return nil, nil, fmt.Errorf("Rust audit dependency count exceeds limit")
		}
		for _, target := range dependency.Dependencies {
			if target >= uint(len(audit.Packages)) {
				return nil, nil, fmt.Errorf("Rust audit dependency index is invalid")
			}
		}
		if dependency.Kind == rustaudit.Build {
			continue
		}
		if dependency.Kind != rustaudit.Runtime || !cargoName.MatchString(dependency.Name) || len(dependency.Version) > 128 {
			return nil, nil, fmt.Errorf("Rust audit package identity is invalid")
		}
		if _, err := semver.StrictNewVersion(dependency.Version); err != nil {
			return nil, nil, fmt.Errorf("Rust audit package version is invalid")
		}
		entry := pkg.Package{
			Name: dependency.Name, Version: dependency.Version, Language: pkg.Rust, Type: pkg.RustPkg,
			Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		}
		if dependency.Source == "crates.io" {
			entry.PURL = packageurl.NewPackageURL(packageurl.TypeCargo, "", entry.Name, entry.Version, nil, "").ToString()
		}
		source := dependency.Source
		if source != "crates.io" && source != "local" {
			source = "other"
		}
		entry.Metadata = pkg.RustBinaryAuditEntry{Name: entry.Name, Version: entry.Version, Source: source}
		entry.SetID()
		byIndex[index] = entry
		packages = append(packages, entry)
	}
	var relationships []artifact.Relationship
	for index, source := range audit.Packages {
		entry, ok := byIndex[index]
		if !ok {
			continue
		}
		for _, target := range source.Dependencies {
			if dependency, ok := byIndex[int(target)]; ok && dependency.ID() != entry.ID() {
				relationships = append(relationships, artifact.Relationship{From: dependency, To: entry, Type: artifact.DependencyOfRelationship})
			}
		}
	}
	return packages, relationships, nil
}

func isBinaryCollector(name string) bool {
	return name == GoBinaryCollector || name == RustBinaryCollector
}

func isDeployedCollector(name string) bool {
	return isBinaryCollector(name) || name == DotnetCollector || name == RubyCollector
}

// Normalize deployed package references before either encoder writes the graph.
// SPDX uses the same explicit identifier as the in-memory package.
func normalizeDeployedPackages(inventory *sbom.SBOM) {
	packages := pkg.NewCollection()
	refs := map[artifact.ID]pkg.Package{}
	for _, item := range inventory.Artifacts.Packages.Sorted() {
		if isDeployedCollector(item.FoundBy) {
			oldID := item.ID()
			prefix := deployedSPDXIDPrefix
			if isBinaryCollector(item.FoundBy) {
				prefix = binarySPDXIDPrefix
			}
			if item.Version == "" || item.Version == cataloging.UnknownStubValue {
				item.Version = ""
				item.PURL = ""
			}
			if item.FoundBy == DotnetCollector {
				// A loose PE identifies an assembly, not a NuGet distribution.
				// A .deps.json library of type package supplies those coordinates.
				if metadata, ok := item.Metadata.(pkg.DotnetDepsEntry); !ok || metadata.Type != "package" {
					item.PURL = ""
				}
			}
			item.OverrideID(artifact.ID(prefix + string(oldID)))
			refs[oldID] = item
		}
		packages.Add(item)
	}
	inventory.Artifacts.Packages = packages
	for i := range inventory.Relationships {
		edge := &inventory.Relationships[i]
		if edge.From == nil || edge.To == nil {
			continue
		}
		if item, ok := refs[edge.From.ID()]; ok {
			edge.From = item
		}
		if item, ok := refs[edge.To.ID()]; ok {
			edge.To = item
		}
	}
}

// Report controlled diagnostics and discard parser messages before export.
func DeployedCollectionIssues(inventory *sbom.SBOM, root string) []model.Issue {
	var issues []model.Issue
	for coordinate, errors := range inventory.Artifacts.Unknowns {
		seen := map[string]bool{}
		for _, message := range errors {
			task, detail, _ := strings.Cut(message, ": ")
			if task == npmDependencySource {
				if issue, ok := npmDependencyIssue(detail, privacyPath(coordinate.RealPath, root)); ok {
					issues = append(issues, issue)
				}
				seen[task] = true
				continue
			}
			if (isDeployedCollector(task) || task == javaDeploymentSource || task == pythonZipappCollector) && !seen[task] {
				seen[task] = true
				code, detail := "deployment_metadata_unreadable", "installed software metadata could not be read within collection limits"
				if isBinaryCollector(task) {
					code, detail = "binary_metadata_unreadable", "embedded binary dependency metadata could not be read within collection limits"
				}
				issues = append(issues, model.Issue{
					Collector: task, Status: "incomplete", Code: code,
					Path: privacyPath(coordinate.RealPath, root), Message: detail,
				})
			}
		}
		if len(seen) == 0 {
			continue
		}
		kept := slices.DeleteFunc(errors, func(message string) bool {
			task, _, _ := strings.Cut(message, ": ")
			return seen[task]
		})
		if len(kept) > 0 {
			inventory.Artifacts.Unknowns[coordinate] = kept
		} else {
			delete(inventory.Artifacts.Unknowns, coordinate)
		}
	}
	slices.SortFunc(issues, func(a, b model.Issue) int {
		if a.Status != b.Status {
			return strings.Compare(a.Status, b.Status) // incomplete diagnostics precede observations
		}
		if a.Path != b.Path {
			return strings.Compare(a.Path, b.Path)
		}
		if a.Collector != b.Collector {
			return strings.Compare(a.Collector, b.Collector)
		}
		return strings.Compare(a.Message, b.Message)
	})
	if len(issues) > maxDeployedIssues {
		omitted := int64(len(issues) - maxDeployedIssues)
		issues = append(issues[:maxDeployedIssues], model.Issue{
			Collector: "syft", Status: "incomplete", Code: "deployment_issue_limit",
			Message: "additional deployed software collection issues were omitted", Observed: omitted,
		})
	}
	return issues
}
