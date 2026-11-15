package collect

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/ulikunitz/xz"
)

func TestKernelCatalogerPreservesModulesAndFallback(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "lib/modules/example/kernel")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	module := testKernelModule(t)
	var compressed bytes.Buffer
	w, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(module); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"compressed.ko.xz": compressed.Bytes(),
		"mislabeled.ko.xz": module,
		"plain.ko":         module,
		"truncated.ko.xz":  compressed.Bytes()[:compressed.Len()-10],
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	ctx := context.Background()
	// Run through Syft's normal context setup, which provides the temp storage
	// used by the original compressed module parser.
	upstream := kernel.NewLinuxKernelCataloger(kernel.DefaultLinuxKernelCatalogerConfig())
	baseline, baselineIssues := catalogKernelFixture(t, ctx, src, upstream)
	optimized, optimizedIssues := catalogKernelFixture(t, ctx, src, newKernelCataloger())
	for _, result := range []map[string]pkg.Package{baseline, optimized} {
		for _, name := range []string{"compressed.ko.xz", "plain.ko"} {
			if _, ok := result["lib/modules/example/kernel/"+name]; !ok {
				t.Fatalf("missing %s in %v", name, result)
			}
		}
	}
	if !reflect.DeepEqual(baseline, optimized) || !reflect.DeepEqual(baselineIssues, optimizedIssues) {
		t.Fatalf("kernel output differs: baseline=%v (%v) optimized=%v (%v)", baseline, baselineIssues, optimized, optimizedIssues)
	}
	if baselineIssues["lib/modules/example/kernel/truncated.ko.xz"] == 0 {
		t.Fatal("truncated module was not reported")
	}
}

func catalogKernelFixture(t *testing.T, ctx context.Context, src source.Source, cataloger pkg.Cataloger) (map[string]pkg.Package, map[string]int) {
	t.Helper()
	config := syft.DefaultCreateSBOMConfig().WithoutFiles()
	config.CatalogerSelection = cataloging.NewSelectionRequest().WithDefaults("rpm-db-cataloger").WithRemovals("file")
	config.WithCatalogers(pkgcataloging.NewAlwaysEnabledCatalogerReference(cataloger))
	inventory, err := syft.CreateSBOM(ctx, src, config)
	if err != nil {
		t.Fatal(err)
	}
	packages := map[string]pkg.Package{}
	for _, module := range inventory.Artifacts.Packages.Sorted() {
		for _, location := range module.Locations.ToSlice() {
			packages[strings.TrimPrefix(location.RealPath, "/")] = module
		}
	}
	// Upstream's archive format checks run in map iteration order. A
	// mislabeled file can name a different probe in the diagnostic text.
	issues := map[string]int{}
	for coordinate, messages := range inventory.Artifacts.Unknowns {
		issues[strings.TrimPrefix(coordinate.RealPath, "/")] = len(messages)
	}
	return packages, issues
}

func testKernelModule(t *testing.T) []byte {
	t.Helper()
	const info = "name=fixture\x00version=1.2.3\x00license=GPL\x00vermagic=example SMP\x00parm=mode:example\x00parmtype=mode:int\x00"
	const names = "\x00.modinfo\x00.shstrtab\x00"
	const headerSize = 64
	const tableOffset = headerSize + len(info) + len(names)
	header := elf.Header64{
		Ident: [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:  uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: uint64(tableOffset), Ehsize: headerSize, Shentsize: 64, Shnum: 3, Shstrndx: 2,
	}
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: headerSize, Size: uint64(len(info)), Addralign: 1},
		{Name: 10, Type: uint32(elf.SHT_STRTAB), Off: uint64(headerSize + len(info)), Size: uint64(len(names)), Addralign: 1},
	}
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	buffer.WriteString(info)
	buffer.WriteString(names)
	if err := binary.Write(&buffer, binary.LittleEndian, sections); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
