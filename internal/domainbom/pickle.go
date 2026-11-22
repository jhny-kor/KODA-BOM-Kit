package domainbom

import (
	"archive/zip"
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Pickle-based model files (PyTorch .bin/.pt/.pth/.ckpt, .pkl) execute the
// callables they import when loaded. The scanner walks opcodes without
// executing anything and reports which globals the file would import.
const (
	maxPickleBytes   = 64 << 20
	maxPickleOps     = 4 << 20
	maxPickleImports = 256
	maxPickleStreams = 8
	maxZipEntries    = 1 << 16
	maxZipDirectory  = 16 << 20 // central directory bytes; archive/zip keeps every record in memory
	maxPickleMemo    = 1 << 16
	maxPickleString  = 4096 // longer strings cannot be module or attribute names here
)

// torch.save's legacy format writes five pickles: magic number, protocol
// version, system info, the object and its storage keys; tensor bytes follow.
// torch.load compares the first pickle's value, so any encoding of it counts.
const torchLegacyMagic = "119547037146038801333356" // 0x1950a86a20f9469cfc6c

const torchLegacyStreams = 5

// Imports that a pickle can use to run commands, load code or reach the network.
var dangerousModules = []string{"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "pty", "webbrowser", "importlib", "pickle", "_pickle", "commands", "requests", "urllib", "httplib", "http", "asyncio", "ctypes", "multiprocessing", "code", "pdb", "marshal", "types", "torch.hub"}
var dangerousBuiltins = map[string]bool{"eval": true, "exec": true, "execfile": true, "compile": true, "open": true, "__import__": true, "getattr": true, "setattr": true, "globals": true, "locals": true, "breakpoint": true, "input": true, "apply": true}

// Imports PyTorch, NumPy and scikit-learn checkpoints need to rebuild tensors and containers.
var allowedImports = map[string]bool{
	"collections.OrderedDict": true, "collections.defaultdict": true, "torch._utils._rebuild_tensor": true, "torch._utils._rebuild_tensor_v2": true,
	"torch._utils._rebuild_parameter": true, "torch._utils._rebuild_parameter_with_state": true, "torch._utils._rebuild_qtensor": true,
	"torch._utils._rebuild_sparse_tensor": true, "torch._utils._rebuild_meta_tensor_no_storage": true, "torch._utils._rebuild_device_tensor_from_numpy": true,
	"torch._tensor._rebuild_from_type_v2": true, "torch.Size": true, "torch.device": true, "torch.dtype": true, "torch.storage.UntypedStorage": true, "torch.storage.TypedStorage": true,
	"torch.nn.parameter.Parameter": true, "numpy.core.multiarray._reconstruct": true, "numpy._core.multiarray._reconstruct": true, "numpy.core.multiarray.scalar": true,
	"numpy._core.multiarray.scalar": true, "numpy.ndarray": true, "numpy.dtype": true, "_codecs.encode": true, "builtins.set": true, "builtins.frozenset": true,
	"builtins.slice": true, "builtins.complex": true, "builtins.bytearray": true, "__builtin__.set": true,
}

var pickleSafetyRank = map[string]int{"allowlisted-imports-only": 1, "unknown-imports": 2, "dangerous-imports": 3}

func pickleImportClass(imp string) string {
	module, name, _ := strings.Cut(imp, ".")
	if module == "builtins" || module == "__builtin__" {
		if dangerousBuiltins[name] {
			return "dangerous"
		}
	}
	for _, m := range dangerousModules {
		if imp == m || strings.HasPrefix(imp, m+".") {
			return "dangerous"
		}
	}
	if allowedImports[imp] || strings.HasPrefix(imp, "torch.") && strings.HasSuffix(imp, "Storage") && !strings.Contains(imp[6:], ".") {
		return "allowlisted"
	}
	return "unknown"
}

type pickleScan struct {
	imports    map[string]bool
	unresolved bool // an import whose target could not be determined statically
	incomplete bool // a stream could not be fully walked; later opcodes may import anything
	streams    int
	ops        int // opcodes walked across all streams
	// The integer a stream consisting of exactly one integer opcode evaluates to.
	firstInt string
}

// littleEndianInt decodes a LONG1/LONG4 two's complement payload.
func littleEndianInt(b []byte) string {
	be := make([]byte, len(b))
	for i, c := range b {
		be[len(b)-1-i] = c
	}
	n := new(big.Int).SetBytes(be)
	if len(b) > 0 && b[len(b)-1]&0x80 != 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	return n.String()
}

var decimalIndex = regexp.MustCompile(`^[0-9]{1,9}$`)

// scanPickle walks one pickle stream up to STOP. Strings pushed by unicode and
// byte-string opcodes are tracked, with memo, to resolve STACK_GLOBAL operands.
func (p *pickleScan) scanPickle(r *bufio.Reader, budget *int64) error {
	var recent []string
	valueOps, intValue := 0, ""
	memo := map[uint64]string{}
	store := func(n uint64, v string) {
		if len(memo) >= maxPickleMemo {
			p.unresolved = true // later GETs may name anything
			return
		}
		memo[n] = v
	}
	push := func(s string) {
		if recent = append(recent, s); len(recent) > 64 {
			recent = recent[len(recent)-64:]
		}
	}
	last := func() string {
		if len(recent) == 0 {
			return ""
		}
		return recent[len(recent)-1]
	}
	read := func(n uint64) ([]byte, error) {
		if n > uint64(*budget) {
			return nil, fmt.Errorf("pickle exceeds inspection limit")
		}
		*budget -= int64(n)
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	skip := func(n uint64) error {
		if n > uint64(*budget) {
			return fmt.Errorf("pickle exceeds inspection limit")
		}
		*budget -= int64(n)
		_, err := r.Discard(int(n))
		return err
	}
	line := func() (string, error) {
		s, err := r.ReadString('\n')
		*budget -= int64(len(s))
		if err != nil || *budget < 0 || len(s) > 4096 {
			return "", fmt.Errorf("invalid pickle text argument")
		}
		return strings.TrimSuffix(s, "\n"), nil
	}
	lengthPrefixed := func(width int) ([]byte, error) {
		b, err := read(uint64(width))
		if err != nil {
			return nil, err
		}
		var n uint64
		switch width {
		case 1:
			n = uint64(b[0])
		case 4:
			n = uint64(binary.LittleEndian.Uint32(b))
		case 8:
			n = binary.LittleEndian.Uint64(b)
		}
		if n > maxPickleString {
			return nil, skip(n) // pushed as a non-name value
		}
		return read(n)
	}
	addImport := func(module, name string) {
		if len(p.imports) < maxPickleImports {
			p.imports[module+"."+name] = true
		}
	}
	for ops := 0; ops < maxPickleOps; ops++ {
		op, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("truncated pickle")
		}
		*budget--
		p.ops++
		if op != 0x80 && op != 0x95 && op != '.' {
			valueOps++
		}
		switch op {
		case '.': // STOP
			if valueOps == 1 {
				p.firstInt = intValue
			} else {
				p.firstInt = ""
			}
			p.streams++
			return nil
		case 'c', 'i': // GLOBAL, INST: module and name lines
			module, err := line()
			if err != nil {
				return err
			}
			name, err := line()
			if err != nil {
				return err
			}
			addImport(module, name)
			push("")
		case 0x93: // STACK_GLOBAL
			if len(recent) >= 2 && recent[len(recent)-2] != "" && recent[len(recent)-1] != "" {
				addImport(recent[len(recent)-2], recent[len(recent)-1])
			} else {
				p.unresolved = true
			}
			push("")
		case 'V', 'S': // UNICODE, STRING
			s, err := line()
			if err != nil {
				return err
			}
			push(strings.Trim(s, `'"`))
		case 0x8c, 'U', 'C': // SHORT_BINUNICODE, SHORT_BINSTRING, SHORT_BINBYTES
			b, err := lengthPrefixed(1)
			if err != nil {
				return err
			}
			push(string(b))
		case 'X', 'T', 'B': // BINUNICODE, BINSTRING, BINBYTES
			b, err := lengthPrefixed(4)
			if err != nil {
				return err
			}
			push(string(b))
		case 0x8d, 0x8e, 0x96: // BINUNICODE8, BINBYTES8, BYTEARRAY8
			b, err := lengthPrefixed(8)
			if err != nil {
				return err
			}
			push(string(b))
		case 0x94: // MEMOIZE
			store(uint64(len(memo)), last())
		case 'p', 'g': // PUT, GET (decimal index lines)
			s, err := line()
			if err != nil {
				return err
			}
			// Python's int() also accepts "+1", " 1" or "1_0"; such indices
			// cannot be mirrored safely, so imports via the memo become unresolved.
			if !decimalIndex.MatchString(s) {
				p.unresolved = true
				push("")
				continue
			}
			n, _ := strconv.ParseUint(s, 10, 64)
			if op == 'p' {
				store(n, last())
			} else {
				push(memo[n])
			}
		case 'q', 'h': // BINPUT, BINGET
			b, err := read(1)
			if err != nil {
				return err
			}
			if op == 'q' {
				store(uint64(b[0]), last())
			} else {
				push(memo[uint64(b[0])])
			}
		case 'r', 'j': // LONG_BINPUT, LONG_BINGET
			b, err := read(4)
			if err != nil {
				return err
			}
			n := uint64(binary.LittleEndian.Uint32(b))
			if op == 'r' {
				store(n, last())
			} else {
				push(memo[n])
			}
		case 'F', 'I', 'L', 'P': // FLOAT, INT, LONG, PERSID
			text, err := line()
			if err != nil {
				return err
			}
			if op == 'I' || op == 'L' {
				intValue = strings.TrimSuffix(strings.TrimSpace(text), "L")
			}
			push("")
		case 'K', 0x80, 0x82: // BININT1, PROTO, EXT1
			if err := skip(1); err != nil {
				return err
			}
			// EXT opcodes import a global registered through copyreg.
			p.unresolved = p.unresolved || op == 0x82
			push("")
		case 'M', 0x83: // BININT2, EXT2
			if err := skip(2); err != nil {
				return err
			}
			p.unresolved = p.unresolved || op == 0x83
			push("")
		case 'J', 0x84: // BININT, EXT4
			p.unresolved = p.unresolved || op == 0x84
			if err := skip(4); err != nil {
				return err
			}
			push("")
		case 'G', 0x95: // BINFLOAT, FRAME
			if err := skip(8); err != nil {
				return err
			}
			if op == 'G' {
				push("")
			}
		case 0x8a, 0x8b: // LONG1, LONG4
			width := 1
			if op == 0x8b {
				width = 4
			}
			b, err := lengthPrefixed(width)
			if err != nil {
				return err
			}
			intValue = littleEndianInt(b)
			push("")
		case '(', '0', '1', '2', 'N', 'Q', 'R', 'a', 'b', 'd', '}', 'e', 'l', ']', 'o', 's', 't', ')', 'u',
			0x81, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x92, 0x97, 0x98:
			push("")
		default:
			return fmt.Errorf("unknown pickle opcode 0x%02x", op)
		}
	}
	return fmt.Errorf("pickle opcode limit reached")
}

func (p *pickleScan) properties(format string) []property {
	imports := make([]string, 0, len(p.imports))
	for imp := range p.imports {
		imports = append(imports, imp)
	}
	sort.Strings(imports)
	safety := "allowlisted-imports-only"
	var dangerous, unknown []string
	for _, imp := range imports {
		switch pickleImportClass(imp) {
		case "dangerous":
			dangerous = append(dangerous, imp)
		case "unknown":
			unknown = append(unknown, imp)
		}
	}
	switch {
	case len(dangerous) > 0:
		safety = "dangerous-imports"
	case len(unknown) > 0 || p.unresolved || p.incomplete:
		safety = "unknown-imports"
	}
	props := []property{prop("format", format), prop("artifact-inspection", "pickle-opcodes-not-executed"), prop("pickle:safety", safety), prop("pickle:import-count", strconv.Itoa(len(imports)))}
	for _, imp := range dangerous {
		props = append(props, prop("pickle:dangerous-import", imp))
	}
	for _, imp := range unknown {
		if textOK(imp, true) {
			props = append(props, prop("pickle:unknown-import", imp))
		}
	}
	if p.unresolved {
		props = append(props, prop("pickle:unresolved-import", "true"))
	}
	if p.incomplete {
		// Opcodes before the failure ran in Python before it raised, so the
		// imports above still count; the rest of the file was not examined.
		props = append(props, prop("pickle:inspection", "incomplete"))
	} else {
		props = append(props, prop("pickle:inspection", "complete"))
	}
	return props
}

// pickleHeader inspects a plain pickle (one stream, which pickle.load reads)
// or a legacy torch.save file (five streams of any protocol). A walk that fails
// part-way is reported as incomplete with the imports found so far, never as an
// error, so a hostile file cannot hide as merely unreadable.
func pickleHeader(f *os.File) ([]property, error) {
	r := bufio.NewReader(io.NewSectionReader(f, 0, maxPickleBytes))
	budget := int64(maxPickleBytes)
	scan := pickleScan{imports: map[string]bool{}}
	streams := 1
	format := "pickle"
	for i := 0; i < streams; i++ {
		if err := scan.scanPickle(r, &budget); err != nil {
			if scan.ops <= 1 {
				return nil, err // the first opcode is not valid: not a pickle at all
			}
			scan.incomplete = true
			break
		}
		if i == 0 && scan.firstInt == torchLegacyMagic {
			streams, format = torchLegacyStreams, "pytorch-legacy"
		}
	}
	return scan.properties(format), nil
}

// torchZipHeader inspects every *.pkl member of a PyTorch zip checkpoint or
// TorchScript archive. Tensor storages are not read.
func torchZipHeader(f *os.File, size int64) ([]property, error) {
	entries, directory, err := zipDirectory(f, size)
	if err != nil {
		return nil, err
	}
	if entries > maxZipEntries || directory > maxZipDirectory {
		// torch.load would still run such an archive's pickles; report it as
		// uninspected rather than loading an unbounded directory.
		scan := pickleScan{imports: map[string]bool{}, incomplete: true}
		return append(scan.properties("pytorch-zip"), prop("archive-entries", strconv.FormatUint(entries, 10))), nil
	}
	z, err := zip.NewReader(f, size)
	if err != nil {
		return nil, err
	}
	scan := pickleScan{imports: map[string]bool{}}
	budget := int64(maxPickleBytes)
	torchscript := false
	for _, entry := range z.File {
		parts := strings.Split(entry.Name, "/")
		if len(parts) >= 2 && parts[1] == "code" {
			torchscript = true
		}
		if path.Ext(entry.Name) != ".pkl" {
			continue
		}
		if entry.Method != zip.Store && entry.Method != zip.Deflate {
			scan.incomplete = true
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			scan.incomplete = true
			continue
		}
		if err = scan.scanPickle(bufio.NewReader(io.LimitReader(rc, budget+1)), &budget); err != nil {
			scan.incomplete = true
		}
		rc.Close()
	}
	if scan.streams == 0 && !scan.incomplete {
		return nil, fmt.Errorf("archive has no pickle member")
	}
	format := "pytorch-zip"
	if torchscript {
		format = "torchscript"
	}
	return append(scan.properties(format), prop("archive-entries", strconv.Itoa(len(z.File)))), nil
}

// zipDirectory returns the entry count and size of a zip's central directory
// from its end records (zip64 included) without reading the directory itself.
func zipDirectory(f *os.File, size int64) (entries, directory uint64, err error) {
	const endLen = 22
	tail := min(size, endLen+0xffff)
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, size-tail); err != nil && err != io.EOF {
		return 0, 0, err
	}
	le := binary.LittleEndian
	end := -1
	for i := len(buf) - endLen; i >= 0; i-- {
		if string(buf[i:i+4]) == "PK\x05\x06" && i+endLen+int(le.Uint16(buf[i+20:])) == len(buf) {
			end = i
			break
		}
	}
	if end < 0 {
		return 0, 0, fmt.Errorf("zip end record not found")
	}
	entries, directory = uint64(le.Uint16(buf[end+10:])), uint64(le.Uint32(buf[end+12:]))
	if entries != 0xffff && directory != 0xffffffff && le.Uint32(buf[end+16:]) != 0xffffffff {
		return entries, directory, nil
	}
	// zip64: a 20-byte locator precedes the end record and points at the zip64 end record.
	if end < 20 || string(buf[end-20:end-16]) != "PK\x06\x07" {
		return 0, 0, fmt.Errorf("zip64 locator not found")
	}
	offset := le.Uint64(buf[end-12:])
	var record [56]byte
	if offset > uint64(size-56) {
		return 0, 0, fmt.Errorf("zip64 end record out of range")
	}
	if _, err := f.ReadAt(record[:], int64(offset)); err != nil || string(record[:4]) != "PK\x06\x06" {
		return 0, 0, fmt.Errorf("zip64 end record not found")
	}
	return le.Uint64(record[32:]), le.Uint64(record[40:]), nil
}
