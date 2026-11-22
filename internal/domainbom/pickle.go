package domainbom

import (
	"archive/zip"
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
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
	// An archive this reader refuses or cannot afford may still load in
	// torch.load: report it uninspected rather than hide it.
	uninspected := func() ([]property, error) {
		scan := pickleScan{imports: map[string]bool{}, incomplete: true}
		return scan.properties("pytorch-zip"), nil
	}
	// archive/zip preallocates a slot per declared entry before reading the
	// directory; refuse counts the byte budget could not hold, since a
	// central directory header is at least 46 bytes.
	declared, checked, err := zipDeclaredEntries(f, size)
	if err != nil || declared > uint64(zipDirectoryBudget/46) {
		return uninspected()
	}
	// It then keeps a record for every directory entry it reads, whatever the
	// end record declares, so the bytes it may read bound the rest. The checked
	// end records are served from memory, so a writer cannot change them in
	// between.
	reader := &budgetReaderAt{r: f, budget: zipDirectoryBudget, spans: checked}
	z, err := zip.NewReader(reader, size)
	if err != nil {
		return uninspected()
	}
	reader.budget = math.MaxInt64 // member reads are bounded by the pickle budget
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

// zipDirectoryBudget bounds the bytes zip.NewReader may read for a checkpoint's
// central directory (about 65,000 typical torch.save entries) plus the 64 KiB
// end-record search.
var zipDirectoryBudget int64 = 8<<20 + 128<<10

// span is file content read once at off.
type span struct {
	off int64
	b   []byte
}

// budgetReaderAt serves spans in place of the file's current content and fails
// other reads once its byte budget is spent.
type budgetReaderAt struct {
	r      io.ReaderAt
	budget int64
	spans  []span
}

func (b *budgetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if held, ok := spanned(b.spans, off, int64(len(p))); ok {
		return copy(p, held), nil
	}
	if int64(len(p)) > b.budget {
		return 0, fmt.Errorf("zip read budget exceeded")
	}
	b.budget -= int64(len(p))
	n, err := b.r.ReadAt(p, off)
	overlay(b.spans, p, off)
	return n, err
}

// spanned returns [off, off+n) from the first span holding all of it.
func spanned(spans []span, off, n int64) ([]byte, bool) {
	for _, s := range spans {
		if off >= s.off && off+n <= s.off+int64(len(s.b)) {
			return s.b[off-s.off : off-s.off+n], true
		}
	}
	return nil, false
}

// overlay replaces bytes of p (read at off) that spans already hold, so every
// span agrees with the earlier ones and each byte has one checked value.
func overlay(spans []span, p []byte, off int64) {
	end := off + int64(len(p))
	for i := len(spans) - 1; i >= 0; i-- { // the earliest span wins
		s := spans[i]
		if lo, hi := max(off, s.off), min(end, s.off+int64(len(s.b))); lo < hi {
			copy(p[lo-off:hi-off], s.b[lo-s.off:hi-s.off])
		}
	}
}

// zipDeclaredEntries returns the entry count a zip's end record declares,
// located exactly as archive/zip locates it: the last end-record signature in
// the final 1 KiB, else the final 65 KiB, provided its comment fits, then the
// zip64 end record when a valid locator precedes the end record. It returns
// the spans it read; archive/zip given them through budgetReaderAt parses the
// same bytes, because both take each range from the same span lookup.
func zipDeclaredEntries(r io.ReaderAt, size int64) (uint64, []span, error) {
	le := binary.LittleEndian
	var spans []span
	read := func(n, off int64) ([]byte, error) {
		if held, ok := spanned(spans, off, n); ok {
			return held, nil
		}
		buf := make([]byte, n)
		if _, err := r.ReadAt(buf, off); err != nil && err != io.EOF {
			return nil, err
		}
		overlay(spans, buf, off)
		spans = append(spans, span{off, buf})
		return buf, nil
	}
	var end []byte
	endOffset := int64(0)
	for i, n := range []int64{1024, 65 * 1024} {
		n = min(n, size)
		buf, err := read(n, size-n)
		if err != nil {
			return 0, nil, err
		}
		if p := zipEndSignature(buf); p >= 0 {
			end, endOffset = buf[p:], size-n+int64(p)
			break
		}
		if i == 1 || n == size {
			return 0, nil, fmt.Errorf("zip end record not found")
		}
	}
	entries := uint64(le.Uint16(end[10:]))
	if entries != 0xffff && le.Uint32(end[12:]) != 0xffff && le.Uint32(end[16:]) != 0xffffffff || endOffset < 20 {
		return entries, spans, nil
	}
	locator, err := read(20, endOffset-20)
	if err != nil {
		return 0, nil, err
	}
	offset := int64(le.Uint64(locator[8:]))
	if string(locator[:4]) != "PK\x06\x07" || le.Uint32(locator[4:]) != 0 || le.Uint32(locator[16:]) != 1 || offset < 0 {
		return entries, spans, nil // archive/zip then keeps the 32-bit values
	}
	record, err := read(56, offset)
	if err != nil {
		return 0, nil, err
	}
	if string(record[:4]) != "PK\x06\x06" {
		return 0, nil, fmt.Errorf("zip64 end record not found")
	}
	return le.Uint64(record[32:]), spans, nil
}

// zipEndSignature mirrors archive/zip: the first end-record signature from the
// end of b, or -1 when none is found or its comment would run past b.
func zipEndSignature(b []byte) int {
	for i := len(b) - 22; i >= 0; i-- {
		if string(b[i:i+4]) == "PK\x05\x06" {
			if i+22+int(binary.LittleEndian.Uint16(b[i+20:])) > len(b) {
				return -1
			}
			return i
		}
	}
	return -1
}
