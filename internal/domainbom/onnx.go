package domainbom

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"koda.local/security-sbom-linux/internal/localfs"
)

// onnxHeader reads the top-level ModelProto fields of an ONNX file: IR
// version, producer, model version and operator set imports. The graph and
// its initializers are skipped without being read. Operator sets outside the
// standard domains need custom operator libraries (native code) to load.
func onnxHeader(f *os.File, size int64) ([]property, error) {
	section := io.NewSectionReader(f, 0, size)
	r := bufio.NewReader(section)
	var offset int64
	// seekPast moves over n bytes without reading them (large graphs and initializers).
	seekPast := func(n int64) error {
		offset += n
		if offset > size {
			return fmt.Errorf("truncated ONNX field")
		}
		if _, err := section.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		r.Reset(section)
		return nil
	}
	varint := func() (uint64, error) {
		v, err := binary.ReadUvarint(r)
		if err == nil {
			offset += int64(uvarintLen(v))
		}
		return v, err
	}
	readBytes := func(n uint64) ([]byte, error) {
		if n > 64<<10 {
			return nil, fmt.Errorf("ONNX field exceeds limit")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		offset += int64(n)
		return b, err
	}
	var props []property
	ir := uint64(0)
	opsets := map[string]string{}
	fields := 0
	for offset < size {
		if fields++; fields > 4096 {
			return nil, fmt.Errorf("ONNX field limit exceeded")
		}
		key, err := varint()
		if err != nil {
			return nil, fmt.Errorf("invalid ONNX field")
		}
		field, wire := key>>3, key&7
		switch wire {
		case 0:
			v, err := varint()
			if err != nil {
				return nil, fmt.Errorf("invalid ONNX varint")
			}
			switch field {
			case 1:
				ir = v
			case 5:
				props = append(props, prop("onnx:model-version", strconv.FormatUint(v, 10)))
			}
		case 2:
			n, err := varint()
			if err != nil || int64(n) > size-offset {
				return nil, fmt.Errorf("invalid ONNX length")
			}
			switch field {
			case 2, 3, 4: // producer_name, producer_version, domain
				b, err := readBytes(n)
				if err != nil {
					return nil, err
				}
				if s := string(b); textOK(s, true) {
					props = append(props, prop("onnx:"+map[uint64]string{2: "producer-name", 3: "producer-version", 4: "domain"}[field], s))
				}
			case 8: // opset_import: OperatorSetIdProto{domain=1, version=2}
				b, err := readBytes(n)
				if err != nil {
					return nil, err
				}
				domain, version := opsetEntry(b)
				if textOK(domain, false) {
					opsets[domain] = version
				}
			default: // graph (7), metadata_props (14), functions, training info
				if err := seekPast(int64(n)); err != nil {
					return nil, err
				}
			}
		case 5:
			if err := seekPast(4); err != nil {
				return nil, err
			}
		case 1:
			if err := seekPast(8); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported ONNX wire type")
		}
	}
	if ir == 0 || len(opsets) == 0 {
		return nil, fmt.Errorf("not an ONNX model")
	}
	props = append([]property{prop("format", "onnx"), prop("artifact-inspection", "model-proto-header"), prop("onnx:ir-version", strconv.FormatUint(ir, 10))}, props...)
	domains := make([]string, 0, len(opsets))
	for d := range opsets {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		name := d
		if name == "" {
			name = "ai.onnx"
		}
		props = append(props, prop("onnx:opset", name+"="+opsets[d]))
		if d != "" && d != "ai.onnx" && d != "ai.onnx.ml" && d != "ai.onnx.training" && d != "ai.onnx.preview.training" {
			props = append(props, prop("onnx:custom-operator-domain", d))
		}
	}
	return props, nil
}

func uvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

func opsetEntry(b []byte) (domain, version string) {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return "", ""
		}
		b = b[n:]
		switch key {
		case 1<<3 | 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return "", ""
			}
			domain, b = string(b[n:n+int(l)]), b[n+int(l):]
		case 2<<3 | 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return "", ""
			}
			version, b = strconv.FormatUint(v, 10), b[n:]
		default:
			return domain, version
		}
	}
	return domain, version
}

// artifactHeader selects the inspection for a model file. ONNX has no magic
// number and is chosen by extension; the other formats are recognized by content.
func artifactHeader(f *os.File, size int64, name string) ([]property, error) {
	if strings.EqualFold(path.Ext(name), ".onnx") {
		return onnxHeader(f, size)
	}
	var magic [4]byte
	if n, _ := f.ReadAt(magic[:], 0); n == 4 {
		switch {
		case string(magic[:]) == "PK\x03\x04":
			return torchZipHeader(f, size)
		case magic[0] == 0x80 && magic[1] >= 2 && magic[1] <= 5:
			return pickleHeader(f)
		}
	}
	props, err := modelHeader(f, size)
	if (err != nil || len(props) == 0) && pickleModelFile(name) {
		// Checkpoint names whose content is neither safetensors nor GGUF may hold
		// a protocol 0/1 pickle, which has no magic number.
		return pickleHeader(f)
	}
	return props, err
}

// pickleModelFile reports file names conventionally used for PyTorch
// checkpoints and ONNX models. Generic .pkl files are often non-model data and
// are inspected only when selected with --model-artifact.
func pickleModelFile(p string) bool {
	return strings.EqualFold(path.Ext(p), ".onnx") || localfs.ModelCheckpointFile(p)
}
