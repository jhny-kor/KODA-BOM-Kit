// Package aixevidence imports read-only inventory captured on one AIX server.
package aixevidence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"

	"koda.local/security-sbom-linux/internal/model"
)

const (
	Schema         = "koda-aix-evidence-v1"
	SchemaMulti    = "koda-aix-evidence-v2"
	maxOracleHomes = 8
	maxSourceBytes = 8 << 20
	maxRecords     = 50000
)

type Inventory struct {
	OSLevel        string            `json:"osLevel,omitempty"`
	Filesets       []Fileset         `json:"filesets"`
	InterimFixes   []InterimFix      `json:"interimFixes"`
	OracleHomes    []OracleHome      `json:"oracleHomes"`
	EvidenceSHA256 map[string]string `json:"evidenceSha256"`
	Issues         []model.Issue     `json:"issues"`
}

type Fileset struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	State    string `json:"state,omitempty"`
	Type     string `json:"type,omitempty"`
	FixState string `json:"fixState,omitempty"`
	PTF      string `json:"ptf,omitempty"`
}

type InterimFix struct {
	Label string   `json:"label"`
	State string   `json:"state,omitempty"`
	APARs []string `json:"apars,omitempty"`
}

type OracleHome struct {
	Path                    string     `json:"path"`
	EvidencePrefix          string     `json:"evidencePrefix,omitempty"`
	ReleaseUpdate           string     `json:"releaseUpdate,omitempty"`
	DatabaseVersion         string     `json:"databaseVersion,omitempty"`
	GridVersion             string     `json:"gridVersion,omitempty"`
	DatabaseRelease         string     `json:"databaseRelease,omitempty"`
	GridRelease             string     `json:"gridRelease,omitempty"`
	PatchIDs                []string   `json:"patchIds"`
	ListenerInstalled       bool       `json:"listenerInstalled"`
	ListenerVersion         string     `json:"listenerVersion,omitempty"`
	ListenerVersionSource   string     `json:"listenerVersionSource,omitempty"`
	ListenerReleaseBasis    string     `json:"listenerReleaseBasis,omitempty"`
	ListenerReleasePatchIDs []string   `json:"listenerReleasePatchIds,omitempty"`
	SQLPatches              []SQLPatch `json:"sqlPatchHistory,omitempty"`
	releaseConflict         bool
}

type SQLPatch struct {
	DatabaseID string `json:"databaseId"`
	PatchID    string `json:"patchId"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	ActionTime string `json:"actionTime"`
}

var sources = []string{"oslevel.txt", "lslpp.txt", "emgr.txt", "oracle-home.txt", "opatch.txt", "listener.txt", "sqlpatch.csv"}

type captureManifest struct {
	statuses map[string]string
	homes    []string
}

func Load(ctx context.Context, directory string) (Inventory, error) {
	inventory := Inventory{Filesets: []Fileset{}, InterimFixes: []InterimFix{}, OracleHomes: []OracleHome{}, EvidenceSHA256: map[string]string{}, Issues: []model.Issue{}}
	if err := ctx.Err(); err != nil {
		return inventory, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return inventory, errors.New("could not open AIX evidence directory")
	}
	defer root.Close()
	manifest, err := readEvidence(root, "capture.tsv", 4096)
	if err != nil {
		return inventory, errors.New("could not read AIX capture manifest")
	}
	capture, err := parseManifest(manifest)
	if err != nil {
		return inventory, err
	}
	addIssue := func(source, code, message string) {
		inventory.Issues = append(inventory.Issues, model.Issue{Collector: "aix-evidence", Status: "incomplete", Path: source, Code: code, Message: message})
	}
	inventory.EvidenceSHA256["capture.tsv"] = digest(manifest)
	input := loadSources(ctx, root, "", sources[:3], capture.statuses, inventory.EvidenceSHA256, addIssue)
	if raw, ok := input["oslevel.txt"]; ok {
		level := strings.TrimSpace(string(raw))
		if osLevelPattern.MatchString(level) {
			inventory.OSLevel = level
		} else {
			addIssue("oslevel.txt", "aix_oslevel_invalid", "unrecognized AIX service level")
		}
	}
	if raw, ok := input["lslpp.txt"]; ok {
		filesets, err := parseFilesets(raw)
		inventory.Filesets = filesets
		if err != nil {
			addIssue("lslpp.txt", "aix_filesets_partial", "some AIX fileset rows could not be interpreted")
		}
	}
	if raw, ok := input["emgr.txt"]; ok {
		fixes, err := parseFixes(raw)
		inventory.InterimFixes = fixes
		if err != nil {
			addIssue("emgr.txt", "aix_fixes_partial", "some interim fix evidence could not be interpreted")
		}
	}
	seenHomes := map[string]bool{}
	for _, prefix := range capture.homes {
		if err := ctx.Err(); err != nil {
			return inventory, err
		}
		input := loadHomeSources(ctx, root, prefix, capture.statuses, inventory.EvidenceSHA256, addIssue)
		if input == nil {
			continue
		}
		homePath := strings.TrimRight(string(input["oracle-home.txt"]), "\r\n")
		if homePath != "" {
			if seenHomes[homePath] {
				return Inventory{}, errors.New("duplicate Oracle Home in AIX capture")
			}
			seenHomes[homePath] = true
		}
		if home, ok := loadOracleHome(prefix, homePath, input, capture.statuses, addIssue); ok {
			inventory.OracleHomes = append(inventory.OracleHomes, home)
		}
	}
	return inventory, ctx.Err()
}

type issueReporter func(source, code, message string)

func loadSources(ctx context.Context, root *os.Root, prefix string, names []string, statuses, digests map[string]string, addIssue issueReporter) map[string][]byte {
	input := make(map[string][]byte)
	for _, source := range names {
		if ctx.Err() != nil {
			break
		}
		location := path.Join(prefix, source)
		switch statuses[location] {
		case "omitted":
			continue
		case "failed":
			addIssue(location, "aix_capture_failed", "evidence source did not complete")
			continue
		}
		limit := int64(maxSourceBytes)
		switch source {
		case "oslevel.txt", "listener.txt":
			limit = 256
		case "oracle-home.txt":
			limit = 4097
		}
		data, err := readEvidence(root, source, limit)
		if err != nil {
			addIssue(location, "aix_evidence_unreadable", "evidence is missing, nonregular, or exceeds its size limit")
			continue
		}
		digests[location] = digest(data)
		input[source] = data
	}
	return input
}

func loadHomeSources(ctx context.Context, root *os.Root, prefix string, statuses, digests map[string]string, addIssue issueReporter) map[string][]byte {
	if prefix == "" {
		return loadSources(ctx, root, prefix, sources[3:], statuses, digests, addIssue)
	}
	parents, err := openEvidenceDirectory(root, "homes")
	if err == nil {
		defer parents.Close()
		var home *os.Root
		home, err = openEvidenceDirectory(parents, path.Base(prefix))
		if err == nil {
			defer home.Close()
			return loadSources(ctx, home, prefix, sources[3:], statuses, digests, addIssue)
		}
	}
	addIssue(prefix, "aix_home_evidence_unreadable", "Oracle Home evidence directory is missing, changed or is a symbolic link")
	return nil
}

func openEvidenceDirectory(root *os.Root, name string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.IsDir() {
		return nil, errors.New("invalid evidence directory")
	}
	dir, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := dir.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		dir.Close()
		return nil, errors.New("evidence directory changed during open")
	}
	return dir, nil
}

func loadOracleHome(prefix, homePath string, input map[string][]byte, statuses map[string]string, report issueReporter) (OracleHome, bool) {
	addIssue := func(name, code, message string) {
		report(path.Join(prefix, name), code, message)
	}
	home, err := parseOracle(homePath, input["opatch.txt"])
	if err != nil {
		addIssue("opatch.txt", "oracle_inventory_unverified", "a successful OPatch inventory for the selected Oracle Home was not established")
		return home, false
	}
	home.EvidencePrefix = prefix
	if home.releaseConflict {
		addIssue("opatch.txt", "oracle_ru_conflict", "conflicting Oracle Database or Grid release updates were reported for the same Home")
	}
	if home.DatabaseVersion == "" && home.GridVersion == "" {
		addIssue("opatch.txt", "oracle_ru_unknown", "Oracle Database or Grid Infrastructure release update was not established")
	}
	if raw, ok := input["listener.txt"]; ok {
		present, err := parseListener(raw)
		if err != nil {
			addIssue("listener.txt", "oracle_listener_unverified", "selected Home Listener executable evidence could not be validated")
		} else if present {
			home.ListenerInstalled = true
			home.ListenerVersion = listenerVersion(home)
			if home.ListenerVersion == "" {
				addIssue("listener.txt", "oracle_listener_version_unknown", "Listener executable was observed but the Home release could not identify its version")
			} else {
				home.ListenerVersionSource = "opatch_inventory_ru"
			}
		}
	}
	if !home.ListenerInstalled {
		home.ListenerReleaseBasis = ""
		home.ListenerReleasePatchIDs = nil
	}
	if statuses[path.Join(prefix, "sqlpatch.csv")] == "omitted" && home.DatabaseVersion != "" {
		addIssue("sqlpatch.csv", "oracle_sqlpatch_not_provided", "SQL patch history was not provided for the selected Database Home")
	}
	if raw, ok := input["sqlpatch.csv"]; ok {
		rows, err := parseSQLPatches(raw)
		home.SQLPatches = rows
		if err != nil {
			addIssue("sqlpatch.csv", "oracle_sqlpatch_partial", "some DBA SQL patch rows could not be interpreted")
		}
	}
	return home, true
}

func readEvidence(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid evidence file")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("evidence file changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit || bytes.ContainsRune(raw, '\x00') {
		return nil, errors.New("invalid evidence contents")
	}
	return raw, nil
}

func parseManifest(raw []byte) (captureManifest, error) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	capture := captureManifest{statuses: make(map[string]string)}
	invalid := errors.New("invalid AIX capture manifest")
	switch strings.TrimSuffix(lines[0], "\r") {
	case Schema:
		if len(lines) != len(sources)+1 {
			return capture, invalid
		}
		if err := parseSourceStatuses(lines[1:], "", sources, capture.statuses); err != nil {
			return capture, err
		}
		if capture.statuses["oracle-home.txt"] != "omitted" {
			capture.homes = []string{""}
		}
	case SchemaMulti:
		if len(lines) <= 4 || (len(lines)-4)%4 != 0 || (len(lines)-4)/4 > maxOracleHomes {
			return capture, invalid
		}
		if err := parseSourceStatuses(lines[1:4], "", sources[:3], capture.statuses); err != nil {
			return capture, err
		}
		for start, i := 4, 1; start < len(lines); start, i = start+4, i+1 {
			prefix := fmt.Sprintf("homes/%d", i)
			if err := parseSourceStatuses(lines[start:start+4], prefix, sources[3:], capture.statuses); err != nil {
				return capture, err
			}
			if capture.statuses[path.Join(prefix, "oracle-home.txt")] != "ok" {
				return capture, invalid
			}
			capture.homes = append(capture.homes, prefix)
		}
	default:
		return capture, invalid
	}
	return capture, nil
}

func parseSourceStatuses(lines []string, prefix string, names []string, statuses map[string]string) error {
	for i, source := range names {
		location := path.Join(prefix, source)
		name, state, ok := strings.Cut(strings.TrimSuffix(lines[i], "\r"), "\t")
		if !ok || name != location || (state != "ok" && state != "failed" && state != "omitted") {
			return errors.New("invalid AIX capture source status")
		}
		switch source {
		case "oslevel.txt", "lslpp.txt", "emgr.txt":
			if state == "omitted" {
				return errors.New("inconsistent AIX capture source status")
			}
		case "opatch.txt", "listener.txt", "sqlpatch.csv":
			home := statuses[path.Join(prefix, "oracle-home.txt")]
			if (home == "omitted" && state != "omitted") || (source != "sqlpatch.csv" && home == "ok" && state == "omitted") {
				return errors.New("inconsistent AIX capture source status")
			}
		}
		statuses[location] = state
	}
	return nil
}

func digest(raw []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func scanner(raw []byte) *bufio.Scanner {
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 256<<10)
	return s
}

var (
	osLevelPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$`)
	inventoryToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~%-]{0,127}$`)
	versionToken   = regexp.MustCompile(`^[0-9][A-Za-z0-9._+~%-]{0,127}$`)
	fixRow         = regexp.MustCompile(`^\s*[0-9]+\s+([A-Z]{1,4})\s+([A-Za-z0-9._+-]{1,128})(?:\s|$)`)
	fixState       = regexp.MustCompile(`^[A-Z][A-Z +_-]{0,63}$`)
	aparToken      = regexp.MustCompile(`^[A-Z]{2}[0-9]{5,9}$`)
)

func parseFilesets(raw []byte) ([]Fileset, error) {
	items := []Fileset{}
	seen := map[Fileset]bool{}
	s := scanner(raw)
	invalid := false
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		row := strings.SplitN(line, ":", 8)
		if len(row) < 8 {
			invalid = true
			continue
		}
		for i := 1; i <= 6; i++ {
			row[i] = strings.TrimSpace(row[i])
		}
		if !inventoryToken.MatchString(row[1]) || !versionToken.MatchString(row[2]) {
			invalid = true
			continue
		}
		for _, i := range []int{3, 4, 5, 6} {
			if row[i] != "" && !inventoryToken.MatchString(row[i]) {
				row[i] = ""
				invalid = true
			}
		}
		item := Fileset{Name: row[1], Version: row[2], State: row[3], PTF: row[4], FixState: row[5], Type: row[6]}
		if !seen[item] {
			if len(items) >= maxRecords {
				invalid = true
				break
			}
			seen[item] = true
			items = append(items, item)
		}
	}
	if s.Err() != nil || invalid || len(items) == 0 {
		return items, errors.New("incomplete AIX fileset rows")
	}
	return items, nil
}

func parseFixes(raw []byte) ([]InterimFix, error) {
	items := []InterimFix{}
	byLabel := map[string]int{}
	current := -1
	noFixes := false
	invalid := false
	s := scanner(raw)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		lower := strings.ToLower(line)
		if lower == "there is no efix data on this system." {
			noFixes = true
			continue
		}
		if match := fixRow.FindStringSubmatch(line); match != nil {
			if len(items) >= maxRecords {
				return items, errors.New("interim fix limit exceeded")
			}
			if _, ok := byLabel[match[2]]; ok {
				invalid = true
				continue
			}
			byLabel[match[2]] = len(items)
			items = append(items, InterimFix{Label: match[2], State: match[1]})
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "EFIX LABEL":
			current = -1
			if !inventoryToken.MatchString(value) {
				invalid = true
				continue
			}
			if idx, ok := byLabel[value]; ok {
				current = idx
				continue
			}
			if len(items) >= maxRecords {
				return items, errors.New("interim fix limit exceeded")
			}
			current = len(items)
			byLabel[value] = current
			items = append(items, InterimFix{Label: value})
		case "EFIX STATE", "STATE":
			if current >= 0 && items[current].State == "" && fixState.MatchString(value) {
				items[current].State = value
			}
		case "APAR NUMBER":
			if current >= 0 && aparToken.MatchString(value) {
				items[current].APARs = append(items[current].APARs, value)
			} else {
				invalid = true
			}
		}
	}
	if s.Err() != nil || invalid || (len(items) == 0 && !noFixes) || (len(items) > 0 && noFixes) {
		return items, errors.New("incomplete AIX interim fix evidence")
	}
	return items, nil
}

func parseListener(raw []byte) (bool, error) {
	value := strings.TrimSpace(string(raw))
	if value == "absent" {
		return false, nil
	}
	bytes, err := hex.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil || len(bytes) < 20 || len(bytes) > 24 {
		return false, errors.New("invalid Listener header")
	}
	// IBM XCOFF32 / XCOFF64, nonempty section table, auxiliary header and F_EXEC.
	validMagic := bytes[0] == 0x01 && (bytes[1] == 0xdf || (bytes[1] == 0xf7 && len(bytes) == 24))
	if !validMagic || (bytes[2] == 0 && bytes[3] == 0) ||
		(bytes[16] == 0 && bytes[17] == 0) || bytes[19]&2 == 0 {
		return false, errors.New("unrecognized Listener executable format")
	}
	return true, nil
}
