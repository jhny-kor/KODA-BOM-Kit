package aixevidence

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	appliedPatch = regexp.MustCompile(`(?i)^patch\s+([0-9]{4,12})\s*:\s*applied on\s+\S`)
	databaseRU   = regexp.MustCompile(`(?i)^(?:oracle )?database release update\s*:?\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:\s|\(|$)`)
	gridRU       = regexp.MustCompile(`(?i)^(?:oracle )?(?:gi|grid infrastructure(?: [a-z]{3} [0-9]{4})?) release update\s*:?\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:\s|\(|$)`)
	patchID      = regexp.MustCompile(`^[0-9]{4,12}$`)
	patchCount   = regexp.MustCompile(`(?i)^interim patches\s*\(([0-9]+)\)\s*:`)
)

func parseOracle(homePath string, raw []byte) (OracleHome, error) {
	home := OracleHome{PatchIDs: []string{}}
	if len(homePath) <= 1 || len(homePath) > 4096 || !path.IsAbs(homePath) ||
		path.Clean(homePath) != homePath || strings.ContainsAny(homePath, "\r\n\t") {
		return home, errors.New("invalid selected Oracle Home")
	}
	home.Path = "oracle-home/" + digest([]byte(homePath))
	s := scanner(raw)
	reportHome := ""
	lastLine := ""
	patches := map[string]bool{}
	currentPatch := ""
	databaseRUs := map[string][]string{}
	gridRUs := map[string][]string{}
	declaredPatchCount := -1
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		lastLine = line
		key, value, _ := strings.Cut(line, ":")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "oracle home":
			candidate := strings.TrimSpace(value)
			if reportHome != "" && reportHome != candidate {
				return home, errors.New("multiple Oracle Homes in OPatch report")
			}
			reportHome = candidate
		case "patch description":
			if currentPatch == "" {
				continue
			}
			desc := strings.Trim(strings.TrimSpace(value), "\"")
			for _, candidate := range []struct {
				pattern  *regexp.Regexp
				versions map[string][]string
			}{{databaseRU, databaseRUs}, {gridRU, gridRUs}} {
				if match := candidate.pattern.FindStringSubmatch(desc); match != nil {
					candidate.versions[match[1]] = append(candidate.versions[match[1]], currentPatch)
				}
			}
			currentPatch = ""
		default:
			if match := patchCount.FindStringSubmatch(line); match != nil {
				count, err := strconv.Atoi(match[1])
				if err != nil || count > maxRecords || (declaredPatchCount >= 0 && declaredPatchCount != count) {
					return home, errors.New("invalid Oracle patch count")
				}
				declaredPatchCount = count
			} else if strings.EqualFold(line, "There are no Interim patches installed in this Oracle Home.") {
				if declaredPatchCount > 0 {
					return home, errors.New("conflicting Oracle patch count")
				}
				declaredPatchCount = 0
			}
			if match := appliedPatch.FindStringSubmatch(line); match != nil {
				if len(patches) >= maxRecords || declaredPatchCount < 0 || patches[match[1]] {
					return home, errors.New("invalid Oracle patch record")
				}
				currentPatch = match[1]
				patches[currentPatch] = true
			}
		}
	}
	if s.Err() != nil || reportHome != homePath || !strings.EqualFold(lastLine, "OPatch succeeded.") || declaredPatchCount != len(patches) {
		return home, errors.New("incomplete Oracle patch inventory")
	}
	for id := range patches {
		home.PatchIDs = append(home.PatchIDs, id)
	}
	sort.Strings(home.PatchIDs)
	home.DatabaseRelease, home.DatabaseVersion = singleRelease(databaseRUs)
	home.GridRelease, home.GridVersion = singleRelease(gridRUs)
	home.releaseConflict = len(databaseRUs) > 1 || len(gridRUs) > 1 ||
		(home.DatabaseRelease != "" && home.GridRelease != "" && home.DatabaseRelease != home.GridRelease)
	switch {
	case home.DatabaseRelease != "" && (home.GridRelease == "" || home.GridRelease == home.DatabaseRelease):
		home.ReleaseUpdate = home.DatabaseRelease
	case home.DatabaseRelease == "":
		home.ReleaseUpdate = home.GridRelease
	}
	if !home.releaseConflict {
		home.selectListenerRelease(databaseRUs[home.DatabaseRelease], gridRUs[home.GridRelease])
	}
	return home, nil
}

func (home *OracleHome) selectListenerRelease(databasePatchIDs, gridPatchIDs []string) {
	switch {
	case len(databasePatchIDs) > 0 && len(gridPatchIDs) > 0:
		home.ListenerReleaseBasis = "database_and_grid_ru"
	case len(databasePatchIDs) > 0:
		home.ListenerReleaseBasis = "database_ru"
	case len(gridPatchIDs) > 0:
		home.ListenerReleaseBasis = "grid_ru"
	default:
		return
	}
	home.ListenerReleasePatchIDs = append(append([]string{}, databasePatchIDs...), gridPatchIDs...)
	sort.Strings(home.ListenerReleasePatchIDs)
}

func singleRelease(versions map[string][]string) (release, version string) {
	if len(versions) != 1 {
		return "", ""
	}
	for raw := range versions {
		parts := strings.Split(raw, ".")
		if parts[0] == "19" && parts[2] == "0" && parts[3] == "0" && len(parts[4]) == 6 {
			// Preserve OPatch's dated build and emit its equivalent RU version.
			parts[4] = "0"
		}
		return raw, strings.Join(parts, ".")
	}
	return "", ""
}

func listenerVersion(home OracleHome) string {
	switch home.ListenerReleaseBasis {
	case "database_ru", "database_and_grid_ru":
		return home.DatabaseVersion
	case "grid_ru":
		return home.GridVersion
	default:
		return ""
	}
}

func parseSQLPatches(raw []byte) ([]SQLPatch, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = 5
	var items []SQLPatch
	header, err := r.Read()
	if err != nil || strings.ToLower(strings.Join(header, ",")) != "database_id,patch_id,action,status,action_time" {
		return nil, errors.New("unexpected SQL patch CSV header")
	}
	invalid := false
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			invalid = true
			break
		}
		if len(items) >= maxRecords {
			invalid = true
			break
		}
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
		}
		action, status := strings.ToUpper(row[2]), strings.ToUpper(row[3])
		if !inventoryToken.MatchString(row[0]) || !patchID.MatchString(row[1]) ||
			(action != "APPLY" && action != "ROLLBACK") ||
			(status != "SUCCESS" && status != "WITH ERRORS") || !validPatchTime(row[4]) {
			invalid = true
			continue
		}
		items = append(items, SQLPatch{DatabaseID: digest([]byte(row[0])), PatchID: row[1], Action: action, Status: status, ActionTime: row[4]})
	}
	if invalid {
		return items, errors.New("incomplete DBA patch CSV rows")
	}
	return items, nil
}

func validPatchTime(value string) bool {
	// Oracle ACTION_TIME is a timestamp without a timezone.
	_, err := time.Parse("2006-01-02T15:04:05", value)
	if err == nil {
		return true
	}
	_, err = time.Parse(time.RFC3339Nano, value)
	return err == nil
}
