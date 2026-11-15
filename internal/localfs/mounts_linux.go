//go:build linux

package localfs

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func RemoteMounts() ([]string, error) {
	f, e := os.Open("/proc/self/mountinfo")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var paths []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), " - ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mount table")
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 1 {
			return nil, fmt.Errorf("invalid mount fields")
		}
		kind := right[0]
		deny := kind == "nfs" || kind == "nfs4" || kind == "cifs" || kind == "smb3" || kind == "9p" || kind == "ceph" || kind == "autofs" || kind == "proc" || kind == "sysfs" || kind == "devtmpfs" || kind == "devpts" || strings.HasPrefix(kind, "fuse")
		if deny {
			p := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\134", "\\").Replace(left[4])
			paths = append(paths, p)
		}
	}
	return paths, sc.Err()
}
