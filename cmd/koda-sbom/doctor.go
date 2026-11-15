package main

import (
	"encoding/json"
	"fmt"
	"koda.local/security-sbom-linux/internal/localfs"
	"os"
	"runtime"
	"strings"
)

func doctor() int {
	supported := runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
	kernel := kernelRelease()
	var major, minor int
	fmt.Sscanf(kernel, "%d.%d", &major, &minor)
	if major < 3 || (major == 3 && minor < 2) {
		supported = false
	}
	dbs := map[string]bool{}
	for _, p := range []string{"/var/lib/rpm/Packages", "/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/dpkg/status", "/lib/apk/db/installed"} {
		_, e := os.Stat(p)
		dbs[p] = e == nil
	}
	_, mountErr := localfs.RemoteMounts()
	if mountErr != nil {
		supported = false
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"tool": "koda-sbom", "version": version, "os": runtime.GOOS, "architecture": runtime.GOARCH, "kernel": kernel, "supported": supported, "packageDatabases": dbs, "note": "read permissions and metadata availability determine coverage; no CVE assessment", "kernelFlavor": func() string {
		if strings.Contains(kernel, "uek") {
			return "UEK"
		}
		return "unconfirmed"
	}()})
	if supported {
		return 0
	}
	return 2
}
