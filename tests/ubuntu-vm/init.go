//go:build ignore

// ubuntu-vm-init is a test-only PID 1 harness, never a target-server deliverable.
// Build explicitly with GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build init.go.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const maxExportBytes int64 = 256 << 20
const maxBaselineFile int64 = 1 << 20
const maxModuleBytes int64 = 16 << 20

type baseline struct {
	Schema               string            `json:"schema"`
	StartedAt            string            `json:"startedAt"`
	FinishedAt           string            `json:"finishedAt"`
	UnameRelease         string            `json:"unameRelease"`
	UnameMachine         string            `json:"unameMachine"`
	ProcRelease          string            `json:"procRelease"`
	Hostname             string            `json:"hostname"`
	OSRelease            map[string]string `json:"osRelease"`
	KernelCommandLine    string            `json:"kernelCommandLine"`
	LoadedModulesBefore  []string          `json:"loadedModulesBefore"`
	LoadedModulesAfter   []string          `json:"loadedModulesAfter"`
	ModulePath           string            `json:"modulePath,omitempty"`
	ModuleSHA256         string            `json:"moduleSha256,omitempty"`
	ModuleLoadState      string            `json:"moduleLoadState"`
	ModuleLoadError      string            `json:"moduleLoadError,omitempty"`
	BinarySHA256         string            `json:"binarySha256"`
	ScanDurationSeconds  float64           `json:"scanDurationSeconds"`
	ScanPeakRSSKiB       int64             `json:"scanPeakRssKiB"`
	ScanUserCPUSeconds   float64           `json:"scanUserCpuSeconds"`
	ScanSystemCPUSeconds float64           `json:"scanSystemCpuSeconds"`
	ScanExitCode         int               `json:"scanExitCode"`
	ScanError            string            `json:"scanError,omitempty"`
	ScanTimedOut         bool              `json:"scanTimedOut"`
	ResultDirectories    []string          `json:"resultDirectories"`
	Issues               []string          `json:"issues"`
	ExportError          string            `json:"exportError,omitempty"`
}

type cappedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		take := n
		if take > remaining {
			take = remaining
		}
		b.data = append(b.data, p[:take]...)
	}
	if n > remaining {
		b.truncated = true
	}
	return n, nil
}
func limitedRead(p string, max int64) ([]byte, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, errors.New("bounded file read exceeded")
	}
	return b, nil
}
func readText(p string) string {
	b, _ := limitedRead(p, maxBaselineFile)
	return strings.TrimSpace(string(b))
}
func digestFile(p string) (string, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 256<<20)); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func uString(a []int8) string {
	b := make([]byte, 0, len(a))
	for _, v := range a {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
func modules() []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(readText("/proc/modules"), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 {
			seen[f[0]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func release() map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(readText("/etc/os-release"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ID", "ID_LIKE", "VERSION_ID", "VERSION", "NAME", "PRETTY_NAME", "VARIANT_ID":
			out[k] = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return out
}
func mount(p, kind, source, options string, flags uintptr, b *baseline) {
	if e := os.MkdirAll(p, 0755); e != nil {
		b.Issues = append(b.Issues, "mkdir "+p+": "+e.Error())
		return
	}
	if e := syscall.Mount(source, p, kind, flags, options); e != nil && e != syscall.EBUSY {
		b.Issues = append(b.Issues, "mount "+p+": "+e.Error())
	}
}
func initModule(b *baseline) {
	b.ModulePath = "/vm-test/modules/" + b.UnameRelease + "/dummy.ko"
	data, e := limitedRead(b.ModulePath, maxModuleBytes)
	if os.IsNotExist(e) {
		b.ModuleLoadState = "not-supplied"
		b.ModulePath = ""
		return
	}
	if e != nil {
		b.ModuleLoadState = "failed"
		b.ModuleLoadError = e.Error()
		return
	}
	sum := sha256.Sum256(data)
	b.ModuleSHA256 = hex.EncodeToString(sum[:])
	if len(data) == 0 {
		b.ModuleLoadState = "failed"
		b.ModuleLoadError = "empty module"
		return
	}
	params, _ := syscall.BytePtrFromString("")
	_, _, errno := syscall.Syscall(syscall.SYS_INIT_MODULE, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(params)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(params)
	if errno != 0 {
		if errno == syscall.EEXIST {
			b.ModuleLoadState = "already-loaded"
		} else {
			b.ModuleLoadState = "failed"
			b.ModuleLoadError = errno.Error()
		}
		return
	}
	b.ModuleLoadState = "loaded"
}
func saveBaseline(b *baseline) {
	b.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	data, e := json.MarshalIndent(b, "", "  ")
	if e == nil {
		e = os.WriteFile("/results/baseline.json", append(data, '\n'), 0600)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "KODA_VM_BASELINE_WRITE_ERROR", e)
	}
}
func exportFiles() ([]string, error) {
	var files []string
	var size int64
	e := filepath.WalkDir("/results", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("nonregular result rejected")
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		if info.Size() < 0 || info.Size() > maxExportBytes-size {
			return errors.New("result archive exceeds 256 MiB uncompressed")
		}
		size += info.Size()
		files = append(files, p)
		if len(files) > 10000 {
			return errors.New("result archive entry limit exceeded")
		}
		return nil
	})
	sort.Strings(files)
	return files, e
}
func exportResults(b *baseline) {
	saveBaseline(b)
	files, e := exportFiles()
	if e != nil {
		b.ExportError = e.Error()
		saveBaseline(b)
		files = []string{"/results/baseline.json"}
	}
	// Markers delimit one base64(gzip(tar)) stream. Logs and progress stay outside.
	fmt.Fprintln(os.Stdout, "KODA_VM_RESULT_BEGIN")
	encoded := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	gz := gzip.NewWriter(encoded)
	archive := tar.NewWriter(gz)
	for _, p := range files {
		info, e := os.Lstat(p)
		if e != nil || !info.Mode().IsRegular() {
			continue
		}
		rel, e := filepath.Rel("/results", p)
		if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0600, Size: info.Size(), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}
		if e = archive.WriteHeader(h); e != nil {
			break
		}
		f, e := os.Open(p)
		if e != nil {
			break
		}
		_, e = io.CopyN(archive, f, info.Size())
		f.Close()
		if e != nil {
			break
		}
	}
	archive.Close()
	gz.Close()
	encoded.Close()
	fmt.Fprintln(os.Stdout, "\nKODA_VM_RESULT_END")
}
func poweroff() {
	syscall.Sync()
	if e := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); e != nil {
		fmt.Fprintln(os.Stderr, "KODA_VM_POWEROFF_ERROR", e)
	}
	for {
		time.Sleep(time.Hour)
	}
}
func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "ubuntu-vm-init must run only as VM PID 1")
		return
	}
	b := baseline{Schema: "koda-sbom-ubuntu-vm-baseline-v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ScanExitCode: -1, ModuleLoadState: "not-attempted", Issues: []string{}, ResultDirectories: []string{}}
	defer func() {
		if p := recover(); p != nil {
			b.Issues = append(b.Issues, fmt.Sprintf("harness panic: %v", p))
		}
		exportResults(&b)
		poweroff()
	}()
	mount("/proc", "proc", "proc", "", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, &b)
	mount("/sys", "sysfs", "sysfs", "", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, &b)
	mount("/dev", "devtmpfs", "devtmpfs", "mode=0755", syscall.MS_NOSUID, &b)
	// Direct initramfs boots may start without valid standard descriptors if
	// /dev/console was absent in the cpio. Reconnect after devtmpfs is mounted.
	if console, e := os.OpenFile("/dev/console", os.O_RDWR, 0); e == nil {
		for _, fd := range []int{0, 1, 2} {
			if e = syscall.Dup2(int(console.Fd()), fd); e != nil {
				b.Issues = append(b.Issues, "console descriptor reconnect failed")
			}
		}
		if int(console.Fd()) > 2 {
			console.Close()
		}
	} else {
		b.Issues = append(b.Issues, "console unavailable: "+e.Error())
	}
	mount("/tmp", "tmpfs", "tmpfs", "mode=1777,size=512m", syscall.MS_NOSUID|syscall.MS_NODEV, &b)
	mount("/results", "tmpfs", "tmpfs", "mode=0700,size=512m", syscall.MS_NOSUID|syscall.MS_NODEV, &b)
	if e := syscall.Sethostname([]byte("koda-ubuntu24041-validation")); e != nil {
		b.Issues = append(b.Issues, "synthetic hostname failed")
	}
	b.Hostname, _ = os.Hostname()
	var uts syscall.Utsname
	if e := syscall.Uname(&uts); e != nil {
		b.Issues = append(b.Issues, "uname failed: "+e.Error())
	} else {
		b.UnameRelease = uString(uts.Release[:])
		b.UnameMachine = uString(uts.Machine[:])
	}
	b.ProcRelease = readText("/proc/sys/kernel/osrelease")
	b.OSRelease = release()
	b.KernelCommandLine = readText("/proc/cmdline")
	b.LoadedModulesBefore = modules()
	initModule(&b)
	b.LoadedModulesAfter = modules()
	if sha, e := digestFile("/koda-sbom"); e == nil {
		b.BinarySHA256 = sha
	} else {
		b.Issues = append(b.Issues, "collector digest failed: "+e.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/koda-sbom", "scan", "--output-dir", "/results", "--timeout", "0", "--max-files", "0", "--exclude", "/vm-test/**", "--exclude", "/init", "--exclude", "/koda-sbom")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TMPDIR=/tmp", "LANG=C", "TZ=UTC"}
	stdout, stderr := &cappedBuffer{limit: 1 << 20}, &cappedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	fmt.Fprintf(os.Stdout, "KODA_VM_SCAN_START kernel=%s binary=%s\n", b.UnameRelease, b.BinarySHA256)
	started := time.Now()
	err := cmd.Run()
	b.ScanDurationSeconds = time.Since(started).Seconds()
	if state := cmd.ProcessState; state != nil {
		b.ScanUserCPUSeconds = state.UserTime().Seconds()
		b.ScanSystemCPUSeconds = state.SystemTime().Seconds()
		if usage, ok := state.SysUsage().(*syscall.Rusage); ok {
			// Linux wait4 reports ru_maxrss in KiB for the collector child.
			b.ScanPeakRSSKiB = usage.Maxrss
		} else {
			b.Issues = append(b.Issues, "collector peak RSS unavailable")
		}
	}
	b.ScanTimedOut = ctx.Err() != nil
	if err == nil {
		b.ScanExitCode = 0
	} else if exit := new(exec.ExitError); errors.As(err, &exit) {
		b.ScanExitCode = exit.ExitCode()
		b.ScanError = "collector exited nonzero"
	} else {
		b.ScanError = err.Error()
	}
	if stdout.truncated {
		b.Issues = append(b.Issues, "collector stdout capped at 1 MiB")
	}
	if stderr.truncated {
		b.Issues = append(b.Issues, "collector stderr capped at 1 MiB")
	}
	if e := os.WriteFile("/results/collector.stdout.log", stdout.data, 0600); e != nil {
		b.Issues = append(b.Issues, "stdout write failed")
	}
	if e := os.WriteFile("/results/collector.stderr.log", stderr.data, 0600); e != nil {
		b.Issues = append(b.Issues, "stderr write failed")
	}
	entries, e := os.ReadDir("/results")
	if e != nil {
		b.Issues = append(b.Issues, "result directory unreadable")
	} else {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "koda-sbom-") {
				b.ResultDirectories = append(b.ResultDirectories, entry.Name())
			}
		}
	}
	fmt.Fprintf(os.Stdout, "KODA_VM_SCAN_COMPLETE kernel=%s exit=%d seconds=%.3f\n", b.UnameRelease, b.ScanExitCode, b.ScanDurationSeconds)
}
