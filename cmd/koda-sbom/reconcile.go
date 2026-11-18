package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/reconcile"
	"koda.local/security-sbom-linux/internal/staticjs"
)

type reconciliationReport struct {
	Schema                 string                     `json:"schema"`
	ArtifactType           string                     `json:"artifactType"`
	ArtifactSHA256         string                     `json:"artifactSha256"`
	SupplierFormat         string                     `json:"supplierFormat"`
	SupplierSBOMSHA256     string                     `json:"supplierSbomSha256"`
	SupplierComponentCount int                        `json:"supplierComponentCount"`
	ObservedStatus         string                     `json:"observedStatus"`
	CollectionCoverage     collect.CollectionCoverage `json:"collectionCoverage"`
	Comparison             reconcile.Comparison       `json:"comparison"`
}

func reconcileDeployment(args []string) int {
	flags := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	artifact := flags.String("artifact", "", "local deployed WAR or EAR file")
	supplierFile := flags.String("supplier-sbom", "", "local supplier CycloneDX or SPDX JSON with subject SHA-256")
	output := flags.String("output-dir", "", "parent directory for new results")
	format := flags.String("format", "both", "both, cyclonedx, spdx")
	cyclonedx17 := flags.Bool("cyclonedx-17", false, cyclonedx17Help)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum total reconciliation time; 0 disables the time limit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	kind := strings.ToLower(filepath.Ext(*artifact))
	if flags.NArg() != 0 || (kind != ".war" && kind != ".ear") || *supplierFile == "" || *output == "" || *timeout < 0 ||
		(*format != "both" && *format != "cyclonedx" && *format != "spdx") {
		flags.Usage()
		return 2
	}
	if !validCycloneDXSelection(*format, *cyclonedx17) {
		return 2
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "reconcile requires Linux x86_64")
		return 2
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(parent, *timeout)
	defer cancel()
	fail := func(message string) int {
		if err := ctx.Err(); err != nil {
			message = failureIssue("reconciliation", err, err).Message
		}
		fmt.Fprintln(os.Stderr, "reconcile:", message)
		return 2
	}
	if ctx.Err() != nil {
		return fail("")
	}
	file, size, err := openReconcileInput(*supplierFile)
	if err != nil {
		return fail("supplier SBOM must be a readable local regular file")
	}
	if size > reconcile.MaxSupplierBytes {
		file.Close()
		return fail(reconcile.ErrSupplierSize.Error())
	}
	supplierHash := sha256.New()
	supplier, err := reconcile.ReadSupplier(io.TeeReader(reconcileReader{ctx, file}, supplierHash))
	file.Close()
	if err != nil {
		return fail(err.Error())
	}
	if ctx.Err() != nil {
		return fail("")
	}

	tmp, err := localfs.ResolveLocal(os.TempDir())
	if err != nil {
		return fail("cannot verify local temporary storage")
	}
	input, err := os.MkdirTemp(tmp, "koda-sbom-deployment-")
	if err != nil {
		return fail("cannot create private temporary storage")
	}
	defer os.RemoveAll(input)
	staged := filepath.Join(input, "deployment"+kind)
	if err := stageDeployment(ctx, *artifact, staged, supplier.SHA256); err != nil {
		return fail(err.Error())
	}
	if ctx.Err() != nil {
		return fail("")
	}
	out, err := localfs.ResolveLocal(*output)
	if err != nil || os.MkdirAll(out, 0700) != nil {
		return fail("cannot create local result parent")
	}
	out, err = localfs.ResolveLocal(out)
	if err != nil {
		return fail("cannot verify local result parent")
	}
	// Build in a private directory on the result filesystem; publish only after
	// the SBOMs, comparison and checksums all succeed.
	pending, err := os.MkdirTemp(out, ".koda-reconcile-")
	if err != nil {
		return fail("cannot stage reconciliation results")
	}
	defer os.RemoveAll(pending)
	var result string
	var unresolved bool
	scanArgs := []string{"--target", input, "--output-dir", pending, "--format", *format, "--timeout", timeout.String(), "--no-context"}
	if *cyclonedx17 {
		scanArgs = append(scanArgs, "--cyclonedx-17")
	}
	code := runScan(ctx, scanArgs,
		func(dir string, scanReport summary, coverage collect.CollectionCoverage, observed []reconcile.Component) error {
			comparison := reconcile.Compare(observed, supplier.Components)
			if err := ctx.Err(); err != nil {
				return err
			}
			data := reconciliationReport{
				Schema: "koda-sbom-reconciliation-v1", ArtifactType: kind[1:], ArtifactSHA256: supplier.SHA256,
				SupplierFormat: supplier.Format, SupplierSBOMSHA256: hex.EncodeToString(supplierHash.Sum(nil)),
				SupplierComponentCount: len(supplier.Components), ObservedStatus: scanReport.Status,
				CollectionCoverage: coverage, Comparison: comparison,
			}
			if err := collect.WriteJSON(dir, "reconcile.json", data); err != nil {
				return err
			}
			result, unresolved = dir, len(comparison.Unresolved) > 0
			return nil
		})
	if code == 2 || result == "" {
		return fail("collection or comparison did not complete; no result published")
	}
	if ctx.Err() != nil {
		return fail("")
	}
	name := "koda-sbom-reconcile-" + strings.TrimPrefix(filepath.Base(result), "koda-sbom-")
	final := filepath.Join(out, name)
	if _, err := os.Lstat(final); !os.IsNotExist(err) || os.Rename(result, final) != nil {
		return fail("cannot publish reconciliation results")
	}
	fmt.Println(final)
	if unresolved {
		return 3
	}
	return code
}

func openReconcileInput(filename string) (*os.File, int64, error) {
	resolved, err := localfs.ResolveLocal(filename)
	if err != nil {
		return nil, 0, err
	}
	f, err := evidencefile.Open(resolved)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, 0, errors.New("input is not a readable regular file")
	}
	return f, info.Size(), nil
}

func stageDeployment(ctx context.Context, path, staged, expected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, size, err := openReconcileInput(path)
	if err != nil {
		return errors.New("deployment must be a readable local regular file")
	}
	defer file.Close()
	if size <= 0 || size > staticjs.MaxArchiveBytes {
		return errors.New("deployment archive is empty or exceeds 512 MiB")
	}
	copyFile, err := os.OpenFile(staged, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create private deployment copy")
	}
	defer copyFile.Close()
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(copyFile, digest), io.LimitReader(reconcileReader{ctx, file}, staticjs.MaxArchiveBytes+1))
	if err != nil || n != size || n > staticjs.MaxArchiveBytes {
		return errors.New("deployment file changed size or could not be copied")
	}
	if hex.EncodeToString(digest.Sum(nil)) != expected {
		return errors.New("deployment SHA-256 does not match the supplier SBOM subject")
	}
	if err := staticjs.ValidateDeploymentArchive(ctx, copyFile, n); err != nil {
		return errors.New("deployment ZIP directory is invalid, unsafe or exceeds inspection limits")
	}
	if err := copyFile.Chmod(0400); err != nil {
		return errors.New("cannot protect private deployment copy")
	}
	return nil
}

type reconcileReader struct {
	ctx context.Context
	io.Reader
}

func (r reconcileReader) Read(buf []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(buf)
}
