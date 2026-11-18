package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"koda.local/security-sbom-linux/internal/assessment"
)

func assessEvidence(args []string) int {
	flags := flag.NewFlagSet("assess", flag.ContinueOnError)
	sbom := flags.String("sbom", "", "collected CycloneDX or SPDX JSON")
	advisories := flags.String("advisories", "", "local advisory rules JSON, exact-version OSV or CSAF 2.0 JSON")
	contextFile := flags.String("context", "", "context.json from the same collection result")
	kev := flags.String("kev", "", "optional local CISA KEV JSON catalog")
	output := flags.String("output", "", "new assessment JSON path")
	timeout := flags.Duration("timeout", 5*time.Minute, "maximum assessment time")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *sbom == "" || *advisories == "" || *output == "" || *timeout < 0 {
		return 2
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(parent, *timeout)
	defer cancel()
	report, err := assessment.EvaluateFiles(ctx, *sbom, *advisories, *contextFile, *kev)
	if err == nil {
		err = writeNewJSON(*output, report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(*output)
	return 0
}

// Publish a complete report with no overwrite, even if concurrent runs use
// the same destination name.
func writeNewJSON(path string, v any) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".koda-assessment-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	e := json.NewEncoder(file)
	e.SetIndent("", "  ")
	encodeErr := e.Encode(v)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Link(file.Name(), path); err == nil {
		return nil
	}
	// Some removable filesystems do not support hard links. Exclusive creation
	// still prevents overwrites and concurrent writers to the same destination.
	staged, err := os.Open(file.Name())
	if err != nil {
		return err
	}
	defer staged.Close()
	destination, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, staged)
	closeErr = destination.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		if err != nil {
			return err
		}
		return closeErr
	}
	return nil
}
