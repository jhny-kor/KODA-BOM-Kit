package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"koda.local/security-sbom-linux/internal/evidencefile"
	"os"
	"runtime"
	"strings"

	"koda.local/security-sbom-linux/internal/hostcontext"
	"koda.local/security-sbom-linux/internal/localfs"
)

// Raw client output is consumed locally and never copied into the SBOM result.
func readLivepatchInput(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("expected a bounded regular report file")
	}
	resolved, err := localfs.ResolveLocal(filename)
	if err != nil {
		return nil, err
	}
	f, err := evidencefile.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("report changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("report read failed or exceeded limit")
	}
	return data, nil
}

func captureLivepatchEvidence(args []string) int {
	flags := flag.NewFlagSet("livepatch-evidence", flag.ContinueOnError)
	var provider, input, output, effectiveFile, queryStatus string
	flags.StringVar(&provider, "provider", "", "canonical-livepatch, ksplice or uptrack")
	flags.StringVar(&input, "input", "", "successful local status command output")
	flags.StringVar(&output, "output", "", "new sanitized evidence file")
	flags.StringVar(&effectiveFile, "effective-kernel-file", "", "successful uptrack-uname -r output")
	flags.StringVar(&queryStatus, "query-status", "", "not_installed, query_failed, query_timed_out or invalid_report")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (input == "" && queryStatus == "") || (input != "" && queryStatus != "") || output == "" || (provider != "canonical-livepatch" && provider != "ksplice" && provider != "uptrack") || (effectiveFile != "" && (provider != "uptrack" || queryStatus != "")) || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "livepatch-evidence requires Linux x86_64, a supported provider, input and new output")
		return 2
	}
	var raw []byte
	var err error
	if input != "" {
		raw, err = readLivepatchInput(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read bounded local client report")
			return 2
		}
	}
	effective := ""
	if effectiveFile != "" {
		data, err := readLivepatchInput(effectiveFile)
		if err != nil || len(data) > 256 {
			fmt.Fprintln(os.Stderr, "cannot read effective kernel report")
			return 2
		}
		effective = strings.TrimSpace(string(data))
	}
	var data []byte
	if queryStatus != "" {
		data, err = hostcontext.CaptureUnavailableLivepatchEvidence(provider, queryStatus)
	} else {
		data, err = hostcontext.CaptureLivepatchEvidence(provider, raw, effective)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "client status is not a recognized bounded report")
		return 2
	}
	out, err := localfs.ResolveLocal(output)
	if err != nil {
		return 2
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create new evidence file")
		return 2
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(out)
		return 2
	}
	fmt.Fprintln(os.Stdout, out)
	return 0
}
