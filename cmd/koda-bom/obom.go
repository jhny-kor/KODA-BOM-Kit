package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/deployment"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/obom"
)

type deploymentFlags struct {
	environment, id  string
	exports, network stringsFlag
}

func (o *deploymentFlags) bind(f *flag.FlagSet) {
	f.StringVar(&o.environment, "environment", "", "operator-supplied environment, e.g. staging")
	f.StringVar(&o.id, "deployment-id", "", "operator-supplied deployment identifier")
	f.Var(&o.network, "network-evidence", "local TCP connection observations for the same host or container (repeatable)")
	f.Var(&o.exports, "kubernetes-evidence", "local Kubernetes JSON export from the same cluster (repeatable)")
}
func (o deploymentFlags) set() bool {
	return o.environment != "" || o.id != "" || len(o.exports) > 0 || len(o.network) > 0
}
func (o deploymentFlags) load(ctx context.Context) (*deployment.Evidence, error) {
	e, err := deployment.Load(ctx, o.environment, o.id, o.exports)
	if err != nil || len(o.network) == 0 {
		return e, err
	}
	if e == nil {
		e = &deployment.Evidence{}
	}
	e.Network, err = deployment.LoadNetworkReports(ctx, o.network)
	return e, err
}

func replayOBOM(args []string) int {
	flags := flag.NewFlagSet("obom", flag.ContinueOnError)
	src := flags.String("collection", "", "existing KODA live-host collection directory")
	out := flags.String("output-dir", "", "parent directory for a new operations BOM")
	dual := flags.Bool("cyclonedx-17", false, cyclonedx17Help)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum replay duration, 0 disables the limit")
	var options deploymentFlags
	options.bind(flags)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *src == "" || *out == "" || *timeout < 0 || flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(parent, *timeout)
	defer cancel()
	dir, err := exportOBOM(ctx, *src, *out, *dual, options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "obom:", err)
		return 2
	}
	fmt.Println(dir)
	return 0
}

func exportOBOM(ctx context.Context, src, out string, dual bool, options deploymentFlags) (string, error) {
	src, err := localfs.ResolveLocal(src)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(src)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("source collection must be a readable local directory")
	}
	out, err = localfs.ResolveLocal(out)
	if err != nil {
		return "", err
	}
	if localfs.Within(src, out) {
		return "", fmt.Errorf("replay output must be outside the original collection")
	}
	deploy, err := options.load(ctx)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(out, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(out, ".koda-obom-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	if err = obom.Write(ctx, src, dir, dual, deploy); err != nil {
		return "", err
	}
	if err = collect.Checksums(dir); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	final := filepath.Join(out, filepath.Base(dir)[1:])
	if _, err = os.Lstat(final); !os.IsNotExist(err) {
		return "", fmt.Errorf("output path exists or cannot be verified")
	}
	if err = os.Rename(dir, final); err != nil {
		return "", err
	}
	return final, nil
}
