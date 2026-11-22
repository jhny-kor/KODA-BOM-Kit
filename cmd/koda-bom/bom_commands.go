package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"koda.local/security-sbom-linux/internal/bomset"
	"koda.local/security-sbom-linux/internal/collect"
	"koda.local/security-sbom-linux/internal/domainbom"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/obom"
)

type domainFlags struct {
	saas, models, weights, provenance, products, modelDirs stringsFlag
}

func (d *domainFlags) bind(f *flag.FlagSet) {
	f.Var(&d.saas, "saas-evidence", "local OpenAPI 3 JSON or KODA service evidence (repeatable)")
	d.bindModels(f)
	f.Var(&d.provenance, "provenance", "local SLSA v1 build provenance or manufacturing workflow evidence (repeatable)")
	f.Var(&d.products, "provenance-artifact", "local build product for corresponding --provenance, use - for a physical product (repeatable)")
}

func (d *domainFlags) bindModels(f *flag.FlagSet) {
	f.Var(&d.models, "model-evidence", "model declaration for the corresponding --model-artifact (repeatable)")
	f.Var(&d.weights, "model-artifact", "local model artifact to hash in full (repeatable)")
}

func (d domainFlags) set() bool {
	return len(d.saas)+len(d.models)+len(d.weights)+len(d.provenance)+len(d.products)+len(d.modelDirs) > 0
}

func (d domainFlags) generate(ctx context.Context, dual bool) (map[string][]byte, error) {
	if !d.set() {
		return nil, nil
	}
	if len(d.models) > 0 && len(d.models) != len(d.weights) {
		return nil, errors.New("--model-evidence requires a corresponding --model-artifact for every declaration")
	}
	if len(d.products) > 0 && len(d.provenance) != len(d.products) {
		return nil, errors.New("--provenance and --provenance-artifact must be paired in order")
	}
	options := domainbom.Options{SaaS: d.saas, Include17: dual}
	for i, artifact := range d.weights {
		m := domainbom.ModelInput{Artifact: artifact}
		if len(d.models) > 0 && d.models[i] != "-" {
			m.Evidence = d.models[i]
		}
		options.Models = append(options.Models, m)
	}
	for i, source := range d.provenance {
		input := domainbom.ProvenanceInput{Evidence: source}
		if len(d.products) > 0 && d.products[i] != "-" {
			input.Artifact = d.products[i]
		}
		options.Provenance = append(options.Provenance, input)
	}
	return domainbom.Generate(ctx, options)
}

func writeDomainBOMs(dir string, documents map[string][]byte) (err error) {
	var written []string
	defer func() {
		if err != nil {
			for _, name := range written {
				os.Remove(filepath.Join(dir, name))
			}
		}
	}()
	for name, document := range documents {
		file, createErr := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return createErr
		}
		written = append(written, name)
		n, writeErr := file.Write(document)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if n != len(document) {
			return io.ErrShortWrite
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// Each offline command publishes a new directory only after all outputs and hashes exist.
func runBOMCommand(command string, args []string) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	out := flags.String("output-dir", "", "parent directory for new results")
	dual := flags.Bool("cyclonedx-17", false, cyclonedx17Help)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum duration, 0 disables the limit")
	var input string
	var domain domainFlags
	switch command {
	case "bom-split":
		flags.StringVar(&input, "collection", "", "existing KODA collection directory containing sbom.cdx.json")
	case "bom-merge":
		flags.StringVar(&input, "set", "", "directory containing bom-set.json and separate BOMs")
	case "ai-bom":
		domain.bindModels(flags)
		flags.Var(&domain.modelDirs, "model-dir", "inspect an installed local model directory (repeatable)")
	case "domain-bom":
		domain.bind(flags)
		flags.Var(&domain.modelDirs, "model-dir", "inspect a local model directory (repeatable)")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	evidenceCommand := command == "domain-bom" || command == "ai-bom"
	if *out == "" || *timeout < 0 || flags.NArg() != 0 || (evidenceCommand && !domain.set()) || (!evidenceCommand && input == "") {
		flags.Usage()
		return 2
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := scanContext(parent, *timeout)
	defer cancel()
	dir, err := publishBOMCommand(ctx, command, input, *out, *dual, domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, command+":", err)
		return 2
	}
	fmt.Println(dir)
	return 0
}

func publishBOMCommand(ctx context.Context, command, input, out string, dual bool, domain domainFlags) (string, error) {
	out, err := localfs.ResolveLocal(out)
	if err != nil {
		return "", err
	}
	if input != "" {
		input, err = localfs.ResolveLocal(input)
		if err != nil {
			return "", err
		}
		st, err := os.Stat(input)
		if err != nil || !st.IsDir() {
			return "", errors.New("source must be a readable local directory")
		}
		if localfs.Within(input, out) {
			return "", errors.New("output must be outside the source directory")
		}
	}
	if err = os.MkdirAll(out, 0700); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(out, ".koda-"+command+"-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	switch command {
	case "bom-split":
		err = splitArchivedBOMs(ctx, input, staging, dual)
	case "bom-merge":
		err = bomset.Merge(ctx, input, staging, dual)
	case "domain-bom", "ai-bom":
		var docs map[string][]byte
		docs, err = domain.generate(ctx, dual)
		if err == nil && len(domain.modelDirs) > 0 {
			var found []domainbom.ModelDiscovery
			for i, path := range domain.modelDirs {
				if i >= 12 {
					return "", errors.New("at most twelve model directories are supported")
				}
				plan, planErr := localfs.Build(ctx, path, nil)
				if planErr != nil {
					return "", planErr
				}
				if localfs.Within(plan.Root, staging) {
					return "", errors.New("model BOM output must be outside the inspected directory")
				}
				scope := ""
				if len(domain.modelDirs) > 1 {
					scope = fmt.Sprintf("target-%d", i+1)
				}
				observation, discoverErr := domainbom.DiscoverModels(ctx, plan, scope)
				if discoverErr != nil {
					return "", discoverErr
				}
				found = append(found, observation)
			}
			err = domainbom.AddDiscoveredModels(ctx, docs, found, dual)
			if err == nil && len(docs["aibom.cdx.json"]) == 0 {
				err = emptyDomainProfile(docs, "aibom", "no model identified in inspected paths", dual)
			}
		}
		if err == nil {
			err = writeDomainBOMs(staging, docs)
		}
	default:
		return "", errors.New("unknown BOM command")
	}
	if err != nil {
		return "", err
	}
	if err = collect.Checksums(staging); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	final := filepath.Join(out, filepath.Base(staging)[1:])
	if _, err = os.Lstat(final); !os.IsNotExist(err) {
		return "", errors.New("result path already exists or is inaccessible")
	}
	if err = os.Rename(staging, final); err != nil {
		return "", err
	}
	return final, nil
}

// Recover the OBOM for older live-host archives. Directory and image scans have no live graph.
func splitArchivedBOMs(ctx context.Context, input, staging string, dual bool) error {
	if _, err := os.Lstat(filepath.Join(input, "obom.cdx.json")); err == nil {
		return bomset.Split(ctx, input, staging, dual)
	} else if !os.IsNotExist(err) {
		return err
	}
	live, err := obom.ArchiveHasRuntime(input)
	if err != nil {
		return err
	}
	if !live {
		return bomset.Split(ctx, input, staging, dual)
	}
	operations, err := os.MkdirTemp(staging, ".operations-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(operations)
	if err = obom.Write(ctx, input, operations, dual); err != nil {
		return err
	}
	if err = collect.Checksums(operations); err != nil {
		return err
	}
	return bomset.Split(ctx, input, staging, dual, operations)
}

// Absence of inventory evidence leaves coverage unknown. Each domain receives a
// real, explicitly scoped CycloneDX document, even on hosts with no such evidence.
func completeDomainProfiles(docs map[string][]byte, dual bool) error {
	for _, p := range []struct{ kind, reason string }{
		{"aibom", "no model identified in admitted scan paths or supplied evidence"},
		{"saasbom", "no service inventory or OpenAPI evidence supplied"},
		{"mbom", "no manufacturing or build provenance supplied"},
	} {
		if _, exists := docs[p.kind+".cdx.json"]; !exists {
			if err := emptyDomainProfile(docs, p.kind, p.reason, dual); err != nil {
				return err
			}
		}
	}
	return nil
}

func emptyDomainProfile(docs map[string][]byte, kind, reason string, dual bool) error {
	props := []map[string]string{
		{"name": "koda:domain:kind", "value": kind}, {"name": "koda:domain:status", "value": "no-evidence"}, {"name": "koda:domain:coverage", "value": reason},
	}
	doc := map[string]any{"bomFormat": "CycloneDX", "version": 1, "metadata": map[string]any{"properties": props}, "compositions": []map[string]string{{"aggregate": "unknown"}}}
	versions := []string{"1.6"}
	if dual {
		versions = append(versions, "1.7")
	}
	for _, v := range versions {
		doc["specVersion"] = v
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		name := kind + ".cdx.json"
		if v == "1.7" {
			name = kind + ".cdx-1.7.json"
		}
		docs[name] = append(raw, '\n')
	}
	return nil
}

// Stage the split set, merged graph and extended checksum manifest together.
// Reuse the already verified hashes of the primary inventory, which may be multi-GB.
func splitScanBOMs(ctx context.Context, dir string, dual bool) (err error) {
	stage, err := os.MkdirTemp(dir, ".bom-products-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	set := filepath.Join(stage, "boms")
	if err = os.Mkdir(set, 0700); err != nil {
		return err
	}
	if err = bomset.Split(ctx, dir, set, dual); err != nil {
		return err
	}
	if err = collect.Checksums(set); err != nil {
		return err
	}
	if err = bomset.Merge(ctx, set, stage, dual); err != nil {
		return err
	}
	if err = collect.Checksums(stage); err != nil {
		return err
	}
	readSums := func(dir string) ([]string, error) {
		b, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		if err != nil {
			return nil, err
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n"), nil
	}
	existing, err := readSums(dir)
	if err != nil {
		return err
	}
	extra, err := readSums(stage)
	if err != nil {
		return err
	}
	lines := append(existing, extra...)
	sort.Strings(lines)
	sumFile := filepath.Join(stage, "root-checksums")
	if err = os.WriteFile(sumFile, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	names := []string{"boms", "bom.cdx.json"}
	if dual {
		names = append(names, "bom.cdx-1.7.json")
	}
	var published []string
	defer func() {
		if err != nil {
			for _, path := range published {
				os.RemoveAll(path)
			}
		}
	}()
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return err
		}
		target := filepath.Join(dir, name)
		if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
			return errors.New("BOM output already exists or is inaccessible")
		}
		if err = os.Rename(filepath.Join(stage, name), target); err != nil {
			return err
		}
		published = append(published, target)
	}
	return os.Rename(sumFile, filepath.Join(dir, "SHA256SUMS"))
}
