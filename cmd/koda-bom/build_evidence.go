package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"

	"koda.local/security-sbom-linux/internal/imagearchive"
	"koda.local/security-sbom-linux/internal/localfs"
	"koda.local/security-sbom-linux/internal/reconcile"
)

type buildEvidenceFlags struct {
	supplier, artifact string
	resolvedArtifact   string
	inventory          *reconcile.BuildInventory
	supplierSHA256     string
	plan               *localfs.Plan
	relative           string
}

func (b *buildEvidenceFlags) bind(flags *flag.FlagSet) {
	flags.StringVar(&b.supplier, "build-sbom", "", "declared build/supplier CycloneDX or SPDX JSON bound to --build-artifact SHA-256")
	flags.StringVar(&b.artifact, "build-artifact", "", "local artifact in the scan scope described by --build-sbom")
}

func (b *buildEvidenceFlags) validate(format string) error {
	if (b.supplier == "") != (b.artifact == "") {
		return errors.New("--build-sbom and --build-artifact must be supplied together")
	}
	if b.supplier != "" && format == "spdx" {
		return errors.New("build evidence requires CycloneDX output")
	}
	return nil
}

func (b *buildEvidenceFlags) load(ctx context.Context) error {
	if b.supplier == "" {
		return nil
	}
	input, size, err := openReconcileInput(b.supplier)
	if err != nil {
		return err
	}
	defer input.Close()
	if size > reconcile.MaxSupplierBytes {
		return reconcile.ErrSupplierSize
	}
	digest := sha256.New()
	inventory, err := reconcile.ReadBuildInventory(io.TeeReader(reconcileReader{ctx, input}, digest))
	if err != nil {
		return err
	}
	b.inventory = &inventory
	b.supplierSHA256 = hex.EncodeToString(digest.Sum(nil))
	b.resolvedArtifact, err = localfs.ResolveLocal(b.artifact)
	return err
}

// admit records the exact preflight scope that permits the artifact. The file
// is reopened through that plan when the declaration is emitted.
func (b *buildEvidenceFlags) admit(plan localfs.Plan) {
	if b.inventory == nil || !localfs.Within(plan.Root, b.resolvedArtifact) {
		return
	}
	relative, err := filepath.Rel(plan.Root, b.resolvedArtifact)
	if err != nil {
		return
	}
	relative = filepath.ToSlash(relative)
	if !slices.Contains(plan.Paths, relative) || plan.ExcludesPath(relative) {
		return
	}
	b.plan = &plan
	b.relative = relative
}

func (b *buildEvidenceFlags) write(ctx context.Context, dir, image string, identity *imagearchive.Identity, include17 bool) (err error) {
	if b.inventory == nil {
		return nil
	}
	digest := ""
	if image != "" {
		resolved, resolveErr := localfs.ResolveLocal(image)
		if resolveErr != nil || resolved != b.resolvedArtifact || identity == nil {
			return errors.New("build artifact must match the scanned image archive")
		}
		digest = identity.ArchiveSHA256
	} else {
		if b.plan == nil {
			return errors.New("build artifact is outside the admitted scan files or is excluded")
		}
		digest, err = b.artifactDigest(ctx)
		if err != nil {
			return err
		}
	}
	if digest != b.inventory.SHA256 {
		return errors.New("build artifact SHA-256 does not match the supplier SBOM subject")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	metadata := b.inventory.Document["metadata"].(map[string]any)
	props := metadata["properties"].([]map[string]string)
	metadata["properties"] = append(props, map[string]string{"name": "koda:build:source-sbom-sha256", "value": b.supplierSHA256}, map[string]string{"name": "koda:build:artifact-binding", "value": "sha256-matched"})
	names := []string{"build-sbom.cdx.json"}
	if include17 {
		names = append(names, "build-sbom.cdx-1.7.json")
	}
	written := []string{}
	defer func() {
		if err != nil {
			for _, name := range written {
				os.Remove(filepath.Join(dir, name))
			}
		}
	}()
	for _, name := range names {
		b.inventory.Document["specVersion"] = "1.6"
		if name == "build-sbom.cdx-1.7.json" {
			b.inventory.Document["specVersion"] = "1.7"
		}
		file, createErr := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return errors.New("build evidence output already exists or cannot be created")
		}
		written = append(written, name)
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		writeErr := encoder.Encode(b.inventory.Document)
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (b *buildEvidenceFlags) artifactDigest(ctx context.Context) (string, error) {
	root, err := b.plan.OpenRoot()
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, before, err := b.plan.OpenIndexedRegular(root, b.relative)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(reconcileReader{ctx, file}, before.Size()+1))
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.New("build artifact changed during digest verification")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
