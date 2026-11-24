# KODA BOM Kit — Collection commands and output files

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Choose a scope

Run the executable on the live host to inventory the operating system, packages, containers and readable hardware. A directory scan inventories that tree. An image scan reads an exported Docker or OCI archive. Choose one input type per run. The defaults are one million regular files and 30 minutes. Setting `--max-files 0 --timeout 0` removes those two limits. Permissions, filesystem boundaries and archive parsing limits still apply.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Scan one or more directories

The shell helper takes a target directory and an optional output parent. It runs with `--no-context` and rejects `/`. Quote paths that contain spaces. Use `--exclude-dir` for a directory and `--exclude` for a pattern. With multiple targets, choose disjoint directories and use absolute exclusion paths. Findings retain `target-1`, `target-2` and their locations after merging.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Read live patch evidence

The host scan reads kernel livepatch state from sysfs. The optional helper queries installed Canonical Livepatch, Ksplice or Uptrack clients and sanitizes their output. Imported reports must match this boot and kernel and be at most 24 hours old to count as current. A missing entry cannot establish whether a particular CVE was fixed.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Recreate the operating graph or merge a set

The host OBOM relates listening sockets, processes and installed packages. A local bind address alone does not establish external reachability. Add `--kubernetes-evidence` or `--network-evidence` for matching exported observations. Set `set_dir` to the directory containing `bom-set.json` from the split operation. Keep the relationship files and checksums together. Archived sets using `mlbom.cdx.json` can still be merged.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Supply evidence for other BOMs

Point the AI collector at the directory containing the installed model. For SaaS or manufacturing records, supply a service or process manifest. Use `--asset-evidence` for Redfish devices, firmware or exported cryptographic observations. A build SBOM is linked to the scanned artifact only when its SHA-256 matches. Inputs and evidence schemas are listed in the guides below.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## Import IBM AIX and Oracle records

Run the shell helper on AIX, then run the importer on the Linux analysis host. Supply OPatch output saved by the Oracle Home owner and optional SQL patch history from the DBA. Up to eight distinct Homes are supported. A Listener version requires evidence from the same Home. Evaluate patch IDs against the applicable vendor bulletin.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Identify deployed dependencies

For npm and pnpm, installed locations, peer resolution and versions determine the edges. Static JavaScript detection covers jQuery, jQuery UI and Fancytree. Go binaries require embedded build information and Rust ELF binaries require cargo-auditable data. For .NET, pair .deps.json records with deployed managed DLLs. Ruby uses installed gemspecs. Java scans nested WAR, EAR and Spring Boot libraries and preserves archive paths. Missing coordinates remain unresolved.

## Compare a deployment with its supplier SBOM

Provide one WAR or EAR and a CycloneDX 1.4–1.7 or SPDX 2.3 document with the SHA-256 of that exact archive. Review `common`, `observedOnly`, `supplierOnly` and `unresolved` in `reconcile.json`. Submit the observed SBOM to Tracker. Limits are 512 MiB for the deployment and 32 MiB for the supplier SBOM.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Check inventory coverage

On a build or QA host, compare the same immutable deployment with KODA, Syft and Trivy. The comparison script requires Python 3.11 or later. Use `--expected` for verified components and dependency pairs or `--baseline` for regressions. Optional Tracker tests upload data to the specified test service. For stored graph checks, supply `--normalized-bom-command`.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Interpret a collection

Set `run_dir` to the result path printed by the collector. The exit codes are 0 for complete, 3 for partial results and 2 for failure. Review `collection.json` for limits, omissions and errors, `context.json` for runtime relationships, and `assets.json` for device or certificate evidence. Each container or image directory has its own checksums. Package versions and dates alone cannot determine vulnerability status.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Build on a separate machine

The release build uses Go and Python 3 on the build host. Go 1.26.11 was used for this release. Use a verified Go binary and SHA-256 for an alternate toolchain. Offline builds require a populated module cache. The release archive targets Linux amd64, and the source also builds for Linux ARM64. Build provenance is written to `release.json`.

```sh
VERSION=0.1.9 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Documentation

- [Offline installation and result checks](air-gapped.md)
- [Hardware, cryptography and operating evidence](asset-inventory.md)
- [Service, AI model and manufacturing manifests](additional-bom.md)
- [Supported platforms and collection limits](support-matrix.md)
- [Build and verification procedures](verification.md)
- [Recorded test results and their scope](verification-results.md)
