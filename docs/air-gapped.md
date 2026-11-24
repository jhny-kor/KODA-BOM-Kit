# Air-gapped execution and result inspection

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 provides a Linux x86_64 (amd64) offline archive for kernels 3.2 or later. Transfer the archive and its matching `.tar.gz.sha256` from the official release. The target server needs no new Go, Python, Docker or jq installation. NOTICE credits jhny-kor and the official repository.

[Release 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## Verify and unpack

Place exactly one matching archive and checksum in an executable local working directory. Verify the archive before extraction and the internal files afterward. A checksum verifies transferred bytes. Use the trusted official release as the source. A noexec USB mount requires copying to an executable local filesystem.

```bash
set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.9 archive.' >&2
fi
```

## Inspect the host

Check architecture, running kernel and `doctor`. `supported=true` means the runtime prerequisites passed. `doctor.kernel` and `context.json.runningKernel` identify the observed kernel. A reported kernel with `kernelFlavor=unknown/unconfirmed` still has a recorded version. Root privileges improve DMI, BMC, process and container visibility.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Choose the collection scope

Running `koda-bom` without arguments creates a fresh directory under `bom-output/`, containing merged `bom.cdx.json` and seven individual documents under `boms/`. AI-BOM is `aibom.cdx.json`. Local evidence availability determines content and completeness. For Qwen, use the real readable model directory. H100 identity belongs in HBOM. Model settings, headers and installed packages cannot establish current GPU allocation or effective serving configuration.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

Directory collection uses `--no-context` and follows the selected directory boundary. Set the output parent outside the input. The wrapper rejects `/`. `--exclude-dir` accepts relative paths in the single-directory wrapper. Multiple targets must not overlap and require absolute excluded-directory paths. The file/time limits are shared across targets. Dependencies outside the selected paths can remain unobserved.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Livepatch collection

The optional helper queries already installed Ksplice, Uptrack or Canonical Livepatch clients, sanitizes evidence and runs the scan. It retains sanitized evidence beside the result directory. Capture `$?` immediately. The helper has client-query limits of 30 seconds and effective-kernel-query limits of 10 seconds. Those remain when the scan time limit is removed. Existing vendor clients and daemons have their own network behavior.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Limits and exit status

The defaults are 1,000,000 selected regular files and 30 minutes. `--max-files 0 --timeout 0` removes those two limits. Ctrl+C cancels collection. File permissions, exclusions, symlink boundaries, the per-file 2 GiB limit and image extraction limits still apply. `--no-containers` skips container and unused-image BOMs. `--no-images` skips stopped containers and unused images. Exit 0 means complete, 3 means partial with results to inspect, and 2 means failure. Investigate any other exit code before using the output.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Find and verify results

Use the exact result directory printed by the command. Helper stdout includes doctor/evidence output before its last result-path line. Set `result` to that actual directory. Root-created files may need sudo for inspection. Check the root manifest and each container/image manifest. Preserve partial-collection reasons alongside the BOM.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## Read collection and patch status

`collection.json` records `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, host identity, package provenance, integrity and container/image status. `filesystemFileCount` counts files selected during traversal. `file_limit_exceeded` provides `limit` and `observed`. `context.json` records the running kernel, processes, listening sockets, services, settings and livepatch evidence. `assets.json` holds observed hardware, firmware and certificate evidence.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` is a direct kernel observation. `reported-applied` is a client report. `disabled` and `transitioning` retain those states. `stale`, `identity_mismatch` and `unknown` require further evidence. Inspect current status with `patches[].state`, because `reportedState` can preserve an older report. Evidence older than 24 hours, a different boot/kernel or an excessive future timestamp cannot establish current application. Canonical Last-Check/CheckState also apply. Missing observations and `not-reported-patched` require interpretation against kernel/vendor evidence.

`integrity.findings[].state=modified` or `missing` describes a file mismatch or absence. `bindScope=all-interfaces` describes binding addresses. Firewall exposure needs separate evidence. `unidentifiedExecutables` means no package association was found. `reboot.recommended=not_observed` records missing reboot signals. Use SBOM package identity, host context and their limitations together when reviewing these findings.

## Supplier comparison and preservation

For WAR/EAR reconciliation, the supplier SBOM must identify the artifact with its actual SHA-256. Missing or mismatched hashes fail with exit 2. Review `reconcile.json` and partial-collection issues. Preserve the complete result parent, including sanitized livepatch evidence, and calculate the exported archive checksum.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Upload and follow-up

Submit `sbom.cdx.json` or `sbom.spdx.json` to a compatible Tracker. Container/image results have their own standard SBOMs. Keep `collection.json`, `context.json` and Syft inventory as accompanying evidence. Tracker upload time limits are configured independently. This collection provides inputs for subsequent advisory analysis. Current patch effectiveness and specific CVE remediation require their own evidence. Historical kernel VM results and each release's exact test scope are documented in the verification records.

## Documentation

[Air-gapped execution and result inspection](air-gapped.md) · [Build and verification guide](verification.md) · [Verification results](verification-results.md)
