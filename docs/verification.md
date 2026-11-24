# Build and verification guide

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 publishes an offline Linux amd64 archive and SHA-256 checksum. Identify each tested executable by its exact SHA-256 and execution environment. Linux host collection targets x86_64 and ARM64. Docker/OCI archive collection targets linux/amd64 images. macOS and Windows platform inventory uses fixed read-only OS commands. Windows execution remains unverified. Historical VM results apply to their recorded builds.

[Release 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## Output formats and integrity

The default output is CycloneDX 1.6 and SPDX 2.3. Add `--cyclonedx-17` to emit 1.7 from the same inventory. `--format cyclonedx --cyclonedx-17` produces the two CycloneDX documents. `--format spdx --cyclonedx-17` is rejected before output. The option is supported by `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` and the two collection helper scripts. Match the expected files to the options.

| Output | Format |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` checks local schemas, component identities, evidence, properties, license semantics, dependencies, collection scope, missing or duplicate checksum entries and hashes. CycloneDX 1.7 schemas are pinned to official 1.7.1 commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`, with provenance in `tests/schemas/provenance.json`. There are 704 license IDs in 1.6 and 811 in 1.7. The 107 additional IDs use `license.name` in 1.6 and `license.id` in 1.7. Review `collection.json` for partial collection even when schemas pass.

## Build-host checks

Prepare Go, Python, Docker, cached Go modules and local schema dependencies on the build host. Set `trusted_go_sha256` to the independently verified Go executable hash. `GOPROXY=off` uses the prepared module cache. Release QA rejects Python optimization (`python3 -O` or `PYTHONOPTIMIZE`). The target server runs the packaged executable. On macOS, use `shasum -a 256 -c SHA256SUMS`.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Integration coverage

Run these commands against the extracted final release. Prepare the required upstream caches before disabling networking. .NET/Ruby tests need .NET 10 SDK and verified upstream packages. Go/Rust tests need cached Go modules and a pinned Alpine ripgrep ELF, or `--rust-binary`. Fancytree verification uses pinned npm SHA-512 or GitHub archive SHA-256. Add `--tracker-root /path/to/tracker` to supported integration commands to check the actual local Tracker parser.

`domain_bom_integration.py` executes the target binary directly. Run that test on Linux amd64.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/runtime_smoke_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

The suite checks nested Java archives, Python pyz/pex metadata, Go/Rust binaries, installed package provenance, directory boundaries, supplier artifact hashes, PURLs and dependencies. Linux fixtures cover sockets, containers, firmware parsing, service state, security settings, integrity and certificates. AIX fixtures verify Oracle Homes, Listener evidence and OPatch IDs. Synthetic fixtures establish parser behavior. Physical BMC, NIC, OT devices, Kubernetes storage and active subscription patch clients require their own environment evidence. GitHub Actions (`.github/workflows/ci.yml`) runs formatting, vet for every build target, Go tests, release guards, the binary check and the container suites above except those needing upstream caches on each push to `main` and each pull request; `docs.yml` checks documentation-only changes. Release builds, cached upstream suites and VM checks still run on the build host.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/scripts)

## Linux kernels and VM reproduction

Run Linux-only tests on Linux. A macOS build host can cross-compile test binaries and execute them in a matching Linux container. Use the final packaged executable for the VM commands. Oracle RHCK `4.18.0-193.el8.x86_64` and UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` boot separately from signed RPMs pinned in `tests/oracle-vm/kernels.json`. Keep input provenance, signature logs, QEMU image IDs, serial logs, baseline and validation reports.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

The Oracle runner uses QEMU system TCG, 4 GiB RAM, two virtual CPUs and a custom static PID 1, with no guest network or disk. It verifies uname, proc release, actual loop module loading and installed versus running kernels. Ubuntu tests boot `6.8.0-47-generic` with authenticated Ubuntu Base and kernel packages. GRUB, UEFI/Secure Boot, complete systemd boot, enforcing SELinux, physical drivers and production services require separate tests. An Oracle container checks user space and RPM data while sharing its host kernel.

[Oracle VM](tests/oracle-vm/README.md) · [Ubuntu VM](tests/ubuntu-vm/README.md)

## Syscalls, resource limits and downstream analysis

Trace the final binary in an isolated build-host container. If ARM64 emulation cannot decode ptrace registers, `trace-network.sh` returns 77. Use QEMU guest syscall tracing with its environment explicitly recorded. A zero-attempt claim requires a working trace. Optional livepatch helpers invoke existing vendor clients, whose daemon/network behavior has its own scope.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

The default limits are 1,000,000 selected regular files and 30 minutes. Test each limit independently, invalid options, cancellation, permissions, corrupted input and excluded paths. `--max-files 0` and `--timeout 0` remove those limits. Record wall time and peak RSS for the actual input. Two collection workers do not impose a hard memory cap. Tracker upload checks use an isolated temporary database and verify both standard formats. Assessing local advisories depends on supplied rules and observations. Production deployment and CVE remediation require their own evidence.

## Documentation

[Air-gapped execution and result inspection](air-gapped.md) · [Build and verification guide](verification.md) · [Verification results](verification-results.md)
