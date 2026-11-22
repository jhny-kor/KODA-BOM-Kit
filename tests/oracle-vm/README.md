# Oracle Linux 8.2 direct-kernel boot validation harness

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` is the **validation VM’s PID 1** for KODA BOM Kit. Its `//go:build ignore` constraint excludes it from normal Go package tests. Build it explicitly with the command below.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker and QEMU are validation tools on the build PC. Deliver the `koda-bom` executable to the air-gapped target server. The harness and Python interpreter are not dependencies of the deployed executable.

## Reproduction

The runner emulates x86_64 with TCG in a QEMU container on an ARM64 build host. The guest has 4 GiB RAM and 2 vCPUs, with a 6 GiB container memory limit. Run the following from the project root on the external build PC. Replace `<ID>` with the actual ID printed by `run.py` and preserve previous reports.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

The validation host requires `jsonschema` and validates offline against the official schemas pinned in `tests/schemas`. Preparation downloads need network access. The kernel VM runs without external connectivity. Preserve the image ID used in the run because a tag can change.

`prepare.py` verifies the SHA-256 and size of the four RPMs pinned in [kernels.json](kernels.json), totaling 120,245,036 bytes, and the Oracle Linux 8 signing-key fingerprint. It imports the public key into a fresh Oracle test container’s RPM database, checks signatures using `rpm -Kv`, then installs kernels with `--nodeps --noscripts --notriggers`. This creates a filesystem for validating kernel images, modules and RPM metadata. Normal installer scripts, dracut and GRUB configuration are outside this procedure.

Rerun `prepare.py` with the final release binary in an existing work directory to rebuild the collector, validation PID 1 and initramfs from the cached kernel/RPM filesystem. Boot both kernel VMs again and compare the **final binary SHA-256** against the baseline. Earlier-build VM results cannot validate a newly built release.

Preserve `input-provenance.json`, `rpm-signature-install.log`, and each run’s `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, both SBOMs and their checksums. Provenance records RPM, kernel, initramfs, PID 1 and collector hashes plus Oracle/QEMU image IDs. A separate release validation report links this evidence to the distribution archive’s SHA-256.

## Guest preparation

The validation initramfs contains the Oracle Linux 8.2 filesystem, the RPM database of both installed kernels, kernel images in `/boot`, both `/lib/modules` trees, `/koda-bom` under test and this harness as `/init`. RHCK and UEK must each boot directly from their own kernel image. Container execution or QEMU user-mode alone does not establish this boot evidence. Optionally place a matching module extracted from the official kernel RPM at the following location.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

The harness records the module SHA-256 and attempts to load it with `init_module`. It records separate status and errors when the module is missing, already loaded or fails because of signatures or dependencies. Compare `loadedModulesAfter` with the collector’s `loadedModules` to confirm actual loading. An unobserved module does not establish that the feature is absent.

QEMU receives no external network interface or virtual disk. The runner uses `-accel tcg,thread=single -cpu max -smp 2 -m 4096`. Test guests use `random.trust_cpu=on` to avoid early-boot `getrandom` waits. This test kernel argument is not a production configuration recommendation. Preserve actual CPU/acceleration settings and kernel, RPM, initramfs and collector checksums in host-side validation records.

## Execution and collection

The harness mounts `/proc`, `/sys`, `/dev`, `/tmp` and `/results`, and sets a synthetic hostname. Its independent baseline records uname, `/proc/sys/kernel/osrelease`, OS release, module lists before/after loading, the VM kernel command line and collector checksum. Hostname and kernel command line are included only in this synthetic VM evidence. The product’s normal collection policy is unchanged. The collector runs once with the following command.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

Use the default live-host mode without `--target /payload`. The 0.1.3 validation disables the collector’s file-count and time limits by setting both to 0. The validation PID 1 retains its separate 11-minute watchdog and the host QEMU runner retains its timeout for resource cleanup. stdout and stderr are each capped at 1 MiB in separate files. Exit code, timing and errors are saved in `/results/baseline.json`. Exit 3 means partial collection and must remain 3.

Results are transmitted over the serial output as **base64(gzip(tar))** between these markers.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

If the uncompressed total exceeds 256 MiB or 10,000 files, only a baseline explaining the failure is exported. After export, the guest attempts sync and poweroff. If these fail, PID 1 stays alive to avoid a kernel panic. The host runner must terminate QEMU if guest execution exceeds its deadline.

## Required checks

- Baseline uname and proc release agree, and RHCK/UEK each boot the intended version.
- `context.json.mode=live-host` and `runningKernel` match the independent baseline exactly.
- UEK reports `kernelFlavor=UEK` and RHCK reports the current contract `RHCK-compatible`.
- Native inventory retains both installed kernels and each RPM’s epoch/version/release/arch/source package.
- Installed kernels are distinguished from the currently running kernel identified by context.
- Module inventory `metadata.kernelVersion` and `versionMagic` match each installation tree. The loaded-module list agrees with the active kernel baseline.
- Both SBOM schemas and checksums pass. Collection failures and partial status are reported faithfully.

## Validation limits

- The harness boots real Oracle RHCK/UEK guest kernels. Physical x86_64 server validation remains a separate activity.
- Oracle Linux 8.2 user space and official kernels run in a custom initramfs. Full systemd boot, GRUB installation, UEFI/Secure Boot, enforcing SELinux and production service integration are outside this test.
- The `loop` test checks loading and observation of one real module. It does not cover every driver or hardware configuration. Installed modules for an inactive kernel must not be treated as loaded.
- Collector exit `3` and `collection.status=partial` are accepted with their reasons retained. Passing kernel identification, standard output and integrity checks does not establish complete collection of every file.
