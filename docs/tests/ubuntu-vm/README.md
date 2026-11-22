# Ubuntu 24.04.1 real-kernel VM validation

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

This is a KODA BOM Kit test tool. It is not a dependency of the executable deployed to an air-gapped server. It directly boots Ubuntu Base **24.04.1 amd64** and the official Ubuntu kernel **6.8.0-47-generic / package 6.8.0-47.47** using a custom initramfs. QEMU user-mode and directory fixtures do not establish real-kernel boot evidence.

The Ubuntu Base source comes from an archived Ubuntu distribution mirror. Its SHA256SUMS.gpg is verified with the Ubuntu CD Image Automatic Signing Key (2012), `843938DF228D22F7B3742BC0D94AA3F0EFE21092`. The Ubuntu archive keyring in this authenticated rootfs verifies the official Snapshot service’s 2024-10-18 noble-updates InRelease. Verification connects signed Release → Packages.xz → SHA-256 and size of both DEBs. Preserve every input URL, checksum, signature log and Docker image ID.

The build host requires Go, Python 3 with `jsonschema`, Docker and GnuPG (`gpg`/`gpgv`). It reuses the Oracle VM tool image. These tools are not installed on the target server. Run the following from the project root, replacing `<ID>` with the actual run ID.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` reuses the Oracle harness’s bounded export and independent baseline design. Ubuntu has a built-in loop driver, so this test loads an actual `dummy.ko` to verify module observation. It independently records running uname and proc release, OS, collector SHA and loaded modules, then compares both SBOMs against pinned official schemas, checksums, original DEB versions/source/PURL and installed kernels/modules. Rerun prepare, run and validate whenever a new final binary is supplied.

The test rootfs uses `dpkg --unpack` to extract original DEBs and create a real dpkg database. Dependency overrides are allowed and packages remain unpacked. It does not establish a completed normal apt installation or configuration. Full systemd boot, GRUB, UEFI/Secure Boot, production services and physical hardware validation require separate tests. QEMU has no NIC or disk. Docker uses `--network none`, a read-only rootfs and dropped capabilities. Installing actual commercial or subscription live patches is outside this test.

Validation for 0.1.3 passes `--max-files 0 --timeout 0` to disable the collector’s two limits. The test PID 1 retains its separate 11-minute watchdog and the host QEMU runner retains its timeout.

Preserve provenance, signature logs, dpkg logs, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, both SBOMs and `validation.json` together. Keep partial-collection exit 3 as 3. Do not convert it to complete-collection exit 0.
