# Native platform observations

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit’s `Collect(ctx)` gathers bounded observations using tools already installed on the target. It uses fixed command arguments, a 60-second deadline per command and a 32 MiB output limit. It selects fields before writing them to the SBOM. Serial numbers, UUIDs, usernames and full application paths are omitted. Local paths contribute only to hashed component identity.

On macOS, `/usr/sbin/system_profiler` supplies hardware, software and application metadata. The collector emits system firmware, OS loader, CPU and applications, retaining the OS build in the OS version string. Some applications may lack version or metadata.

On Windows, system PowerShell runs without profiles and reads CIM computer, BIOS, OS and QuickFixEngineering records, plus machine and current-user uninstall registry entries. OS build and architecture are retained. QuickFixEngineering covers only the updates it reports. Registry inventory does not enumerate every user profile, Store application or embedded dependency. The collector records a coverage issue for these limits.

Run native macOS verification with `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Windows parsing fixtures and cross-compilation verify the source shape. Actual Windows execution requires a Windows target.
