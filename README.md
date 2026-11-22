<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="README.ja.md"><img src="docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="LICENSE"><img src="docs/badges/license.svg" alt="Apache-2.0"></a>
  <a href="docs/support-matrix.md"><img src="docs/badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Collect a Linux host’s software, hardware and operating evidence with one offline executable. KODA BOM Kit writes seven CycloneDX bills of materials, a merged BOM and an SPDX software inventory.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>Download v0.1.8</b></a> ·
  Original author <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Official repository</a>
</p>

## Quick start

Download the Linux amd64 archive and its matching SHA-256 file. Transfer both to an empty directory on the target server and run these commands there. The target needs no Go installation, package download or vulnerability database.

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## What the collector writes

The last line gives the new directory under `bom-output/`. Open `bom.cdx.json` for the merged inventory. The seven source BOMs live in `boms/`.

| File | What it describes |
|---|---|
| `boms/sbom.cdx.json` | Installed packages, libraries and applications |
| `boms/hbom.cdx.json` | Devices, firmware and drivers |
| `boms/cbom.cdx.json` | Cryptographic assets such as certificates and algorithms |
| `boms/obom.cdx.json` | Observed relationships between services, processes, sockets and packages |
| `boms/aibom.cdx.json` | Local model files, weights and supplied model metadata |
| `boms/saasbom.cdx.json` | Services described by an OpenAPI document or service manifest |
| `boms/mbom.cdx.json` | Manufacturing and build workflows described by supplied evidence |

A host can produce a BOM with no entries. Check its evidence status and `collection.json` for the reason. Tracker accepts the top-level `sbom.cdx.json` or `sbom.spdx.json`. The default formats are CycloneDX 1.6 and SPDX 2.3. Add `--cyclonedx-17` to generate CycloneDX 1.7 alongside 1.6.

To merge again, copy the entire `boms/` directory, including its manifest, relationships and checksums. Set `run_dir` to the path printed by the collector.

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Documentation

- [Offline installation and result checks](docs/air-gapped.md)
- [Collector commands and output files](docs/collector-guide.md)
- [Hardware, cryptography and operating evidence](docs/asset-inventory.md)
- [Service, AI model and manufacturing manifests](docs/additional-bom.md)
- [Supported platforms and collection limits](docs/support-matrix.md)
- [Build and verification procedures](docs/verification.md)
- [Recorded test results and their scope](docs/verification-results.md)

### Source and test guides

- [External asset imports](internal/assetimport/README.md)
- [Platform inventory](internal/platforminventory/README.md)
- [Product identification](internal/products/README.md)
- [Oracle Linux VM](tests/oracle-vm/README.md)
- [Ubuntu VM](tests/ubuntu-vm/README.md)

## License and attribution

KODA BOM Kit is licensed under Apache-2.0. See the original author notice and the notices for bundled dependencies. [Apache-2.0](LICENSE) · [Author notice](NOTICE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
