# Verification results

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

These are dated records for KODA BOM Kit and its earlier releases. Exact build hashes, environments, partial results and untested areas remain part of each record. The current release is 0.1.9. Its official release entry identifies the archive, checksum and execution scope. Earlier successful tests do not validate a newly built executable.

[Release 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 2026-11-21 — split and merge

Worktree `f0610ca-worktree-00ed83f2acd8` tested `scan --separate-boms`, `bom-split`, `bom-merge` and `domain-bom` using two archived 0.1.6 collections. Every original component and relationship was compared independently. One relationship between inventory and operational roots was added in each merge. Ten Ubuntu certificate ID pairs represented different file positions. All 20 records were retained and the merged document had zero duplicate IDs. An isolated Linux ARM64 run combined four observed BOMs with synthetic OpenAPI, model, SLSA and manufacturing inputs. A real loopback TCP 18443 listener linked to Perl and its package. CycloneDX 1.6/1.7, SPDX and checksums passed. Signature authenticity and field evidence remain separate checks.

| Archive | Components before / after | Relationships before / after |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — operational relationships

Worktree `f0610ca-worktree-06f22395e26f` regenerated OBOMs from two partial 0.1.6 archives. Socket observations are counted per namespace/process. A Debian ARM64 test linked `127.0.0.1:18443/tcp` to `/usr/bin/perl` and `perl-base`. It also checked three Redfish part numbers, declared/example TLS data, two build relationships, 11 checksums and byte-identical regenerated OBOMs. Five exported synthetic Kubernetes resources linked to archived full container IDs. Production clusters, physical inventory and real TLS sessions were outside this test.

| Archive | Containers | Sockets host + containers | Linked to package host + containers | Compared relationships |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — 12 Daybreak fixes

The findings against earlier repository KODA-SBOM-Maker at `cc86c1b` were addressed. Changes covered isolated Go build settings, hashing the exact extracted archive stream, the 256-layer limit and hash reuse, bounded ZIP/ZIP64 indexes, validated whiteouts, exclusive output directories, indexed and bounded advisory matching, rejection of optimized Python QA, file access within validated roots, safe short container IDs, RPM epoch-aware version conflicts and cancellable 256-entry directory traversal.

Go tests, vet and release guards passed on macOS ARM64. An offline Go 1.26.11 / Syft 1.57.1 Linux amd64 build was static. All 306 package checksums passed. Network-disabled Debian CLI and directory tests passed. The before/after inventory retained 88 packages, one OS, 20 devices and 15 drivers. Both scans were partial with observed limits. ARM64 Linux, macOS and Windows cross-compilation passed. Their execution and fresh kernel VM regressions were outside this run.

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

On Docker Desktop kernel `7.0.14-linuxkit`, Linux tests and Go/vet checks passed. CPU observations matched lscpu. The collector read 1,736 kernel options. Debian had one unrecorded local package among 147. Rocky recorded 167 repository packages, distinguished local-file installation and unrecorded rpm installation. Docker found nine running containers, 14 stopped containers and 11 unused images, producing 35 schema-valid SBOMs in about 3 min 30 s. Matching image/container package counts were 796, 71 and 51. Overlay2 tests retained writable-layer curl and collected unused busybox. A deleted temporary container was marked `not_collected`. Real x86 CPUID/CPE, systemd running state, Kubernetes/k3s/Podman/CRI-O storage and fresh kernel VM tests remained unverified.

## 2026-11-19 — 0.1.6

Linux ARM64 tests ran in Debian 12 on Docker Desktop kernel `7.0.14-linuxkit`. Host identity hashing, real listeners and 16 running Docker container BOMs passed. Five actual out-of-tree kernel modules were recorded. Integrity checks examined 735 files, about 89 MB, detecting exactly one intentionally modified and one moved/missing file. RSA-1024 and ECDSA P-384 certificate checks covered expiry and weak keys without exporting private keys. Hardware/ioctl structures, snap/flatpak/conda and several security states used fixtures. Physical RAID/NIC/BMC, production SELinux, other runtimes and fresh kernel VM regressions remained unverified.

## 2026-11-18 — 0.1.6-dev

Go tests, vet, helper limits and shell checks passed. Linux amd64 and ARM64 collection and actual macOS ARM64 platform inventory passed local schema/checksum checks. Windows was cross-compiled only. Deleted/replaced executables, image hashes and offline advisory rules were tested. The local Tracker parser read both CycloneDX versions. Production Tracker deployment and browser behavior were unverified. Dual output used 704 versus 811 license IDs, preserving the 107 extra names semantically. Output checksum counts depended on collection scope.

## 0.1.2–0.1.5 historical releases

0.1.5 added pnpm path relationships and Maven POM properties/ranges. 0.1.4 added the directory wrapper and out-of-scope checks. 0.1.3 added configurable file/time limits and helper forwarding. Match each build to its `release.json`, `VERIFICATION.json` and corresponding `dist/evidence/v0.1.x/final-verification.json` where supplied. 0.1.2 reran Ubuntu and both Oracle kernels for its final executable. Vendor subscription installation and live patch application were outside the synthetic helper tests.

## 2026-10-29 — implementation and Oracle VMs

The initial implementation passed 68 Linux-target checks and vet. Isolated uid 65534 fixtures used read-only inputs/rootfs, no capabilities and no network. Official schemas, PURLs, canary protection, failure states and checksums passed. The Oracle container had RPM 182, Python 5 and binary 2. Guest syscall tracing recorded zero network and additional execve attempts. Each format uploaded to an isolated SQLite-backed Tracker with HTTP 202. A small 0.1.0 fixture took 0.78 s and 219,644 KiB peak RSS under emulation.

Oracle Linux 8.2 system VMs booted signed RHCK and UEK kernels. Independent uname/proc observations and loaded loop modules matched. Both produced 5,516 components, including 186 RPMs, two kernel images, 5,321 modules, five Python packages and two binaries. Module trees held RHCK 2,478 and UEK 2,843. Each passed both schemas and five checksums. Both exited 3 with partial collection and completed context. Recorded reasons included protected files, unresolved/out-of-scope links, conflicting OpenSSH strings and Syft warnings.

| Kernel | Collection / total seconds |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## Evidence limits

The initial VMs used the 0.1.0 binary hash shown below. Later releases have their own hashes and reports. Physical x86 servers, full OS boot/service integration and active vendor patching were outside those records. QEMU guest traces and native x86 ptrace have different execution environments. A live scan can observe changes across time. Record a quiet collection window or use a read-only snapshot. Package versions and absent observations alone cannot establish CVE applicability or remediation.

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## Documentation

[Air-gapped execution and result inspection](air-gapped.md) · [Build and verification guide](verification.md) · [Verification results](verification-results.md)
