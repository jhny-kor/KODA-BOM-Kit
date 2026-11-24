# Hardware and software inventory

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Use the `koda-bom` binary built for the target OS and CPU. Linux `scan` collects packages and host hardware. The Windows/macOS `platform-inventory` command calls local inventory tools provided by the OS.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

In Windows PowerShell, use `.\koda-bom.exe platform-inventory --output-dir .\reports`. Linux directory/image scans use the selected filesystem. Live hardware is observed during host `/` collection with context enabled. Explicit Docker/OCI archives support Linux amd64 images. Submit a verified CycloneDX document to Tracker and retain both format versions and checksums together.

## Collected evidence

| Area | Collection and interpretation |
|---|---|
| Hardware | CPU/microcode, mitigations, board, BIOS/UEFI, ESRT, PCI/driver, NVMe/SCSI, USB and TPM fields. As root, the raw SMBIOS table supplies memory module manufacturer, part number, capacity and speed, power supply model and wattage, and system slots with their PCI address; serial numbers are recorded as SHA-256. RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS and amdgpu `vbios_version` are read when exposed. NIC firmware uses read-only ioctl equivalent to `ethtool -i`. megaraid_sas needs exported evidence. |
| BMC | Read-only IPMI `Get Device ID` through `/dev/ipmi0`, requiring root and `ipmi_si`/`ipmi_devintf`. Records firmware revision, IANA manufacturer, product ID and auxiliary revision. Missing devices are explained. Compare vendor build labels using Redfish exports when needed. |
| CPU identity | x86 `cpuidSignature` and `familyModelStepping`, socket/core topology, ARM vendor/core names and revision such as `r3p1`. Unknown ARM cores retain raw identifiers. USB `bcdDevice` remains a device release identifier. |
| External assets | Expanded Redfish objects, fwupd JSON, devlink JSON and the common schema below. Running and stored firmware remain separate observations. Available fields depend on the vendor/model. |
| Runtime | Executable/shared-library replacement, file identifiers and uniquely identified owning packages. Replacement produces `restart_review`. Installed package versions alone do not establish the in-memory version. |
| Host identity | SHA-256 of normalized machine-id and DMI UUID/product/board serials on host `/`, even with `--no-context`. machine-id/UUID are lowercase, serials are trimmed. Shared placeholders and zero UUIDs are omitted. Serial hashes are pseudonymous and can be guessable. `--asset-tag` records an explicit single-line label of up to 128 characters. Container scope is `container-visible`. |
| Sockets | TCP LISTEN and unconnected UDP in the collector's network namespace, matched through process file descriptors. `bindScope` is `all-interfaces`, `loopback` or `address`. Firewall/routing reachability needs separate evidence. Unowned sockets go to `context.json.unattributedSockets`. Established outbound TCP connections are recorded per process and remote endpoint in `outboundConnections` with `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`). |
| Security and reboot | SELinux current/configured mode, AppArmor enabled/profile counts, lockdown, FIPS and allowlisted boot options. Credentials and unrelated boot arguments are excluded. `kernelConfig` records `y`/`m` from `/proc/config.gz` or `/boot/config-<running-kernel>`. Reboot signals cover `/run/reboot-required`, missing running-kernel modules and a newer installed kernel in the same release family. Positive signals set `reboot.recommended=true`, otherwise `not_observed`. Family matching is a release-string heuristic. |
| SSH | Global declarations in `sshd_config` and `sshd_config.d/*.conf`, including `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. `Match` blocks are excluded. Effective values depend on `Include` order. |
| Kernel modules and unknown programs | `kernel.tainted` and `taintedModules` hold names, `O`/`E`/`P` flags, version and srcversion. `unidentifiedExecutables` records path/PID for same-root programs without package/component/product ownership. usr-merge paths are matched. |
| Integrity | RPM/dpkg/apk database hashes are compared with executables and `.so` files. Config and ghost files are excluded. `modified`/`missing` findings appear in `collection.json.integrity.findings` and component properties. Hash budgets are 8 GiB per host and 1 GiB per container, with `partial` when exhausted. prelink can cause mismatches. |
| Package origin | apt `Packages` (plain/gz/lz4) matches names, dnf history and yum `from_repo` provide repository IDs. Values include `repository`, `local-file`, `not-recorded`. Missing history, dnf5 and apk are unsupported. Repository URLs/local paths are omitted. The dnf DB is copied to a temporary directory and opened read-only. |
| Boot services | systemd `*.wants`/`*.requires`, unit/drop-in declarations, first `ExecStart`, socket activation and package PURL. Masked units are excluded. Process presence in `system.slice` determines running/stopped on hosts. Custom slices can appear stopped. Enabled timers record their `On*` schedule and the service they start. |
| Hardware CPE | Supported Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge device/BIOS and Lenovo ThinkSystem device patterns. Unidentified models, HPE and BMC receive no guessed CPE. |
| Certificates | SSH host public keys (`etc/ssh/ssh_host_*_key.pub`) with OpenSSH SHA-256 fingerprints, and public X.509 certificate fingerprints, validity, algorithms, key size and status. Weak indicators include SHA-1/MD5 signatures, RSA below 2048 bits and DSA. Classical algorithms have `nistQuantumSecurityLevel=0`. Subject/issuer names and private key data are excluded. Distribution trust stores and bundles over 20 certificates are skipped. |
| Applications | Active snap revisions and embedded Debian packages, active flatpak/AppStream releases, conda metadata with channel names, `.pyz`/`.pex` metadata, JAR, static JS and Go/Rust build evidence. OCI/Docker artifact hashes and available verified digests are retained. |

## Containers and outputs

Running containers receive individual `containers/<name>/` collections. Kubernetes names use namespace, pod and container, adding 12 ID characters on collision. Docker, containerd, Podman and CRI-O metadata are read from disk. Runtime API sockets are never contacted. The mounted root is located through mountinfo device matching. Image/writable layers are included, volumes/bind mounts are excluded. Container sockets are attributed to that container's processes. Package ownership takes priority and Go executables use the main module. Missing roots/timeouts produce `not_collected` with a reason. `--no-containers` disables this collection.

Stopped containers and unused local images support Docker overlay2, containerd overlayfs (including k3s/RKE2) and rootful Podman/CRI-O storage. Layers are copied into a temporary output directory with whiteout/opaque handling, inspected and removed. Device files and set-ID bits are omitted. A root over 16 GiB or free space below root size + 1 GiB is skipped. Results use `state: stopped` or `state: image`, without listening sockets. Concurrent runtime changes can prevent collection. Other Docker storage drivers and rootless Podman are unsupported. `--no-images` disables this path.

Default collection writes seven profiles under `boms/` and merges them into `bom.cdx.json`. AI-BOM uses `aibom.cdx.json`. Compatibility outputs include CycloneDX 1.6 `sbom.cdx.json` and SPDX 2.3 `sbom.spdx.json`. `--cyclonedx-17` adds 1.7 files. SPDX uses `OTHER` and annotations for types without a native equivalent. Host identity uses `koda:host:*`, container identity uses `koda:container:*`, sockets use `koda:runtime:listening`/`koda:runtime:bind-scope`. Review `assets.json`, `context.json`, `collection.json` and `inventory.syft.json`. Verify files with `SHA256SUMS`.

## Common asset evidence

Provide at most eight files of up to 8 MiB each. `parentId` references an asset `id` in the same file. Omit unknown versions. Redfish requires expanded asset/firmware objects beyond URI listings. Input SHA-256 identifies the imported file.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

## Cryptographic assets and TLS sessions

X.509 certificates, public keys and algorithms become `cryptographic-asset` components. Candidate issuer relationships are signature-checked. Allowlisted Nginx/Apache/sshd directives record configuration evidence. JKS v1/v2 public chains and alias SHA-256 are recorded, encrypted keys are skipped and password-free store integrity is `not-verified`.

Import public PKCS#12/HSM/KMS metadata using `--asset-evidence`. A `related-crypto-material` entry can contain key type/size/state and `algorithmRef`, plus `properties.storageType` and `keyAlias`. Consumer `dependsOn` points to the key metadata in the same file.

The following example imports independently measured TLS negotiation. Replace example fingerprints, endpoint and time with actual observations. A matching certificate hash links service → protocol → certificate.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## Offline advisory assessment

Reassess archived results with new advisory files through the same binary.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`, `--context` and `--kev` are optional. Context use verifies both SBOM and context against the collection's `SHA256SUMS`. KEV adds prioritization information. Supported inputs are explicit rules below, OSV with exact affected versions/PURLs, and CSAF 2.0 with exact product IDs/unconditional status. Unsupported version ranges or conditional/product-combination expressions stop assessment with a reason.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "Verify firmware activation according to the vendor advisory"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Use release-specific distro IDs and exact package versions. SBOM/PURL version conflicts yield `review_required`. RPM epoch is considered. The maximum is 1,000,000 exact-version entries per run. Explicit rules support `supportEndsAt` and, for supported software ecosystems, `affectedSemver`. Replaced files/stored firmware trigger activation review. Unknown assets and versions absent from advisories require review. Verify physical Linux and Windows equipment against vendor inventory. Native Windows/macOS inventory focuses on OS, hardware and installed applications.

The report's `risks` array lists the risks that the collector recorded in the BOM, with source `KODA collection evidence`. They need no advisory file and are kept apart from advisory `findings`. `sbom.cdx.json` and `sbom.spdx.json` carry the cryptographic risks, and the merged `bom.cdx.json` adds the AI-BOM and OBOM risks. In `bom.cdx.json`, advisories skip the OBOM nodes that repeat a host package; packages of running containers are matched through their OBOM nodes, which cover only the packages their processes use. Assess `containers/<name>/sbom.cdx.json` for a container's full inventory. `risk_observed` means the recorded evidence shows the condition; `review_required` means it could not be ruled out.

| Finding ID | Status | Recorded evidence |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | Certificate or SSH host key using RSA below 2048 bits, or DSA |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | Certificate signed with MD5 or SHA-1, unless the collector verified it as self-signed |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | Configuration that allows protocols below TLS 1.2, or the LEGACY system crypto policy |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | Pickle in a model file, or in a checkpoint of a model directory, imports callables that can run code |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | Pickle imports modules outside the allowlist, or inspection was incomplete |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | Host listener beyond loopback that declared firewall rules accept; restricted sources, rules that could not be evaluated, or no active firewall declaration (`none-observed`) need review |

## TCP reachability observations

`--network-evidence` matches previously measured TCP outcomes with host or archived OBOM sockets. `hostField` is `machineIdSha256`, `productUuidSha256` or an explicitly assigned `assetTag`. `scope` is `host` or a full 64-character container ID.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

Results are `connected`, `refused`, `timed-out`. Ambiguous owners or missing sockets remain unmatched. Each vantage point and time requires its own observation. The collector performs no connection probes. See the [support matrix](support-matrix.md) and [additional BOM evidence](additional-bom.md).
