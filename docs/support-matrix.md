# Collection support and evidence limits

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


This matrix describes identifiable evidence. Review the status and reasons in `collection.json` for each run. Completeness depends on readable metadata, installation format and permissions. Vulnerability assessment requires matching advisory evidence.

## Seven CycloneDX BOMs

A default host `/` scan produces individual documents under `boms/` and a merged `bom.cdx.json`. `--cyclonedx-17` adds 1.7 versions. Unsupported or absent domain evidence is marked explicitly, including `no-evidence` and unknown coverage. [CycloneDX categories](https://github.com/CycloneDX/specification#readme)

| BOM | Available evidence | Additional evidence |
|---|---|---|
| SBOM | OS/language packages, versions/PURLs, available licenses/dependencies, JARs, embedded modules, containers | Supplier/CI CycloneDX or SPDX tied to artifact SHA-256 for static/build dependencies, emitted as `build-sbom.cdx.json` |
| HBOM | CPU/board/devices/drivers/firmware, EDAC DIMMs and power/fan sensors | Redfish or asset registers for invisible parts, part numbers, suppliers and lifecycle |
| CBOM | Public certificates/keys/algorithms, verified issuer relations, TLS/SSH configuration, JKS metadata | Measured TLS negotiation and exported public HSM/KMS/protected-keystore metadata |
| OBOM | Host/container/process/executable/package/socket relations and systemd activation | Same-cluster Kubernetes JSON for Pod/workload/Service/Ingress, deployment labels, host-matched `--network-evidence` |
| SaaSBOM | Service specifications/OpenAPI become `saasbom.cdx.json` | Provider/catalog/API evidence, external dependencies, authentication, trust boundaries and classified data flows |
| AI-BOM | Local configuration, quantization/context, weight indexes, GGUF/safetensors headers/sizes, Ollama layers. Explicit artifacts receive full SHA-256. Output is `aibom.cdx.json` | Model identity/revision/weights, parent lineage, model cards/licenses, training/evaluation data sources |
| MBOM | Matching SLSA provenance or declared/reported physical assembly/testing becomes `mbom.cdx.json` `formulation` | CI steps/tools/inputs/outputs/run records or manufacturer assembly/process/inspection history |

## Collection layers

| Layer | Evidence and boundaries |
|---|---|
| OS packages | os-release/vendor release and RPM/DEB/APK DBs. Permissions, corruption and missing source-package/module-stream data can limit results. |
| Hardware/firmware | CPU/microcode/CPUID/topology/ARM identity, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM. Supported RAID/HBA, RDMA, GPU VBIOS and NIC ioctl fields vary by driver. megaraid_sas needs exports. BMC IPMI needs root/modules and vendor revision reconciliation. VM/container devices may describe the physical host. |
| External assets | Expanded Redfish, fwupd, devlink or common JSON files. Preserve reported version/state and review unmatched devices. |
| Windows/macOS | Native system/OS/firmware and installed-app metadata. Windows evidence includes cross-build checks. Internal application dependencies and vendor updates need additional inputs. |
| Runtime software | Executable/mapped-library file identity and package ownership within the same filesystem scope. Replaced files supply restart-review evidence. |
| Host identity | SHA-256 machine-id/DMI UUID/serial and explicit asset tag for host `/`. Serial permissions and shared placeholders affect availability. Hashing is pseudonymization. |
| Listening sockets | TCP LISTEN/bound UDP in the collector namespace, attributed via process FDs. Binding alone cannot determine firewall reachability. Unowned sockets remain `unattributedSockets`. |
| Settings/reboot | SELinux, AppArmor, lockdown, FIPS, allowlisted boot options, `y`/`m` kernel configuration, reboot-required, running module tree and newer same-family kernels. These observations need interpretation. An absent signal does not prove a reboot unnecessary. |
| SSH | Global declarations in sshd configuration files. `Match` is excluded and effective `Include` precedence is not calculated. |
| Taint/modules | `kernel.tainted`, `/proc/modules` flags and sysfs version/srcversion when provided. |
| Unknown executables | Same-root running files without package/component/product attribution. Other mount namespaces are excluded. Classification requires further investigation. |
| Package origin | apt Packages plain/gz/lz4, dnf history and yumdb. apt matches names. Deleted lists, dnf5 and apk are unsupported. URLs/local paths are omitted. |
| Boot services | systemd wants/requires, units/drop-ins and cgroup v1/v2. Only first ExecStart. Relative executables lack package association. Custom slices may appear stopped. SysV is unsupported. |
| Hardware CPE | Supported Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge device/BIOS, Lenovo ThinkSystem device. Dictionary/model gaps can prevent matching. HPE/BMC CPEs are omitted. |
| Package integrity | Executable/library hashes in RPM/dpkg/apk DBs. Excludes config/ghost files. Budgets are 8 GiB host and 1 GiB container. prelink may cause false mismatches. |
| CBOM/certificates | PEM/DER X.509, public keys/algorithms, JKS v1/v2 public chains and alias hashes. Encrypted key payloads are skipped and JKS integrity remains unverified. Subject/issuer names, private keys, PKCS#12 contents, distro trust stores and bundles over 20 certificates are excluded. |
| Kernel | uname, installed images/modules, vermagic and RPM versions. Running and installed kernels remain distinguishable. Missing module evidence may reflect built-in functionality. |
| Livepatch | Linux livepatch sysfs, Oracle raw Ksplice stage and optional Ksplice/Uptrack/Canonical helper reports. Boot/kernel/time mismatches invalidate application evidence. CVE applicability requires separate analysis. |
| Java | JDK/JRE release, JAR/WAR/EAR manifest and Maven metadata. Modified or removed shaded metadata can limit identification. |
| PHP | Package/interpreter, installed Composer and PEAR evidence. Lock-only uninstalled packages are excluded. Exploitability depends on configuration. |
| snap/flatpak/conda | snap current revision/meta and embedded DEB, flatpak active/AppStream, conda-meta. Generic snap/flatpak PURLs, absent versions without AppStream, conda channel names only. |
| Python | dist-info/egg-info, venv and actual `.pyz`/`.pex` bundle metadata. Removed/unreadable metadata limits collection. |
| Node.js/static JS | node_modules/runtime, jQuery/jQuery UI/Fancytree evidence in files and EAR/WAR/ZIP/JAR web resources. Filenames alone are insufficient. Supported layouts and scan limits apply. |
| Go/Rust | Go build info and cargo-auditable ELF dependencies. Missing data leaves dependencies unknown. Corrupt/oversized metadata produces partial results. |
| .NET | Published `.deps.json`, managed DLLs and standalone DLL version resources. Standalone DLLs receive no NuGet PURL. Single-file bundles need further verification. |
| Ruby | Installed specifications/gem files and default gems. Gemfile.lock alone or removed installation metadata is insufficient. |
| Native servers | Package/binary evidence for httpd, nginx, OpenSSL, OpenSSH, Redis, PostgreSQL, MySQL and MariaDB. Custom/stripped/static copies can remain unknown. |
| Java servers | Tomcat ServerInfo/manifest/catalina.jar. WebLogic/JBoss/WildFly product/install/patch metadata. `.patch_storage` alone does not prove active patches. JEUS/commercial versions lacking real fixtures remain unverified. |
| Stopped containers/images | Docker overlay2, containerd overlayfs including k3s/RKE2, rootful Podman/CRI-O overlay. Temporary reconstruction is bounded to 16 GiB/root and checked free space. Other drivers/rootless Podman are unsupported. No listening sockets. |
| Running containers | procfs roots and runtime disk metadata, individual `containers/<name>/` SBOMs. Excludes volumes/bind mounts and Kubernetes sandboxes. Invisible roots get a reason. No runtime API/socket connection. Only sockets owned by the container's processes are attributed. |
| Image archives | Explicit Linux amd64 Docker/OCI tar, archive hash and supported verified manifest digest. Scope is the image contents. Host kernel/runtime require separate observations. |
| AIX/Oracle | `aix-import` filesets, interim fixes, per-Home OPatch and optional SQL patch history from up to eight Homes on one AIX server. Execution state needs separate evidence. |

Manual installations retain directory/instance identity. Matching names and versions can still represent different locations or patch states. Undetermined CPEs are left unset. Use confirmed identifiers and their evidence for downstream review.

Default formats are CycloneDX 1.6 and SPDX 2.3, with optional CycloneDX 1.7. [Asset inventory and assessment](asset-inventory.md) explains `assess`, exact-version OSV/CSAF support and evidence schemas. [Additional BOM evidence](additional-bom.md) covers services, models and manufacturing.

## Regression scenarios

Regression cases exercise PHP runtime versus Composer, Node runtime versus node_modules, full JDK builds, WebLogic installation/patch identity, manual Tomcat and AJP/HTTP2 declarations, httpd/mod_http2 distro releases, nginx source/alias/rewrite declarations, separate OpenSSL CLI/libssl/libcrypto copies, and running versus installed UEK/RHCK kernels. A regression fixture supplies identification evidence. An advisory match is needed for a vulnerability conclusion.
