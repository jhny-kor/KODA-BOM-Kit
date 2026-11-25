# 硬件与软件资产清单

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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


使用为目标OS和CPU构建的 `koda-bom`。Linux的 `scan` 采集包和主机硬件。Windows/macOS的 `platform-inventory` 调用操作系统提供的本地清单工具。

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

Windows PowerShell使用 `.\koda-bom.exe platform-inventory --output-dir .\reports`。Linux目录/镜像扫描以指定文件系统为范围。运行硬件在启用上下文的主机 `/` 采集中观察。Docker/OCI归档支持Linux amd64镜像。将验证后的CycloneDX文档导入Tracker，并共同保存两个版本及校验和。

## 采集的证据

| 领域 | 内容及解释 |
|---|---|
| 硬件 | CPU/微码、缓解措施、主板、BIOS/UEFI、ESRT、PCI/驱动、NVMe/SCSI、USB和TPM。读取公开的RAID/HBA `mpt3sas`、`qla2xxx`、`lpfc`、`hpsa`、`smartpqi`，RDMA `fw_ver`，NVIDIA Video BIOS，amdgpu `vbios_version`。NIC使用相当于 `ethtool -i` 的只读ioctl。megaraid_sas需要导出证据。以root运行时，从SMBIOS原始表读取内存模块的制造商、零件号、容量和速度，电源型号和额定功率，以及系统插槽及其PCI地址；序列号仅记录SHA-256 |
| BMC | 通过 `/dev/ipmi0` 的只读IPMI `Get Device ID`，需要root及 `ipmi_si`/`ipmi_devintf`。记录固件修订、IANA制造商、产品ID和辅助修订。缺失设备给出原因，需要时用Redfish核对厂商构建标签 |
| CPU标识 | x86 `cpuidSignature`、`familyModelStepping`、插槽/核心拓扑，ARM厂商/核心名及 `r3p1` 类修订。未知ARM保留原始标识。USB `bcdDevice` 保持设备发行标识含义 |
| 外部资产 | 展开的Redfish对象、fwupd、devlink JSON和下方通用格式。运行/存储固件分别保留，字段取决于厂商型号 |
| 运行状态 | 可执行文件/共享库替换、文件标识和唯一识别的归属包。替换产生 `restart_review`，已安装版本不足以确定内存版本 |
| 主机身份 | 主机 `/` 上machine-id和DMI UUID/产品/主板序列号的规范化SHA-256，`--no-context` 时也采集。machine-id/UUID转小写，序列号去首尾空格。公共默认值和全零UUID省略。哈希属于可能被猜测的假名化。`--asset-tag` 原样记录最多128字符的单行标签。容器范围为 `container-visible` |
| 套接字 | 采集器网络命名空间内TCP LISTEN和未连接UDP，通过进程FD归属。`bindScope` 为 `all-interfaces`、`loopback`、`address`。防火墙/路由可达性需另外证据。无归属项写入 `context.json.unattributedSockets`。主机进程已建立的外部TCP连接按进程和远程端点记录在 `outboundConnections`，并带 `remoteScope`（`loopback`、`private`、`link-local`、`public`、`local-host`） |
| 安全与重启 | SELinux当前/配置模式、AppArmor启用/配置数量、lockdown、FIPS、允许的启动参数。排除凭据和无关参数。`kernelConfig` 读取 `/proc/config.gz` 或 `/boot/config-<running-kernel>` 的 `y`/`m`。重启请求、运行内核模块缺失、同系列较新内核作为信号，有信号则 `reboot.recommended=true`，否则 `not_observed`。系列匹配基于发行字符串推断 |
| SSH | `sshd_config` 与 `sshd_config.d/*.conf` 全局声明，包括 `PermitRootLogin`、`PasswordAuthentication`、`PermitEmptyPasswords`、`KbdInteractiveAuthentication`、`LoginGraceTime`、`MaxStartups`、`X11Forwarding`、`AllowTcpForwarding`。排除 `Match`，生效值取决于 `Include` 顺序 |
| 模块与未知程序 | `kernel.tainted` 和 `taintedModules` 记录名称、`O`/`E`/`P`、version/srcversion。同一root且无包/组件/产品归属的程序写入 `unidentifiedExecutables` 路径/PID。考虑usr-merge路径 |
| 完整性 | 比较RPM/dpkg/apk数据库哈希与可执行文件/`.so`。排除配置和ghost。`modified`/`missing` 记录于 `collection.json.integrity.findings` 和组件属性。主机预算8 GiB、每容器1 GiB，用尽标记 `partial`。prelink可能造成差异 |
| 包来源 | apt Packages平文/gz/lz4按名称匹配，dnf历史和yum `from_repo` 提供仓库ID。分类为 `repository`、`local-file`、`not-recorded`。缺少历史、dnf5、apk不支持。省略仓库URL/本地路径，dnf DB复制到临时目录只读打开 |
| 启动服务 | systemd wants/requires、unit/drop-in、首个 `ExecStart`、socket激活、包PURL。排除被屏蔽unit，主机以 `system.slice` 进程判断运行。自定义slice可能显示停止。已启用的定时器记录 `On*` 计划和其启动的服务 |
| 硬件CPE | 支持Intel Xeon/Core、AMD EPYC/Ryzen、Dell PowerEdge设备/BIOS、Lenovo ThinkSystem设备模式。未知型号、HPE、BMC不猜测CPE |
| 证书 | 公共X.509指纹、有效期、算法、密钥长度、状态。弱项包括SHA-1/MD5、低于2048位RSA、DSA。经典算法 `nistQuantumSecurityLevel=0`。排除主体/签发者名称与私钥，跳过发行版信任库及超过20证书的文件。另记录SSH主机公钥（`etc/ssh/ssh_host_*_key.pub`）及其OpenSSH SHA-256指纹 |
| 应用 | 当前snap及内置DEB、active flatpak/AppStream、conda渠道名、`.pyz`/`.pex`、JAR、静态JS、Go/Rust。保留Docker/OCI产物哈希和可验证摘要 |

## 容器与输出

运行容器分别写入 `containers/<name>/`。Kubernetes使用namespace、pod、container，重名时增加ID前12位。读取Docker/containerd/Podman/CRI-O磁盘元数据，不连接运行时API。通过mountinfo设备号定位root，包含镜像/写层，排除volume/bind mount。套接字归属本容器进程，包所有权优先，Go使用main module。不可见root/超时记录带原因的 `not_collected`。`--no-containers` 禁用该采集。

停止容器和未使用本地镜像支持Docker overlay2、containerd overlayfs（含k3s/RKE2）、rootful Podman/CRI-O。复制到输出临时目录，应用whiteout/opaque后采集并删除副本。排除设备文件和set-ID位。root超过16 GiB或可用空间小于root大小+1 GiB则跳过。结果为 `state: stopped` 或 `state: image`，不包含监听套接字。并发变化可能导致采集失败。其他Docker驱动和rootless Podman不支持。`--no-images` 禁用该路径。

默认在 `boms/` 生成7种BOM并合并为 `bom.cdx.json`。AI-BOM使用 `aibom.cdx.json`。兼容输出为CycloneDX 1.6 `sbom.cdx.json` 和SPDX 2.3 `sbom.spdx.json`，`--cyclonedx-17` 增加1.7文件。SPDX缺少专用类型时使用 `OTHER` 和注释。主机身份为 `koda:host:*`，容器为 `koda:container:*`，套接字为 `koda:runtime:listening`/`koda:runtime:bind-scope`。检查 `assets.json`、`context.json`、`collection.json`、`inventory.syft.json`，使用 `SHA256SUMS` 验证。

## 通用资产证据

最多8个文件，每个8 MiB。`parentId` 引用同文件 `id`，未知版本省略。Redfish需要展开URI列表后的设备/固件对象。输入SHA-256标识导入文件。

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

## 密码资产与TLS会话

X.509、公开密钥、算法生成 `cryptographic-asset`。候选签发者关系会验证签名。Nginx/Apache/sshd允许指令记录配置证据。JKS v1/v2记录公开证书链和别名SHA-256，跳过加密密钥，无密码完整性为 `not-verified`。

通过 `--asset-evidence` 导入PKCS#12/HSM/KMS公开元数据。`related-crypto-material` 可包含密钥类型/大小/状态、`algorithmRef`，以及 `properties.storageType` 和 `keyAlias`。使用方 `dependsOn` 指向同文件的密钥元数据。

以下为独立测量的TLS协商示例。以实测指纹、端点和时间替换示例值。证书哈希一致时建立服务→协议→证书关系。

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

## 离线安全公告评估

用同一程序及新公告重新评估存档结果。

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`、`--context`、`--kev` 可选。使用context时对照本次 `SHA256SUMS` 验证SBOM和上下文。KEV提供优先级信息。支持下方显式规则、精确受影响版本/PURL的OSV、精确产品ID/无条件状态的CSAF 2.0。未支持的范围、条件或产品组合会停止并说明原因。

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

使用包含发行版本的distro ID和精确包版本。SBOM/PURL版本冲突为 `review_required`，考虑RPM epoch。每次最多1,000,000条精确版本。显式规则支持 `supportEndsAt` 和受支持生态的 `affectedSemver`。替换文件/存储固件需要激活复核，未知设备/公告外版本需人工审查。物理Linux和Windows设备须核对厂商清单。Windows/macOS原生采集主要覆盖OS、硬件、已安装应用。

报告的 `risks` 数组以来源 `KODA collection evidence` 列出采集器已记录在BOM中的风险。这些风险无需安全公告文件，并与安全公告的 `findings` 分开。`sbom.cdx.json` 和 `sbom.spdx.json` 包含密码学风险，合并的 `bom.cdx.json` 还包含AI-BOM和OBOM风险。在 `bom.cdx.json` 中，安全公告跳过重复主机软件包的OBOM节点，运行中容器的软件包则通过其OBOM节点匹配，但仅覆盖其进程使用的软件包。容器的完整清单请评估 `containers/<name>/sbom.cdx.json`。`risk_observed` 表示记录的证据显示该状况；`review_required` 表示无法排除该状况。

| 发现ID | 状态 | 记录的证据 |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | 使用低于2048位RSA或DSA的证书或SSH主机密钥 |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | 使用MD5或SHA-1签名的证书（采集器确认为自签名的除外） |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | 允许低于TLS 1.2协议的配置，或LEGACY系统加密策略 |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | 模型文件或模型目录检查点中的pickle导入了可执行代码的可调用对象 |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | pickle导入了允许列表之外的模块，或检查未完成 |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | 声明的防火墙规则允许的非环回主机监听；来源受限、无法评估的规则或没有有效防火墙声明（`none-observed`）时需要复核 |

## NIS-SBOM表

`nis-sbom`将收集到的CycloneDX SBOM转换为NIS-SBOM 1.0的20个基本项目（韩国《SW 공급망 보안 가이드라인 1.0》表35）。该指南只规定项目和表格形式，没有规定文件模式，因此结果是每个软件组件一行的UTF-8 CSV。只列出软件组件。硬件、文件和密码资产不包含在内。

```sh
./koda-bom nis-sbom \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --organization EXAMPLE \
  --output ./nis-sbom.csv
```

`--organization`和`--sequence`（默认值1）组成SBOM ID `EXAMPLE-YYYYMMDD-000001`。`--product`、`--product-version`和`--author`用来替换扫描目标名称和收集器名称。供应商使用SBOM中记录的值，没有时使用PURL命名空间。哈希只列出SHA-256及以上。`SBOM Type`采用SBOM中记录的生命周期阶段，没有记录时为`Deployed`。`SPDX Doc. ID`和`Component Alias`保持为空。收集器不比对漏洞，因此`Vul. DB`和`Vul. Info`也保持为空。电子表格可能当作公式执行的值，前面会加上`'`。

## TCP可达性观察

`--network-evidence` 将已有TCP测量与主机或存档OBOM套接字匹配。`hostField` 为 `machineIdSha256`、`productUuidSha256` 或明确分配的 `assetTag`。`scope` 为 `host` 或完整64位容器ID。

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

结果支持 `connected`、`refused`、`timed-out`。归属不明确或套接字不存在时保留为未匹配。每个测量位置和时间需要独立观察。采集器不主动探测连接。[支持矩阵](support-matrix.zh.md) · [补充BOM证据](additional-bom.zh.md)
