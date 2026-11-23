# 采集支持范围与证据限制

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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


本表描述可识别的证据。每次运行请查看 `collection.json` 的状态与原因。完整性取决于可读元数据、安装形式及权限。漏洞判断需要匹配公告证据。

## 七种CycloneDX BOM

默认主机 `/` 扫描在 `boms/` 生成独立文件并合并为 `bom.cdx.json`。`--cyclonedx-17` 增加1.7版。证据缺失会明确标记，包括 `no-evidence` 和未知覆盖范围。[CycloneDX分类](https://github.com/CycloneDX/specification#readme)

| BOM | 可用证据 | 补充资料 |
|---|---|---|
| SBOM | OS/语言包、版本/PURL、可得许可证/依赖、JAR、内置模块、容器 | 将供应者/CI CycloneDX或SPDX绑定产物SHA-256，补充静态/构建依赖，生成 `build-sbom.cdx.json` |
| HBOM | CPU/主板/设备/驱动/固件、EDAC DIMM和电源/风扇、SMBIOS内存模块（制造商/零件号/速度）、电源和插槽 | 不可见零件、零件号、供应者、生命周期的Redfish或资产台账 |
| CBOM | 公共证书/密钥/算法、验证的签发关系、TLS/SSH配置、JKS、SSH主机公钥、系统加密策略、OpenSSL协议/密码套件/组声明 | 实测TLS和HSM/KMS/保护密钥库的公开导出元数据 |
| OBOM | 主机/容器/进程/文件/包/套接字关系及systemd、每个进程的外部TCP连接目标、systemd定时器、cron任务、防火墙配置声明 | 同集群Pod/workload/Service/Ingress JSON、部署标签、主机身份匹配的 `--network-evidence` |
| SaaSBOM | 服务规范/OpenAPI生成 `saasbom.cdx.json`。也读取OpenAPI YAML及nginx/Apache/HAProxy配置中声明的后端 | 提供者/目录/API、外部依赖、认证、信任边界、分类数据流 |
| AI-BOM | 本地配置、量化/上下文、权重索引、GGUF/safetensors头/大小、Ollama层。明确产物的完整SHA-256。`aibom.cdx.json`。另观测ONNX头、PyTorch pickle导入安全性、Hugging Face模型卡/缓存ref、模型服务器启动时指定的模型 | 模型身份/修订/权重、谱系、模型卡/许可证、训练/评估来源 |
| MBOM | 匹配SLSA或物理组装/测试声明生成 `mbom.cdx.json` 的 `formulation` | CI步骤/工具/输入输出/执行记录，制造工艺/检验历史 |

## 各层采集

| 层 | 证据与限制 |
|---|---|
| OS包 | os-release/vendor release及RPM/DEB/APK数据库。权限、损坏、source package/module stream缺失影响结果 |
| 硬件/固件 | CPU/微码/CPUID/拓扑/ARM、DMI、BIOS/UEFI/ESRT、PCI、NVMe/SCSI、USB、TPM。RAID/HBA、RDMA、GPU VBIOS、NIC ioctl字段依驱动而变。megaraid_sas需导出，BMC需root/IPMI及厂商版本核对。VM/容器可能显示物理主机信息 |
| 外部设备 | 展开Redfish、fwupd、devlink、通用JSON。保留报告的版本/状态，复核未匹配项 |
| Windows/macOS | 系统/OS/固件/应用元数据。Windows验证包括交叉构建。应用内部依赖和厂商更新需额外输入 |
| 运行软件 | 同文件系统范围内的可执行文件/映射库与包归属。替换提供重启复核依据 |
| 主机身份 | 主机 `/` 的machine-id/DMI UUID/序列号SHA-256和显式标签。序列号权限及公共默认值影响可用性。哈希是化名化 |
| 监听套接字 | 同命名空间TCP LISTEN/绑定UDP和进程FD。仅绑定无法确认防火墙可达性，无归属项为 `unattributedSockets` |
| 外部连接 | 按进程和远程端点汇总本地端口不是监听端口的ESTABLISHED TCP，最多16,384个套接字。从固定本地端口连向对方临时端口的连接视为已接受的连接。只看到采集时打开的连接，仅限主机进程。连接到本主机监听端口的连接会关联到该监听套接字及其所属进程 |
| 计划任务 | `/etc/crontab`、`/etc/cron.d`、用户crontab、`cron.{hourly,daily,weekly,monthly}` 脚本，以及已启用systemd定时器的 `On*` 计划。只记录程序绝对路径，丢弃参数 |
| 防火墙 | iptables-save文件（RHEL/Debian/ufw）、firewalld默认区域及其服务定义、nftables input hook链和字面include。这些是文件声明，不读取内核已加载的规则。没有policy的base chain视为接受，`ENABLED=no` 的ufw记为 `disabled`，systemd单元已安装但既未启用也未运行或已被屏蔽的框架记为 `not-enabled`，两者都不视为生效。仅环回、已建立状态和否定规则不视为开放端口，协议范围的TCP/UDP接受视为开放该协议全部端口。主机网络命名空间中的非环回监听套接字带有 `firewall-declared`：`accept-declared`、`accept-declared-restricted`、`policy-accept-declared`、`no-accept-declared`、`undetermined`，未读取到有效声明时为 `none-observed`。容器套接字位于各自的网络命名空间，不带此值。容器通过NAT发布的端口经过FORWARD规则，不予评估 |
| 设置/重启 | SELinux、AppArmor、lockdown、FIPS、允许启动参数、内核 `y`/`m`、重启请求、运行模块、较新同系列内核。需解释观察结果，无信号不足以证明无需重启 |
| SSH | 全局配置声明，排除 `Match`，不计算 `Include` 生效优先级 |
| taint/模块 | `kernel.tainted`、`/proc/modules` 标志和sysfs version/srcversion |
| 未知可执行文件 | 同root内无包/组件/产品归属的运行文件。排除其他挂载命名空间，分类需进一步调查 |
| 包来源 | apt平文/gz/lz4、dnf历史、yumdb。apt按名称。删除清单、dnf5、apk不支持。省略URL/路径 |
| 启动服务 | systemd wants/requires、unit/drop-in、cgroup v1/v2。只取首个ExecStart，相对路径不关联包，自定义slice可能显示停止。SysV不支持。已启用的定时器记录 `On*` 计划和其启动的服务 |
| 硬件CPE | Intel Xeon/Core、AMD EPYC/Ryzen、Dell PowerEdge设备/BIOS、Lenovo ThinkSystem设备。字典/型号缺失可导致不匹配。省略HPE/BMC |
| 包完整性 | RPM/dpkg/apk可执行文件/库哈希，排除配置/ghost。主机8 GiB、容器1 GiB。prelink可能产生误报 |
| CBOM/证书 | PEM/DER、公钥/算法、JKS v1/v2公开链/别名哈希。跳过加密密钥，JKS完整性未验证。排除主体/签发者名、私钥、PKCS#12内容、发行版信任库及超过20证书的文件。另记录SSH主机公钥。`crypto-policies` 和 `openssl.cnf` 的MinProtocol/CipherString/Ciphersuites/Groups作为声明记录，不解析 `.include` 和节的启用 |
| 内核 | uname、安装镜像/模块、vermagic、RPM版。区分运行与已安装内核，未见模块可能因为功能内置 |
| 热补丁 | livepatch sysfs、Oracle raw Ksplice、可选Ksplice/Uptrack/Canonical helper。启动/内核/时间不匹配的证据不能证明生效。CVE需单独分析 |
| Java | JDK/JRE release、JAR/WAR/EAR manifest和Maven。shaded元数据被删改时只能部分识别 |
| PHP | 包/解释器、已安装Composer/PEAR。排除仅lock中未安装项，可利用性依赖配置 |
| snap/flatpak/conda | snap current及内置DEB、flatpak active/AppStream、conda-meta。snap/flatpak使用generic PURL，无AppStream时版本为空，conda只记渠道名 |
| Python | dist-info/egg-info、venv、`.pyz`/`.pex` 实际元数据。删除或不可读会限制采集 |
| Node.js/静态JS | node_modules/runtime，文件和EAR/WAR/ZIP/JAR中jQuery/jQuery UI/Fancytree。文件名不足以定版本，依赖支持布局和扫描上限 |
| Go/Rust | Go构建信息和cargo-auditable ELF。缺失信息则依赖未知，损坏/超限为部分采集 |
| .NET | `.deps.json`、托管DLL及独立DLL版本。独立DLL不发NuGet PURL，single-file需额外验证 |
| Ruby | 已安装specifications/gem及default gem。仅Gemfile.lock或元数据被删时证据不足 |
| 原生服务器 | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB包/二进制。定制、strip、静态副本可能未知 |
| Java服务器 | Tomcat ServerInfo/manifest/catalina.jar，WebLogic/JBoss/WildFly安装/补丁。仅 `.patch_storage` 不能证明补丁生效。无真实fixture的JEUS等标为未验证 |
| 停止容器/镜像 | Docker overlay2、containerd overlayfs/k3s/RKE2、rootful Podman/CRI-O。临时重建上限16 GiB/root并检查空间。其他驱动/rootless不支持，无监听套接字 |
| 运行容器 | procfs root及磁盘状态，`containers/<name>/` 独立SBOM。排除volume/bind mount及Kubernetes sandbox。不可见root记录原因，不连接API，只归属本容器进程套接字 |
| 镜像归档 | 明确Linux amd64 Docker/OCI tar、归档哈希、验证manifest digest。范围是镜像内容，主机内核/运行状态需另观察 |
| AIX/Oracle | `aix-import` fileset、临时修复、各Home OPatch及可选SQL历史。单AIX最多8 Home，执行状态需额外证据 |

手动安装保留目录/实例身份。同名同版本也可能有不同位置或补丁状态。无法确定的CPE留空，后续审核使用确定的标识和证据。

默认格式是CycloneDX 1.6和SPDX 2.3，可增加CycloneDX 1.7。[资产清单与评估](asset-inventory.zh.md) 说明 `assess`、精确版本OSV/CSAF及证据格式。[补充BOM证据](additional-bom.zh.md) 涵盖服务、模型和制造。

## 回归验证场景

覆盖PHP与Composer、Node运行时与node_modules、完整JDK构建、WebLogic安装/补丁、手工Tomcat与AJP/HTTP2、httpd/mod_http2发行包、nginx来源/alias/rewrite、OpenSSL CLI/libssl/libcrypto独立副本、运行与安装UEK/RHCK内核。回归样本检验识别证据，漏洞结论还需要公告匹配。
