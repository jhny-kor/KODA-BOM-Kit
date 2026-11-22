# 验证结果

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

本页记录 KODA BOM Kit 及旧版本的验证日期、构建哈希、环境、部分结果与未验证范围。当前 0.1.8 的压缩包、哈希及运行范围以官方发布条目为准。新可执行文件需要对应的测试证据。

[发布 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 2026-11-21 — 拆分与合并

`f0610ca-worktree-00ed83f2acd8` 对两份 0.1.6 归档验证了 `scan --separate-boms`、`bom-split`、`bom-merge`、`domain-bom`。独立比较所有原始组件和关系，每次合并新增一条清单根与运行根之间的关系。Ubuntu 的 10 对证书 ID 属于不同文件位置，保留全部 20 条记录，合并后重复 ID 为零。Linux ARM64 使用四种观测 BOM 和合成 OpenAPI、模型、SLSA、制造输入，同时将真实 TCP 18443 监听关联到 Perl 及其包。模式和哈希通过，签名及现场证据真实性需另外核实。

| 归档 | 组件 原始 / 合并 | 关系 原始 / 合并 |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — 运行关系

`f0610ca-worktree-06f22395e26f` 从两份部分采集归档重建 OBOM。套接字按命名空间和进程分别计数。Debian ARM64 将 `127.0.0.1:18443/tcp` 关联到 `/usr/bin/perl` 和 `perl-base`，检查 3 个 Redfish 部件号、TLS 声明示例、2 条构建关系、11 个校验和。重建 OBOM 逐字节一致。5 个合成 Kubernetes 资源关联到归档的完整容器 ID。生产集群、物理清单和真实 TLS 会话未验证。

| 归档 | 容器 | 套接字 主机 + 容器 | 包关联 主机 + 容器 | 对照关系 |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — Daybreak 12 项修复

针对旧 KODA-SBOM-Maker `cc86c1b` 的发现完成处理。范围包括隔离 Go 设置、对解压的同一输入计算哈希、256 层上限和复用哈希、限制 ZIP/ZIP64 索引、校验 whiteout、独占输出目录、公告匹配索引与工作量上限、拒绝 Python 优化模式、验证根内读取、安全处理短 ID、识别 RPM epoch 冲突、每批 256 项且可取消的目录遍历。

macOS ARM64 的 Go、vet 和发布守卫通过。Go 1.26.11 / Syft 1.57.1 离线构建静态 Linux amd64 文件，306 项校验通过。断网 Debian 的 CLI 与目录测试通过。修改前后保留 88 个包、1 个 OS、20 个设备、15 个驱动，两次均为带限制说明的 partial。其他平台通过交叉编译，实际运行和新内核 VM 回归不在本轮范围。

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Docker Desktop `7.0.14-linuxkit` 中 Linux、Go 和 vet 通过。CPU 与 lscpu 一致，读取 1,736 个内核选项。Debian 147 个包中仅 1 个本地包未记录，Rocky 识别 167 个仓库包及本地、无记录安装。9 个运行容器、14 个停止容器、11 个闲置镜像生成 35 份合格 SBOM，约 3 分 30 秒。对应包数 796、71、51 一致。overlay2 保留写入层 curl 并采集闲置 busybox。被删除的临时容器标为 `not_collected`。真实 x86、systemd、Kubernetes/k3s/Podman/CRI-O 及新 VM 未验证。

## 2026-11-19 — 0.1.6

在 Debian 12、Linux ARM64、Docker Desktop `7.0.14-linuxkit` 测试。确认主机哈希、真实监听、16 个运行 Docker 容器及 5 个树外内核模块。735 个文件约 89 MB 的完整性检查准确发现 1 个故意修改和 1 个移动/缺失文件。RSA-1024、ECDSA P-384 检查有效期与弱密钥，并避免输出私钥。硬件、snap/flatpak/conda、部分安全设置使用合成资料。物理 RAID/NIC/BMC、生产 SELinux、其他运行时和新 VM 未验证。

## 2026-11-18 — 0.1.6-dev

Go、vet、脚本限制和语法检查通过。Linux amd64/ARM64 采集与真实 macOS ARM64 基础资产输出通过模式和校验和。Windows 仅交叉编译。检查已删除/替换文件、镜像哈希和本地公告规则。Tracker 本地解析器成功读取两种 CycloneDX。生产部署与浏览器未验证。704/811 个许可证 ID 和新增 107 个的语义被保留。校验文件数量随采集范围变化。

## 0.1.2–0.1.5 历史版本

0.1.5 增加 pnpm 和 Maven POM 关系，0.1.4 增加目录脚本，0.1.3 增加文件/时间限制。用哈希关联提供的 `release.json`、`VERIFICATION.json`、`dist/evidence/v0.1.x/final-verification.json`。0.1.2 为最终文件重新运行 Ubuntu 和两种 Oracle 内核。订阅客户端安装及真实补丁应用不在合成脚本测试中。

## 2026-10-29 — 实现与 Oracle VM

初始实现通过 68 项 Linux 检查及 vet。uid 65534、只读文件系统、无 capability、断网环境中验证模式、PURL、canary、失败状态和哈希。Oracle 容器包含 RPM 182、Python 5、binary 2。guest syscall 的网络及额外 execve 尝试均为零。隔离 SQLite Tracker 的两种上传均为 HTTP 202。小型 0.1.0 样本在仿真中耗时 0.78 秒、峰值 RSS 219,644 KiB。

Oracle Linux 8.2 VM 启动签名 RHCK/UEK，uname/proc 与实际 loop 模块一致。各有 5,516 个组件，含 RPM 186、内核 2、模块 5,321、Python 5、binary 2。模块树为 RHCK 2,478、UEK 2,843。两种模式与各 5 项校验通过。退出 3、partial、context completed，保留受保护文件、范围外链接、OpenSSH 冲突和 Syft 警告。

| Kernel | 采集 / 总秒数 |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## 证据边界

初始 VM 使用下列 0.1.0 哈希。后续发行版各有自己的报告。物理 x86、完整 OS/服务集成、真实供应商补丁尚未覆盖。QEMU guest trace 与原生 ptrace 环境不同。实时文件采集可能跨越修改时点，宜选择低变更窗口或只读快照。包版本与未观测结果本身不能确认 CVE 适用性或修复完成。

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## 相关文档

[隔离网络中的运行与结果检查](air-gapped.zh.md) · [构建与验证指南](verification.zh.md) · [验证结果](verification-results.zh.md)
