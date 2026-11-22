# Ubuntu 24.04.1 真实内核 VM 验证

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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

这是 KODA BOM Kit 测试工具，不属于隔离网络部署可执行文件的依赖。它使用自定义 initramfs 直接启动 Ubuntu Base **24.04.1 amd64** 和官方 Ubuntu 内核 **6.8.0-47-generic / 包 6.8.0-47.47**。QEMU user-mode 或目录 fixture 无法建立真实内核启动证据。

Ubuntu Base 原件取自归档 Ubuntu 发行镜像站。使用 Ubuntu CD Image Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092` 验证 SHA256SUMS.gpg。通过已认证 rootfs 内的 Ubuntu archive keyring，验证官方 Snapshot 服务的 2024-10-18 noble-updates InRelease。验证链连接签名 Release → Packages.xz → 两个 DEB 的 SHA-256 和大小。保留所有输入 URL、校验和、签名日志和 Docker 镜像 ID。

构建主机需要 Go、Python 3/`jsonschema`、Docker、GnuPG（`gpg`/`gpgv`）。复用 Oracle VM 工具镜像。无需在目标服务器安装这些工具。在项目根目录执行以下命令，将 `<ID>` 替换为实际运行 ID。

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

`init.go` 复用 Oracle 工具的有界导出和独立 baseline 设计。Ubuntu 的 loop 驱动内置，因此测试加载真实 `dummy.ko` 验证模块观测。独立记录运行中的 uname、proc release、OS、采集器 SHA、已加载模块，再将两份 SBOM 与固定官方 schema、校验和、DEB 原始版本/source/PURL、已安装内核/模块对照。每次提供新的最终二进制时都要重新执行 prepare、run、validate。

测试 rootfs 用 `dpkg --unpack` 解包原始 DEB 并生成真实 dpkg 数据库。允许依赖覆盖后保留 unpack 状态，无法据此确认正常 apt 安装及配置已完成。完整 systemd 启动、GRUB、UEFI/Secure Boot、生产服务、物理硬件需另行验证。QEMU 不连接网卡或磁盘，Docker 使用 `--network none`、只读 rootfs 并移除 capability。实际商业或订阅 live patch 安装不在此测试范围内。

0.1.3 验证传入 `--max-files 0 --timeout 0` 解除采集器的两项限制。测试 PID 1 的独立 11 分钟 watchdog 和主机 QEMU 运行器超时仍然保留。

一并保留 provenance、签名日志、dpkg 日志、`command.json`、`serial.log`、`boot-report.json`、`baseline.json`、两份 SBOM 及 `validation.json`。部分采集退出码 3 保持为 3，不转成完整采集退出码 0。
