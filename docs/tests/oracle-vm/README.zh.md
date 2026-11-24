# Oracle Linux 8.2 内核直接启动验证工具

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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

`init.go` 是 KODA BOM Kit 的 **验证 VM PID 1**。`//go:build ignore` 使它不参与普通 Go 包测试。请使用下列命令显式构建。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python、Go、Docker 和 QEMU 是构建 PC 上的验证工具。将 `koda-bom` 可执行文件交付给隔离网络目标服务器。这套工具和 Python 解释器不是部署可执行文件的依赖。

## 复现步骤

运行器在 ARM64 构建主机的 QEMU 容器中通过 TCG 模拟 x86_64。客户机分配 4 GiB RAM、2 vCPU，容器内存上限为 6 GiB。在外部构建 PC 的项目根目录执行。将 `<ID>` 替换为 `run.py` 输出的实际 ID，并保留以往报告。

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

验证主机需要 `jsonschema`，使用 `tests/schemas` 固定的官方 schema 离线检查。准备阶段下载需要联网，内核 VM 无外部连接。标签对应镜像可能变化，因此保留实际使用的镜像 ID。

`prepare.py` 检查 [kernels.json](../../../tests/oracle-vm/kernels.json) 固定的 4 个 RPM（共 120,245,036 字节）的 SHA-256、大小及 Oracle Linux 8 签名密钥指纹。它向全新 Oracle 测试容器的 RPM 数据库导入公钥，用 `rpm -Kv` 检查签名，再以 `--nodeps --noscripts --notriggers` 安装内核。这会创建验证内核镜像、模块和 RPM 元数据所需的文件系统。正常安装脚本、dracut、GRUB 配置不在此流程中。

在已有工作目录以最终发布二进制重新运行 `prepare.py`，使用缓存的内核/RPM 文件系统重建采集器、验证 PID 1 和 initramfs。重新启动两个内核 VM，并将 **最终二进制 SHA-256** 与 baseline 对照。旧构建的 VM 结果无法验证新发布。

保留 `input-provenance.json`、`rpm-signature-install.log`，以及每次运行的 `command.json`、`serial.log`、`boot-report.json`、`validation.json`、`results/baseline.json`、两份 SBOM 和校验和。provenance 记录 RPM、内核、initramfs、PID 1、采集器哈希及 Oracle/QEMU 镜像 ID。另用发布验证报告将这些证据关联到发布归档的 SHA-256。

## 客户机准备

验证 initramfs 包含 Oracle Linux 8.2 文件系统、两个已安装内核的 RPM 数据库、`/boot` 内核镜像、两个 `/lib/modules` 树、待测 `/koda-bom` 和本工具 `/init`。RHCK、UEK 必须各自通过自己的内核镜像直接启动。仅运行容器或 QEMU user-mode 不能建立这项启动证据。可以将从官方内核 RPM 提取且版本匹配的模块放到以下位置。

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

工具记录模块 SHA-256，并通过 `init_module` 尝试加载。模块缺失、已加载或因签名与依赖失败时，分别记录状态和错误。比较 `loadedModulesAfter` 与采集器的 `loadedModules` 来确认实际加载。未观测到模块不能证明功能不存在。

QEMU 不连接外部网卡或虚拟磁盘。运行器使用 `-accel tcg,thread=single -cpu max -smp 2 -m 4096`。测试客户机使用 `random.trust_cpu=on` 避免早期启动 `getrandom` 等待。此参数不是生产配置建议。在主机端保留实际 CPU/加速模式及内核、RPM、initramfs、采集器校验和。

## 运行与采集

工具挂载 `/proc`、`/sys`、`/dev`、`/tmp`、`/results` 并设置合成主机名。独立 baseline 记录 uname、`/proc/sys/kernel/osrelease`、OS release、模块加载前后列表、VM 内核命令行、采集器校验和。主机名和内核命令行仅用于此合成 VM 证据，产品常规采集政策保持原样。采集器按以下命令运行一次。

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

不传 `--target /payload`，使用默认 live-host 模式。0.1.3 验证将文件数和时间上限设为 0 以解除限制。验证 PID 1 的独立 11 分钟 watchdog 和主机 QEMU 超时保留以回收资源。stdout、stderr 各限 1 MiB，写入独立文件。退出码、用时和错误保存至 `/results/baseline.json`。退出码 3 表示部分采集，必须保留为 3。

结果通过串口输出，在下列标记之间以 **base64(gzip(tar))** 传输。

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

若未压缩总量超过 256 MiB 或 10,000 个文件，仅导出说明失败原因的 baseline。导出后尝试 sync 和 poweroff。失败时 PID 1 保持运行以避免 kernel panic。客户机超时时由主机运行器终止 QEMU。

## 必须检查的项目

- baseline 的 uname 与 proc release 一致，RHCK/UEK 分别启动预期版本。
- `context.json.mode=live-host` 和 `runningKernel` 与独立 baseline 完全一致。
- UEK 报告 `kernelFlavor=UEK`，RHCK 按当前输出约定报告 `RHCK-compatible`。
- 原生清单保留两个已安装内核及各 RPM 的 epoch/version/release/arch/source package。
- 区分已安装内核与 context 标识的当前运行内核。
- 模块 `metadata.kernelVersion`、`versionMagic` 与各安装树匹配，已加载模块列表与活动内核 baseline 一致。
- 两份 SBOM 的 schema 与校验和通过，采集失败和部分状态如实报告。

## 验证范围限制

- 启动真实 Oracle RHCK/UEK 客户机内核。物理 x86_64 服务器验证需要另行执行。
- 以自定义 initramfs 运行 Oracle Linux 8.2 用户空间及官方内核。完整 systemd 启动、GRUB 安装、UEFI/Secure Boot、SELinux enforcing、生产服务集成不在测试范围内。
- `loop` 测试检查一个真实模块的加载与观测，不覆盖所有驱动和硬件。不得将非活动内核的已安装模块视为已加载。
- 接受退出码 `3` 和 `collection.status=partial`，同时保留原因。内核识别、标准输出和完整性检查通过不代表已完整采集所有文件。
