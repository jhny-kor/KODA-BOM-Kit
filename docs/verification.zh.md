# 构建与验证指南

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 提供 Linux amd64 离线压缩包和 SHA-256 校验文件。用可执行文件的精确哈希及运行环境识别验证对象。Linux 主机采集面向 x86_64 和 ARM64，Docker/OCI 归档采集面向 linux/amd64。macOS 和 Windows 资产清单使用固定的只读系统命令。Windows 实际运行尚未验证。历史 VM 结果对应各自记录的构建。

[发布 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 输出格式与完整性

默认输出为 CycloneDX 1.6 和 SPDX 2.3。`--cyclonedx-17` 从同一清单增加 1.7。与 `--format cyclonedx` 组合生成两份 CycloneDX，与 `--format spdx` 组合会在输出前拒绝。`scan`、`aix-import`、`asset-import`、`platform-inventory`、`reconcile` 和两个采集脚本支持此选项。根据所选选项核对预期文件。

| 输出 | 格式 |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` 检查本地模式、组件标识、证据、属性、许可证含义、依赖、范围、校验项遗漏或重复及哈希。1.7 模式固定到官方 1.7.1 提交 `b29bae660048e0ad2fbc5f2972927b442ce951c4`，来源记录在 `tests/schemas/provenance.json`。1.6 有 704 个许可证 ID，1.7 有 811 个。新增 107 个在 1.6 中保存为 `license.name`，在 1.7 中使用 `license.id`。模式通过后仍需检查 `collection.json` 的部分采集状态。

## 构建机检查

在构建机准备 Go、Python、Docker、Go 模块缓存及模式依赖。`trusted_go_sha256` 应为独立验证的 Go 可执行文件哈希。`GOPROXY=off` 使用预先准备的缓存。发布 QA 拒绝 `python3 -O` 或 `PYTHONOPTIMIZE`。目标服务器使用打包的可执行文件。macOS 校验命令为 `shasum -a 256 -c SHA256SUMS`。

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## 集成测试范围

对解压后的最终发行包运行以下命令。断网前准备所需上游缓存。.NET/Ruby 需要 .NET 10 SDK，Go/Rust 需要缓存及固定的 ripgrep ELF，也可指定 `--rust-binary`。Fancytree 使用固定的 npm SHA-512 或 GitHub SHA-256。支持的测试加上 `--tracker-root /path/to/tracker` 可验证本地真实 Tracker 解析器。

`domain_bom_integration.py` 直接运行目标二进制文件，请在 Linux amd64 上执行。

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/runtime_smoke_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

测试涵盖嵌套 Java、pyz/pex、Go/Rust、安装来源、目录边界、供应商哈希、PURL 和依赖。Linux 测试数据涵盖套接字、容器、固件解析、服务、设置、完整性及证书。AIX 测试检查 Oracle Home、Listener 和 OPatch。物理 BMC/NIC/OT、真实 Kubernetes 存储及已订阅补丁客户端需要现场证据。 GitHub Actions（`.github/workflows/ci.yml`）会在每次推送到 `main` 和每个拉取请求时运行格式检查、所有构建目标的 vet、Go 测试、发布防护、二进制检查以及上述无需上游缓存的容器测试；仅文档变更由 `docs.yml` 检查。发布构建、依赖缓存的上游测试和 VM 验证仍在构建主机上运行。

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/scripts)

## Linux 内核与 VM 复现

Linux 专用测试必须在 Linux 运行。macOS 可交叉编译并在相同架构的 Linux 容器执行。VM 使用最终发行包内的文件。Oracle RHCK `4.18.0-193.el8.x86_64` 和 UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` 分别启动。签名 RPM 固定在 `tests/oracle-vm/kernels.json`。保留输入来源、签名日志、QEMU 镜像 ID、串口日志、基线和验证报告。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle runner 使用 QEMU system TCG、4 GiB 内存、2 个虚拟 CPU 和专用静态 PID 1，来宾无网络或磁盘。检查 uname、proc、实际加载的 loop 模块、已安装与运行内核。Ubuntu 从已认证资料启动 `6.8.0-47-generic`。GRUB、UEFI/Secure Boot、完整 systemd 启动、SELinux enforcing、物理驱动及生产服务需另行验证。Oracle 容器共享宿主内核，只能验证其用户空间和 RPM 数据。

[Oracle VM](tests/oracle-vm/README.zh.md) · [Ubuntu VM](tests/ubuntu-vm/README.zh.md)

## 系统调用、资源限制与后续分析

在隔离的构建机容器追踪最终文件。ARM64 仿真无法解析 ptrace 寄存器时，`trace-network.sh` 返回 77。可使用 QEMU guest syscall 追踪，并注明环境。声称零次尝试必须有有效追踪。可选 livepatch 脚本调用现有供应商客户端，其守护进程与网络行为需另行评估。

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

默认限制是选中的普通文件 1,000,000 个和 30 分钟。分别测试限制、非法选项、取消、权限、损坏输入与排除路径。`--max-files 0 --timeout 0` 解除这两项限制。记录实际输入的耗时和峰值 RSS。并行度 2 不提供硬内存上限。Tracker 使用隔离临时数据库验证两种标准格式。本地安全公告评估依赖输入规则与观测。生产部署与 CVE 修复需要相应证据。

## 相关文档

[隔离网络中的运行与结果检查](air-gapped.zh.md) · [构建与验证指南](verification.zh.md) · [验证结果](verification-results.zh.md)
