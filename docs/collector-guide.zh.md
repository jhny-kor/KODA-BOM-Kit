# KODA BOM Kit — 采集命令与输出文件

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## 选择采集范围

在运行中的主机上执行，可采集操作系统、软件包、容器和有权读取的硬件信息。目录扫描仅采集指定目录树。镜像扫描读取已导出的 Docker 或 OCI 压缩包。每次运行选择一种输入。默认上限为一百万个普通文件和 30 分钟。`--max-files 0 --timeout 0` 可解除这两项上限，权限、文件系统边界和归档解析限制仍然有效。

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## 扫描一个或多个目录

脚本接受目标目录和可选的输出父目录，以 `--no-context` 运行，拒绝将 `/` 作为目标。带空格的路径需加引号。用 `--exclude-dir` 排除目录，用 `--exclude` 排除匹配模式。多个目标不能重叠，排除目录要写绝对路径。合并后仍会保留 `target-1`、`target-2` 和实际发现位置。

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## 读取内核热补丁证据

主机扫描从 sysfs 读取内核热补丁状态。可选脚本查询已安装的 Canonical Livepatch、Ksplice 或 Uptrack 客户端并清理其输出。导入的报告必须匹配本次启动和内核，且采集时间不超过 24 小时，才可作为当前状态。缺少条目不能判断某个 CVE 是否已修复。

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## 重建运行关系或合并清单

主机 OBOM 关联监听套接字、进程和已安装的软件包。本地绑定地址不足以确定外部可达性。可用 `--kubernetes-evidence` 或 `--network-evidence` 导入对应的观测。将 `set_dir` 设为拆分后包含 `bom-set.json` 的目录，保留关系文件和校验和。旧名为 `mlbom.cdx.json` 的已归档集合仍可合并。

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## 为其他清单提供证据

将 AI 采集器指向本地模型目录。SaaS 和制造流程需要提供服务或工艺清单。用 `--asset-evidence` 导入 Redfish 设备、固件或密码资产证据。仅在 SHA-256 一致时才会将构建清单与实物关联。输入格式见文末指南。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## 导入 IBM AIX 和 Oracle 记录

在 AIX 上运行采集脚本，然后在 Linux 分析主机上导入。提供 Oracle Home 所有者保存的 OPatch 输出，还可提供 DBA 导出的 SQL 补丁历史。支持最多八个不同的 Home。识别 Listener 版本需要同一 Home 的证据。应按对应厂商公告核实补丁 ID。

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## 识别已部署的依赖

npm 和 pnpm 通过实际安装位置、peer 解析结果及版本确定依赖。静态 JavaScript 识别覆盖 jQuery、jQuery UI 和 Fancytree。Go 使用内嵌构建信息，Rust ELF 读取 cargo-auditable 数据。.NET 将 .deps.json 与已部署的托管 DLL 对照，Ruby 使用已安装的 gemspec。Java 保留嵌套 WAR、EAR 和 Spring Boot 库的路径。坐标不明的条目保持未解析。

## 对照部署包与供应商清单

提供一个 WAR 或 EAR，并提供含该归档自身 SHA-256 的 CycloneDX 1.4–1.7 或 SPDX 2.3 文档。在 `reconcile.json` 中查看 `common`、`observedOnly`、`supplierOnly` 和 `unresolved`。向 Tracker 提交实测 SBOM。部署包上限为 512 MiB，供应商 SBOM 上限为 32 MiB。

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## 验证覆盖范围

在构建或测试主机上，用 KODA、Syft 和 Trivy 对照同一份未变动的部署。比较脚本需要 Python 3.11 或更高版本。通过 `--expected` 指定确认过的组件和依赖，通过 `--baseline` 检查回归。可选的 Tracker 测试会上传至指定测试服务。可通过 `--normalized-bom-command` 检查保存后的关系图。

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## 解读采集结果

将 `run_dir` 设为采集器输出的路径。退出码 0 表示完成，3 表示部分结果，2 表示失败。在 `collection.json` 查看上限、遗漏和错误，在 `context.json` 查看运行关系，在 `assets.json` 查看设备或证书证据。每个容器或镜像目录均有独立校验和。仅凭版本和日期无法判断漏洞状态。

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## 在独立主机构建

构建主机需要 Go 和 Python 3。此版本使用 Go 1.26.11。使用其他 Go 时需提供经过验证的可执行文件及其 SHA-256。离线构建需要已填充的模块缓存。发布的压缩包面向 Linux amd64，源码也支持构建 Linux ARM64。构建信息写入 `release.json`。

```sh
VERSION=0.1.9 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## 文档

- [离线部署与结果核查](air-gapped.zh.md)
- [硬件、密码与运行证据](asset-inventory.zh.md)
- [服务、AI 模型与制造流程清单](additional-bom.zh.md)
- [支持范围与采集限制](support-matrix.zh.md)
- [构建与验证步骤](verification.zh.md)
- [测试记录与验证范围](verification-results.zh.md)
