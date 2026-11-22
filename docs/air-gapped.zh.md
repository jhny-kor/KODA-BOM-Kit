# 隔离网络中的运行与结果检查

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 离线包面向 Linux x86_64 (amd64)、内核 3.2 及以上。从官方发布下载压缩包和配套 `.tar.gz.sha256`。目标服务器无需新增 Go、Python、Docker 或 jq。NOTICE 标注 jhny-kor 和官方仓库。

[发布 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 校验与解压

将唯一匹配的压缩包和校验文件放在可执行的本地目录。解压前检查归档，解压后检查内部文件。校验和确认传输字节，来源应为可信官方发布。USB 的 noexec 挂载需要复制到允许执行的本地文件系统。

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## 检查主机

检查架构、运行内核和 `doctor`。`supported=true` 表示满足运行前提。`doctor.kernel` 和 `context.json.runningKernel` 记录内核。即使 `kernelFlavor=unknown/unconfirmed`，内核版本仍可能已记录。root 权限可扩展 DMI、BMC、进程和容器可见范围。

```bash
uname -m
uname -r
./koda-bom doctor
```

## 选择采集范围

无参数运行 `koda-bom` 会在 `bom-output/` 建立新目录，生成合并的 `bom.cdx.json` 和 `boms/` 下七种文件。AI-BOM 名为 `aibom.cdx.json`。内容及完整性取决于可读本地证据。Qwen 使用实际模型路径。H100 信息在 HBOM，模型配置、头部和安装包不能确定当前 GPU 分配或实际服务配置。

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

目录采集使用 `--no-context`，输出应位于输入范围外。目录脚本拒绝 `/`。单目录脚本的 `--exclude-dir` 可用相对路径，多个目标不能重叠且排除目录须用绝对路径。文件和时间限制由全部目标共享。选定范围外的依赖可能无法观测。

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Livepatch 采集

可选脚本查询已有 Ksplice、Uptrack、Canonical 客户端，清理证据后执行 scan，并在结果旁保存清理后的证据。立即保存 `$?`。客户端查询上限为 30 秒，有效内核查询为 10 秒，解除 scan 超时不会解除这些上限。供应商客户端与守护进程有各自的网络行为。

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## 限制与退出状态

默认选中普通文件上限 1,000,000 个，时间 30 分钟。`--max-files 0 --timeout 0` 解除这两项限制，Ctrl+C 可取消。权限、排除、符号链接边界、单文件 2 GiB 及镜像解压限制仍适用。`--no-containers` 跳过容器和闲置镜像，`--no-images` 跳过停止容器和闲置镜像。0 为完成，3 为部分采集且有结果，2 为失败。其他异常退出也需检查。

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## 定位与验证结果

使用命令打印的实际结果目录。脚本先输出 doctor 与证据，最后输出结果路径。将 `result` 设为此路径。root 创建的文件可能需 sudo 查看。检查根清单和各容器/镜像清单，并保留部分采集原因。

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## 读取采集与补丁状态

`collection.json` 记录 `status`、`packageCount`、`packageTypes`、`limits`、`filesystemFileCount`、`issues`、主机标识、来源、完整性及容器状态。文件数为遍历选中的普通文件。`file_limit_exceeded` 包含 `limit` 和 `observed`。`context.json` 保存内核、进程、监听、服务、设置及补丁，`assets.json` 保存硬件、固件及证书证据。

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` 为内核直接观测，`reported-applied` 为客户端报告。`disabled`、`transitioning` 保留对应状态。`stale`、`identity_mismatch`、`unknown` 需要更多证据。结合当前状态和 `patches[].state`，因为 `reportedState` 可能保留旧报告。超过 24 小时、不同启动/内核、超限未来时间不能证明当前应用状态。还要检查 Canonical Last-Check/CheckState。未观测及 `not-reported-patched` 需结合内核/供应商证据解释。

`integrity.findings[].state=modified` 或 `missing` 表示内容不符或缺失。`bindScope=all-interfaces` 表示绑定范围，防火墙暴露需另行检查。`unidentifiedExecutables` 表示无法关联安装包，`reboot.recommended=not_observed` 表示未见重启信号。结合身份、上下文和限制解释结果。

## 供应商对照与保存

WAR/EAR 供应商 SBOM 必须绑定实际 SHA-256。缺失或不符时退出 2。检查 `reconcile.json` 和部分采集原因。保存包含清理后 livepatch 证据的完整父目录，并计算导出归档校验和。

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## 上传与后续分析

向兼容 Tracker 提交 `sbom.cdx.json` 或 `sbom.spdx.json`。容器/镜像各有自己的标准 SBOM。collection、context、Syft 清单作为附件证据保存。上传超时单独配置。采集为公告分析提供输入，当前补丁效果和 CVE 修复需独立证据。历史 VM 和各发行版测试范围见验证记录。

## 相关文档

[隔离网络中的运行与结果检查](air-gapped.zh.md) · [构建与验证指南](verification.zh.md) · [验证结果](verification-results.zh.md)
