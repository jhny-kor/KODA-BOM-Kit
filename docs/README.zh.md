<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.zh.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>使用单个离线可执行文件收集 Linux 主机上的软件、硬件及运行证据。KODA BOM Kit 生成七种 CycloneDX 物料清单、一份合并清单和一份 SPDX 软件清单。</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>下载 v0.1.8</b></a> ·
  原作者 <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">官方仓库</a>
</p>

## 快速开始

下载 Linux amd64 压缩包及对应的 SHA-256 校验文件，将两者复制到目标服务器的空目录，然后执行以下命令。目标服务器无需安装 Go、下载软件包或配置漏洞数据库。

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## 输出文件

最后一行显示在 `bom-output/` 下新建的目录。合并清单位于 `bom.cdx.json`，七份独立清单位于 `boms/`。

| 文件 | 记录内容 |
|---|---|
| `boms/sbom.cdx.json` | 已安装的软件包、库和应用程序 |
| `boms/hbom.cdx.json` | 设备、固件和驱动程序 |
| `boms/cbom.cdx.json` | 证书、算法等密码资产 |
| `boms/obom.cdx.json` | 观测到的服务、进程、套接字与软件包之间的关系 |
| `boms/aibom.cdx.json` | 本地模型文件、权重及提供的模型元数据 |
| `boms/saasbom.cdx.json` | OpenAPI 文档或服务清单中描述的服务，以及代理配置中声明的后端 |
| `boms/mbom.cdx.json` | 由输入证据描述的制造和构建流程 |

如果未找到相应证据，某份清单的条目可能为空。请查看该清单中的证据状态和 `collection.json` 了解原因。向 Tracker 提交顶层的 `sbom.cdx.json` 或 `sbom.spdx.json`。 默认输出 CycloneDX 1.6 和 SPDX 2.3。添加 `--cyclonedx-17` 可同时输出 CycloneDX 1.7。

重新合并时请复制整个 `boms/` 目录，保留清单、关系文件和校验和。将 `run_dir` 设置为采集结束时输出的路径。

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## 文档

- [离线部署与结果核查](air-gapped.zh.md)
- [采集命令与输出文件](collector-guide.zh.md)
- [硬件、密码与运行证据](asset-inventory.zh.md)
- [服务、AI 模型与制造流程清单](additional-bom.zh.md)
- [支持范围与采集限制](support-matrix.zh.md)
- [构建与验证步骤](verification.zh.md)
- [测试记录与验证范围](verification-results.zh.md)

### 源码与测试指南

- [导入外部资产](internal/assetimport/README.zh.md)
- [平台清单](internal/platforminventory/README.zh.md)
- [产品识别](internal/products/README.zh.md)
- [Oracle Linux VM](tests/oracle-vm/README.zh.md)
- [Ubuntu VM](tests/ubuntu-vm/README.zh.md)

## 许可证与署名

KODA BOM Kit 以 Apache-2.0 许可发布。原作者及随包分发的依赖项许可请参阅以下声明。 [Apache-2.0](../LICENSE) · [原作者声明](../NOTICE) · [第三方声明](THIRD_PARTY_NOTICES.zh.md)
