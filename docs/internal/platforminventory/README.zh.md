# 原生平台观测

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 的 `Collect(ctx)` 使用目标系统已安装的工具进行有界观测。命令参数固定，每条命令限时 60 秒、输出限额 32 MiB。写入 SBOM 前会筛选字段。序列号、UUID、用户名和应用完整路径会被排除。本地路径仅参与组件标识的哈希计算。

macOS 上使用 `/usr/sbin/system_profiler` 获取硬件、软件和应用元数据。采集器输出系统固件、OS 加载器、CPU 和应用，并在 OS 版本字符串中保留 OS 构建号。部分应用可能缺少版本或元数据。

Windows 上通过不加载配置文件的系统 PowerShell 读取 CIM computer、BIOS、OS、QuickFixEngineering 记录，以及计算机和当前用户的卸载注册表项。保留 OS 构建号和架构。QuickFixEngineering 仅覆盖自身报告的更新。注册表清单无法枚举每个用户配置文件、Store 应用或内嵌依赖。采集器会记录这些覆盖范围限制。

使用 `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory` 运行 macOS 原生验证。Windows 解析 fixture 和交叉编译验证源码结构。实际 Windows 执行验证需要 Windows 目标。
