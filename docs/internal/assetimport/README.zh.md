# 离线设备证据

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

KODA BOM Kit 的 `Load` 读取一个普通 JSON 文件，最大 8 MiB、4096 条记录。它支持 fwupd `get-devices --json` 导出（`Devices`）、展开的 Redfish `SoftwareInventory`、`Manager`、`ComputerSystem` 对象及其集合。仅含 URI 的 Redfish 成员会产生采集不完整问题。导入值属于管理员导出的观测结果。固件 `ImageState` 在可用时保留，否则保持未知。导出文件的哈希用于标识证据字节，不能认证其来源。

Windows、macOS、OT 及其他清单提供方可以导出以下显式格式。

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id":"board", "kind":"device", "name":"Controller", "vendor":"Vendor", "model":"Model", "revision":"A"},
    {"id":"firmware", "parentId":"board", "kind":"firmware", "name":"Controller firmware", "version":"1.2", "properties":{"applicationState":"Active", "storedVersion":"1.3"}}
  ]
}
```

支持的类型为 `device`、`firmware`、`device-driver`。允许的属性为 `runningVersion`、`storedVersion`、`versionFormat`、`rawVersion`、`applicationState`、`platform`、`productCode`、`pciVendor`、`pciDevice`、`pciSubsystem`、`updateState`。ID 限定在证据摘要范围内，避免意外合并不同导入。固件版本缺失会产生采集不完整问题。不会推断 CPE。观测时间描述源导出的时间，省略时保持未知。

通用格式还支持 `library`、`application`、`operating-system`、`container`。可选 `purl` 会被解析，其中的版本必须与显式版本一致。qualifier 限于 `arch`、`distro`、`epoch`、`type`、`classifier`。可选 `sha256` 必须是 64 个十六进制字符，用来标识导入组件。导入器另行计算证据文件的哈希。Windows 和 macOS 可以使用原生平台清单命令。其他提供方的补充证据可使用本格式。

`devlink -j dev info` 导出通过 `info` 对象导入。总线引用用于标识条目，fixed、running、stored 版本组分别保留。报告的运行中 `fw` 用作组件版本。驱动程序特有的其他版本键保留在属性中。缺少 `fw` 会产生版本未知问题。序列号会被排除。
