# 離線裝置證據

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
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

KODA BOM Kit 的 `Load` 讀取一個一般 JSON 檔案，最大 8 MiB、4096 筆記錄。它支援 fwupd `get-devices --json` 匯出（`Devices`）、展開的 Redfish `SoftwareInventory`、`Manager`、`ComputerSystem` 物件及其集合。僅含 URI 的 Redfish 成員會產生收集不完整問題。匯入值屬於管理員匯出的觀測結果。韌體 `ImageState` 在可用時保留，否則維持未知。匯出檔案的雜湊用來識別證據位元組，無法認證來源。

Windows、macOS、OT 及其他清冊提供者可以匯出以下明確格式。

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

支援的類型為 `device`、`firmware`、`device-driver`。允許的屬性為 `runningVersion`、`storedVersion`、`versionFormat`、`rawVersion`、`applicationState`、`platform`、`productCode`、`pciVendor`、`pciDevice`、`pciSubsystem`、`updateState`。ID 限定於證據摘要範圍，以免意外合併不同匯入。韌體版本缺漏會產生收集不完整問題。不會推斷 CPE。觀測時間描述來源匯出的時間，省略時維持未知。

通用格式也支援 `library`、`application`、`operating-system`、`container`。選填的 `purl` 會被解析，其中的版本必須與明確指定的版本一致。qualifier 限於 `arch`、`distro`、`epoch`、`type`、`classifier`。選填的 `sha256` 必須是 64 個十六進位字元，用來識別匯入元件。匯入器另外計算證據檔案的雜湊。Windows 和 macOS 可以使用原生平台清冊命令。其他提供者的補充證據可使用本格式。

`devlink -j dev info` 匯出透過 `info` 物件匯入。匯流排參照用來識別項目，fixed、running、stored 版本群組分別保留。回報的執行中 `fw` 用作元件版本。驅動程式特有的其他版本鍵保留在屬性中。缺少 `fw` 會產生版本未知問題。序號會被排除。
