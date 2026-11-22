# オフラインのデバイス証拠

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
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

KODA BOM Kit の `Load` は、最大 8 MiB、4096 レコードの通常の JSON ファイルを 1 個読み込みます。fwupd の `get-devices --json` 出力（`Devices`）、展開済み Redfish `SoftwareInventory`、`Manager`、`ComputerSystem` オブジェクトとそのコレクションに対応します。URI だけの Redfish メンバーは収集不完全の問題として記録します。取り込む値は管理者がエクスポートした観測値です。ファームウェアの `ImageState` は取得できれば保持し、なければ不明とします。エクスポートのハッシュは証拠のバイト列を識別するもので、出所の認証にはなりません。

Windows、macOS、OT などのインベントリ提供元は、次の明示的な形式でエクスポートできます。

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

対応する種類は `device`、`firmware`、`device-driver` です。許可されるプロパティは `runningVersion`、`storedVersion`、`versionFormat`、`rawVersion`、`applicationState`、`platform`、`productCode`、`pciVendor`、`pciDevice`、`pciSubsystem`、`updateState` です。ID の範囲は証拠のダイジェストに限定し、別の取り込み結果の誤結合を防ぎます。ファームウェアのバージョン欠落は収集不完全として記録します。CPE は推測しません。観測時刻は元のエクスポートの時刻を表し、省略時は不明です。

汎用形式は `library`、`application`、`operating-system`、`container` も受け付けます。任意の `purl` を解析し、バージョンを含む場合は明示したバージョンとの一致を要求します。qualifier は `arch`、`distro`、`epoch`、`type`、`classifier` に制限されます。任意の `sha256` は 64 桁の 16 進数で、取り込むコンポーネントを識別します。取り込み処理は証拠ファイルのハッシュを別に計算します。Windows と macOS ではネイティブなプラットフォームインベントリコマンドも利用できます。他の提供元の追加証拠にはこの形式を使用します。

`devlink -j dev info` の出力は `info` オブジェクトから取り込みます。バス参照で項目を識別し、fixed、running、stored のバージョングループを個別に保持します。実行中の `fw` が報告されればコンポーネントのバージョンに使用します。ドライバー固有の代替バージョンキーはプロパティに残します。`fw` がなければバージョン不明として記録し、シリアル番号は除外します。
