# サードパーティーに関する通知

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="docs/badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="docs/badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="docs/badges/ko.svg" alt="한국어"></a>
  <a href="THIRD_PARTY_NOTICES.es.md"><img src="docs/badges/es.svg" alt="Español"></a>
  <a href="THIRD_PARTY_NOTICES.fr.md"><img src="docs/badges/fr.svg" alt="Français"></a>
  <a href="THIRD_PARTY_NOTICES.vi.md"><img src="docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="THIRD_PARTY_NOTICES.pt.md"><img src="docs/badges/pt.svg" alt="Português"></a>
  <a href="THIRD_PARTY_NOTICES.th.md"><img src="docs/badges/th.svg" alt="ไทย"></a>
  <a href="THIRD_PARTY_NOTICES.tr.md"><img src="docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="LICENSE"><img src="docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit のソースコードは Apache-2.0 で提供されます。[LICENSE](LICENSE) を参照してください。[英語版の通知](THIRD_PARTY_NOTICES.md) もあります。

この実行ファイルには Anchore Syft v1.57.1 と、その推移的な Go 依存関係が組み込まれています。各コンポーネントはそれぞれのライセンスを維持します。リリースには Linux amd64 に実際にリンクされたモジュールを記載した `licenses/inventory.json` と、ライセンス・通知の原文の写しが含まれます。ライセンスが欠落すると報告され、厳格なリリースパッケージングが停止します。Go 標準ライブラリのライセンスは `licenses/GO-LICENSE` に含まれます。この文書は各コンポーネントのライセンスを変更せず、すべての依存関係が Apache-2.0 であるとも主張しません。

ビルドホストのテスト専用スキーマ fixture は CycloneDX 仕様 1.6・1.7 と SPDX 仕様 2.3 からコピーされています。上流のライセンス原文、ソース URL、SHA-256 は `tests/schemas/` に保存されています。対象サーバーにこれらの fixture は不要です。

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
