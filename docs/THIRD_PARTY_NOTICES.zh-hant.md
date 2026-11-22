# 第三方聲明

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="THIRD_PARTY_NOTICES.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="THIRD_PARTY_NOTICES.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="THIRD_PARTY_NOTICES.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="THIRD_PARTY_NOTICES.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="THIRD_PARTY_NOTICES.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="THIRD_PARTY_NOTICES.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 原始碼採用 Apache-2.0。請參閱 [LICENSE](../LICENSE) 和[英文聲明](THIRD_PARTY_NOTICES.md)。

此執行檔嵌入 Anchore Syft v1.57.1 及其遞移 Go 相依項目。各元件保留各自的授權條款。發行套件包含 `licenses/inventory.json`，列出 Linux amd64 實際連結的模組，並附有授權與聲明原文副本。缺少授權時會回報並停止嚴格發行封裝步驟。Go 標準程式庫授權包含於 `licenses/GO-LICENSE`。本文不會重新授權這些元件，也不宣稱所有相依項目皆為 Apache-2.0。

僅供建置主機測試的 schema fixture 複製自 CycloneDX 1.6、1.7 和 SPDX 2.3 規範。上游授權原文、來源 URL 和 SHA-256 保存在 `tests/schemas/`。目標伺服器無需這些 fixture。

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
