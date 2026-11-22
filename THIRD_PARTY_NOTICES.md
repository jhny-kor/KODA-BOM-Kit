# Third-party notices

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="docs/badges/ja.svg" alt="日本語"></a>
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

KODA BOM Kit source code is provided under Apache-2.0. See [LICENSE](LICENSE).

This executable embeds Anchore Syft v1.57.1 and its transitive Go dependencies. These components retain their respective licenses. A release contains `licenses/inventory.json` listing the modules actually linked for Linux amd64 and copies of their license/notice texts. A missing license is reported and stops the strict release packaging step. Go standard-library licensing is included as `licenses/GO-LICENSE`. This file does not relicense those components or claim that every dependency is Apache-2.0.

Schema fixtures used only by build-host tests are copied from CycloneDX specifications 1.6 and 1.7 and SPDX specification 2.3. Their upstream license texts, source URLs and SHA-256 values are retained in `tests/schemas/`. They are not required on the target server.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
