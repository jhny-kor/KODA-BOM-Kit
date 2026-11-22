# 第三方声明

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
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

KODA BOM Kit 源代码采用 Apache-2.0。请参阅 [LICENSE](../LICENSE) 和[英文声明](THIRD_PARTY_NOTICES.md)。

此可执行文件嵌入 Anchore Syft v1.57.1 及其传递性 Go 依赖。各组件保留各自的许可证。发布包包含 `licenses/inventory.json`，列出 Linux amd64 实际链接的模块，并附有许可证及声明原文副本。缺少许可证时会报告并停止严格发布打包步骤。Go 标准库许可证包含于 `licenses/GO-LICENSE`。本文不会重新许可这些组件，也不声称所有依赖均为 Apache-2.0。

仅供构建主机测试的 schema fixture 复制自 CycloneDX 1.6、1.7 和 SPDX 2.3 规范。上游许可证原文、来源 URL 和 SHA-256 保存在 `tests/schemas/`。目标服务器无需这些 fixture。

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
