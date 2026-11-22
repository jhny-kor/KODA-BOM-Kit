# 서드파티 고지

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
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

KODA BOM Kit 소스 코드는 Apache-2.0으로 제공됩니다. [LICENSE](../LICENSE)를 참조하세요. [영문 고지](THIRD_PARTY_NOTICES.md)도 제공됩니다.

이 실행 파일에는 Anchore Syft v1.57.1 및 전이 Go 의존성이 포함됩니다. 각 구성 요소의 라이선스가 유지됩니다. 배포본의 `licenses/inventory.json`에는 Linux amd64에 실제 링크된 모듈 목록이 들어 있으며 해당 라이선스·고지 원문 사본도 포함됩니다. 라이선스 누락은 보고되며 엄격 배포 패키징 단계를 중단합니다. Go 표준 라이브러리 라이선스는 `licenses/GO-LICENSE`에 포함됩니다. 이 문서는 해당 구성 요소의 라이선스를 변경하거나 모든 의존성이 Apache-2.0이라고 주장하지 않습니다.

빌드 호스트 테스트에서만 쓰는 스키마 fixture는 CycloneDX 사양 1.6·1.7과 SPDX 사양 2.3에서 복사했습니다. 상위 프로젝트 라이선스 원문, 원본 URL, SHA-256은 `tests/schemas/`에 보존합니다. 대상 서버에는 이 fixture가 필요하지 않습니다.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
