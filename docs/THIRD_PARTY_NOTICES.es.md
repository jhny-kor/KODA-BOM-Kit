# Avisos de terceros

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
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

El código fuente de KODA BOM Kit se distribuye bajo Apache-2.0. Consulte [LICENSE](../LICENSE) y los [avisos en inglés](THIRD_PARTY_NOTICES.md).

Este ejecutable integra Anchore Syft v1.57.1 y sus dependencias transitivas de Go. Estos componentes conservan sus propias licencias. Cada publicación incluye `licenses/inventory.json` con los módulos realmente enlazados para Linux amd64 y copias de sus textos de licencia y avisos. Una licencia ausente se informa y detiene el empaquetado estricto de la publicación. La licencia de la biblioteca estándar de Go se incluye en `licenses/GO-LICENSE`. Este archivo no cambia las licencias de esos componentes ni afirma que todas las dependencias usen Apache-2.0.

Los fixtures de esquema usados solo en pruebas del equipo de compilación proceden de las especificaciones CycloneDX 1.6 y 1.7 y SPDX 2.3. Sus licencias originales, URL de origen y valores SHA-256 se conservan en `tests/schemas/`. No son necesarios en el servidor de destino.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
