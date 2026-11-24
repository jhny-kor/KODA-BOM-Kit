# Mentions relatives aux tiers

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="THIRD_PARTY_NOTICES.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="THIRD_PARTY_NOTICES.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="THIRD_PARTY_NOTICES.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="THIRD_PARTY_NOTICES.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="THIRD_PARTY_NOTICES.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Le code source de KODA BOM Kit est fourni sous Apache-2.0. Consultez [LICENSE](../LICENSE) et les [mentions en anglais](THIRD_PARTY_NOTICES.md).

Cet exécutable intègre Anchore Syft v1.57.1 et ses dépendances Go transitives. Ces composants conservent leurs licences respectives. Une publication contient `licenses/inventory.json`, qui répertorie les modules effectivement liés pour Linux amd64, ainsi que des copies de leurs textes de licence et de leurs mentions. Une licence manquante est signalée et interrompt l’étape stricte de création du paquet. La licence de la bibliothèque standard Go figure dans `licenses/GO-LICENSE`. Ce fichier ne modifie pas les licences de ces composants et n’affirme pas que toutes les dépendances sont sous Apache-2.0.

Les fixtures de schéma réservées aux tests de l’hôte de compilation proviennent des spécifications CycloneDX 1.6 et 1.7 et SPDX 2.3. Leurs textes de licence amont, URL sources et valeurs SHA-256 sont conservés dans `tests/schemas/`. Elles ne sont pas requises sur le serveur cible.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
