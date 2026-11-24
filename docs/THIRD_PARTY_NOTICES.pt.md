# Avisos de terceiros

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="THIRD_PARTY_NOTICES.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="THIRD_PARTY_NOTICES.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="THIRD_PARTY_NOTICES.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="THIRD_PARTY_NOTICES.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="THIRD_PARTY_NOTICES.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

O código-fonte do KODA BOM Kit é fornecido sob Apache-2.0. Consulte [LICENSE](../LICENSE) e os [avisos em inglês](THIRD_PARTY_NOTICES.md).

Este executável incorpora Anchore Syft v1.57.1 e suas dependências transitivas de Go. Esses componentes mantêm suas respectivas licenças. Uma versão inclui `licenses/inventory.json`, que lista os módulos realmente vinculados para Linux amd64, e cópias dos textos de licença e avisos. Uma licença ausente é informada e interrompe a etapa estrita de empacotamento. A licença da biblioteca padrão Go está em `licenses/GO-LICENSE`. Este arquivo não altera a licença desses componentes nem afirma que todas as dependências usam Apache-2.0.

Os fixtures de esquema usados apenas nos testes do host de compilação foram copiados das especificações CycloneDX 1.6 e 1.7 e SPDX 2.3. Seus textos de licença originais, URLs de origem e valores SHA-256 são preservados em `tests/schemas/`. Eles não são necessários no servidor de destino.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
