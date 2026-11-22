<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.pt.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Colete dados de software, hardware e operação de um host Linux com um único executável offline. O KODA BOM Kit gera sete listas de materiais CycloneDX, uma lista consolidada e um inventário de software em SPDX.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>Baixar v0.1.8</b></a> ·
  Autor original <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Repositório oficial</a>
</p>

## Início rápido

Baixe o pacote para Linux amd64 e o arquivo SHA-256 correspondente. Transfira ambos para um diretório vazio do servidor de destino e execute os comandos abaixo. O servidor não precisa de Go, de baixar pacotes nem de uma base de dados de vulnerabilidades.

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## Arquivos gerados

A última linha mostra o diretório criado em `bom-output/`. Abra `bom.cdx.json` para consultar o inventário consolidado. As sete listas individuais ficam em `boms/`.

| Arquivo | Conteúdo |
|---|---|
| `boms/sbom.cdx.json` | Pacotes, bibliotecas e aplicações instalados |
| `boms/hbom.cdx.json` | Dispositivos, firmware e drivers |
| `boms/cbom.cdx.json` | Ativos criptográficos, como certificados e algoritmos |
| `boms/obom.cdx.json` | Relações observadas entre serviços, processos, sockets e pacotes |
| `boms/aibom.cdx.json` | Arquivos locais de modelos, pesos e metadados fornecidos |
| `boms/saasbom.cdx.json` | Serviços descritos por um documento OpenAPI ou manifesto de serviço, e backends declarados na configuração de proxies |
| `boms/mbom.cdx.json` | Processos de fabricação e compilação descritos pelas evidências fornecidas |

Uma lista pode ficar vazia quando o host não tem evidências correspondentes. Consulte o estado das evidências e `collection.json` para entender o motivo. O Tracker aceita `sbom.cdx.json` ou `sbom.spdx.json` no diretório principal. Os formatos padrão são CycloneDX 1.6 e SPDX 2.3. Acrescente `--cyclonedx-17` para gerar também o CycloneDX 1.7.

Para consolidar as listas novamente, copie todo o diretório `boms/`, incluindo o manifesto, as relações e as somas de verificação. Defina `run_dir` como o caminho exibido pelo coletor.

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Documentação

- [Instalação offline e verificação de resultados](air-gapped.pt.md)
- [Comandos do coletor e arquivos de saída](collector-guide.pt.md)
- [Evidências de hardware, criptografia e operação](asset-inventory.pt.md)
- [Manifestos de serviços, modelos de IA e fabricação](additional-bom.pt.md)
- [Plataformas compatíveis e limites de coleta](support-matrix.pt.md)
- [Procedimentos de compilação e verificação](verification.pt.md)
- [Resultados e escopo dos testes](verification-results.pt.md)

### Guias de código e testes

- [Importação de ativos externos](internal/assetimport/README.pt.md)
- [Inventário de plataformas](internal/platforminventory/README.pt.md)
- [Identificação de produtos](internal/products/README.pt.md)
- [Oracle Linux VM](tests/oracle-vm/README.pt.md)
- [Ubuntu VM](tests/ubuntu-vm/README.pt.md)

## Licença e atribuição

O KODA BOM Kit é distribuído sob a licença Apache-2.0. Os avisos abaixo identificam o autor original e as licenças das dependências incluídas. [Apache-2.0](../LICENSE) · [Aviso de autoria](../NOTICE) · [Avisos de terceiros](THIRD_PARTY_NOTICES.pt.md)
