<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="docs/badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="README.fr.md"><img src="docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="LICENSE"><img src="docs/badges/license.svg" alt="Apache-2.0"></a>
  <a href="docs/support-matrix.es.md"><img src="docs/badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Recopila datos de software, hardware y actividad de un equipo Linux con un solo ejecutable sin conexión. KODA BOM Kit genera siete listas de materiales CycloneDX, una lista consolidada y un inventario de software en SPDX.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>Descargar v0.1.8</b></a> ·
  Autor original <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Repositorio oficial</a>
</p>

## Primeros pasos

Descarga el archivo para Linux amd64 y su fichero SHA-256. Copia ambos a un directorio vacío del servidor de destino y ejecuta allí los siguientes comandos. El servidor no necesita Go, descargas de paquetes ni una base de datos de vulnerabilidades.

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

## Archivos de salida

La última línea muestra el directorio creado dentro de `bom-output/`. Abre `bom.cdx.json` para consultar el inventario consolidado. Las siete listas individuales están en `boms/`.

| Archivo | Contenido |
|---|---|
| `boms/sbom.cdx.json` | Paquetes, bibliotecas y aplicaciones instalados |
| `boms/hbom.cdx.json` | Dispositivos, firmware y controladores |
| `boms/cbom.cdx.json` | Activos criptográficos, como certificados y algoritmos |
| `boms/obom.cdx.json` | Relaciones observadas entre servicios, procesos, sockets y paquetes |
| `boms/aibom.cdx.json` | Archivos locales de modelos, pesos y metadatos aportados |
| `boms/saasbom.cdx.json` | Servicios descritos en un documento OpenAPI o un manifiesto de servicio |
| `boms/mbom.cdx.json` | Procesos de fabricación y compilación descritos por las evidencias aportadas |

Una lista puede quedar vacía si no se encuentran evidencias. Consulta su estado y `collection.json` para conocer la causa. Tracker admite los archivos `sbom.cdx.json` y `sbom.spdx.json` del directorio principal. Los formatos predeterminados son CycloneDX 1.6 y SPDX 2.3. Añade `--cyclonedx-17` para generar también CycloneDX 1.7.

Para volver a combinar las listas, copia el directorio `boms/` completo, con su manifiesto, relaciones y sumas de verificación. Asigna a `run_dir` la ruta que mostró el recopilador.

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Documentación

- [Instalación sin conexión y comprobación de resultados](docs/air-gapped.es.md)
- [Comandos del recopilador y archivos de salida](docs/collector-guide.es.md)
- [Evidencias de hardware, criptografía y funcionamiento](docs/asset-inventory.es.md)
- [Manifiestos de servicios, modelos de IA y fabricación](docs/additional-bom.es.md)
- [Plataformas compatibles y límites de recopilación](docs/support-matrix.es.md)
- [Procedimientos de compilación y verificación](docs/verification.es.md)
- [Resultados y alcance de las pruebas](docs/verification-results.es.md)

### Guías de código y pruebas

- [Importación de activos externos](internal/assetimport/README.es.md)
- [Inventario de plataformas](internal/platforminventory/README.es.md)
- [Identificación de productos](internal/products/README.es.md)
- [Oracle Linux VM](tests/oracle-vm/README.es.md)
- [Ubuntu VM](tests/ubuntu-vm/README.es.md)

## Licencia y atribución

KODA BOM Kit se distribuye bajo Apache-2.0. Los siguientes avisos identifican al autor original y las licencias de las dependencias incluidas. [Apache-2.0](LICENSE) · [Aviso de autoría](NOTICE) · [Avisos de terceros](THIRD_PARTY_NOTICES.es.md)
