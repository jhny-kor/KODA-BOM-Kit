# Ejecución sin conexión e inspección

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 ofrece un archivo para Linux x86_64 (amd64), núcleo 3.2 o posterior. Transfiera el archivo y su `.tar.gz.sha256` desde la publicación oficial. El servidor no necesita instalar Go, Python, Docker ni jq. NOTICE identifica a jhny-kor y el repositorio oficial.

[Publicación 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Verificar y extraer

Coloque un único archivo coincidente y su checksum en un directorio local ejecutable. Verifique el archivo antes de extraer y los ficheros internos después. La suma verifica los bytes transferidos. Obtenga el paquete de la publicación oficial de confianza. Copie desde USB noexec a un sistema de archivos ejecutable.

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## Inspeccionar el servidor

Compruebe arquitectura, núcleo y `doctor`. `supported=true` indica requisitos de ejecución cumplidos. `doctor.kernel` y `context.json.runningKernel` identifican el núcleo. `kernelFlavor=unknown/unconfirmed` puede acompañar una versión registrada. root mejora la visibilidad de DMI, BMC, procesos y contenedores.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Elegir el alcance

Sin argumentos, `koda-bom` crea un directorio en `bom-output/` con `bom.cdx.json` combinado y siete documentos en `boms/`. AI-BOM se llama `aibom.cdx.json`. El contenido depende de la evidencia local. Para Qwen indique la ruta real del modelo. H100 aparece en HBOM. Configuración, cabeceras y paquetes no determinan la asignación GPU actual ni la configuración efectiva del servicio.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

La recopilación de directorios aplica `--no-context`. Guarde resultados fuera de la entrada. El auxiliar rechaza `/` y permite exclusiones relativas para un único directorio. Varios objetivos deben ser disjuntos y sus exclusiones absolutas. Comparten límites de tiempo/archivos. Las dependencias externas pueden quedar sin observar.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Recopilar livepatch

El auxiliar opcional consulta clientes Ksplice, Uptrack o Canonical existentes, depura evidencia y ejecuta scan. Conserva la evidencia junto al resultado. Capture `$?` inmediatamente. Mantiene 30 s por consulta y 10 s para el núcleo efectivo aunque se quite el límite de scan. Los clientes/demonios del proveedor tienen comportamiento de red propio.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Límites y códigos de salida

Valores predeterminados de 1,000,000 archivos regulares y 30 minutos. `--max-files 0 --timeout 0` los elimina y Ctrl+C cancela. Siguen aplicándose permisos, exclusiones, enlaces, 2 GiB por archivo y límites de extracción. `--no-containers` omite contenedores e imágenes sin usar. `--no-images` omite contenedores detenidos e imágenes sin usar. 0 significa completo, 3 parcial con resultados y 2 fallo. Investigue otras salidas anormales.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Localizar y validar resultados

Use el directorio exacto impreso. El auxiliar muestra doctor y evidencia antes de la última línea con la ruta. Asigne esa ruta a `result`. Puede necesitar sudo para archivos de root. Verifique el manifiesto principal y cada contenedor/imagen. Conserve las causas de recopilación parcial.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## Interpretar recopilación y parches

`collection.json` contiene `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, identidad, procedencia, integridad y contenedores. El contador de archivos corresponde a la selección del recorrido. `file_limit_exceeded` incluye `limit` y `observed`. `context.json` contiene núcleo, procesos, sockets, servicios, configuración y parches. `assets.json` conserva hardware, firmware y certificados.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` procede del núcleo y `reported-applied` del cliente. `disabled` y `transitioning` conservan su significado. `stale`, `identity_mismatch` y `unknown` requieren evidencia adicional. Lea estado actual y `patches[].state`, porque `reportedState` puede ser antiguo. Capturas de más de 24 horas, otro arranque/núcleo o demasiado futuras no prueban el estado actual. También se comprueban Last-Check/CheckState de Canonical. Interprete ausencia y `not-reported-patched` con evidencia del núcleo/proveedor.

`integrity.findings[].state=modified` o `missing` indica diferencia o ausencia. `bindScope=all-interfaces` describe direcciones enlazadas. La exposición a través del cortafuegos requiere otra evidencia. `unidentifiedExecutables` indica falta de asociación a paquete. `reboot.recommended=not_observed` indica ausencia de señales. Revise contexto y límites conjuntamente.

## Comparar con el proveedor y conservar

El SBOM del proveedor WAR/EAR debe incluir el SHA-256 real del artefacto. Un hash ausente o distinto produce salida 2. Revise `reconcile.json` y causas parciales. Archive todo el directorio padre con la evidencia depurada de livepatch y calcule su suma.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Subir y analizar

Envíe `sbom.cdx.json` o `sbom.spdx.json` a Tracker compatible. Cada contenedor/imagen tiene su propio SBOM. Guarde collection, context y Syft como evidencia adicional. El timeout de carga es independiente. La recopilación alimenta análisis posteriores. La eficacia de parches y corrección de CVE requiere evidencia propia. Consulte el historial para el alcance exacto de cada versión y VM.

## Documentación

[Ejecución sin conexión e inspección](air-gapped.es.md) · [Guía de compilación y verificación](verification.es.md) · [Resultados de verificación](verification-results.es.md)
