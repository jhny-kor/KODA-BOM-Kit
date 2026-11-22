# KODA BOM Kit — Comandos de recopilación y archivos de salida

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Elegir el alcance

En un equipo en ejecución, el recopilador registra el sistema operativo, los paquetes, los contenedores y el hardware accesible. El análisis de un directorio se limita a su árbol. El de una imagen lee un archivo Docker u OCI exportado. Elige un tipo de entrada por ejecución. Los límites iniciales son un millón de archivos regulares y 30 minutos. Con `--max-files 0 --timeout 0` se eliminan esos dos límites. Siguen vigentes los permisos y los límites del sistema de archivos y del análisis de archivos comprimidos.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Analizar uno o varios directorios

El script recibe el directorio de destino y, opcionalmente, el directorio padre de los resultados. Ejecuta `--no-context` y rechaza `/`. Pon entre comillas las rutas con espacios. Usa `--exclude-dir` para excluir un directorio y `--exclude` para un patrón. Con varios destinos, elige árboles disjuntos y usa rutas absolutas para los directorios excluidos. Las ubicaciones conservan `target-1`, `target-2` tras la fusión.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Leer el estado de los parches en caliente

El análisis del equipo lee el estado del núcleo desde sysfs. El script opcional consulta los clientes instalados de Canonical Livepatch, Ksplice o Uptrack y depura su salida. Para considerarse actual, un informe importado debe corresponder al mismo arranque y núcleo y tener como máximo 24 horas. La ausencia de una entrada no demuestra que se haya corregido un CVE.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Reconstruir el grafo operativo o fusionar un conjunto

El OBOM relaciona sockets en escucha, procesos y paquetes instalados. La dirección local de escucha por sí sola no demuestra que el puerto sea accesible desde el exterior. Añade observaciones exportadas con `--kubernetes-evidence` o `--network-evidence`. Asigna a `set_dir` el directorio con `bom-set.json` generado al separar el conjunto. Conserva los archivos de relaciones y las sumas de verificación. Los conjuntos anteriores con `mlbom.cdx.json` también se pueden fusionar.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Aportar evidencias para otras listas

Indica al recopilador de IA el directorio del modelo instalado. Para SaaS o fabricación, facilita un manifiesto de servicios o procesos. Usa `--asset-evidence` para importar dispositivos Redfish, firmware u observaciones criptográficas. La lista de compilación se vincula al artefacto analizado si coincide su SHA-256. Las guías al final del documento detallan los formatos.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## Importar registros de IBM AIX y Oracle

Ejecuta el script en AIX y después el importador en el equipo Linux de análisis. Facilita la salida de OPatch guardada por el propietario del Oracle Home y, si procede, el historial SQL exportado por el DBA. Se admiten hasta ocho Homes distintos. La versión de Listener requiere evidencias del mismo Home. Contrasta los identificadores de parches con el boletín del proveedor.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Identificar dependencias desplegadas

Para npm y pnpm se comprueban las ubicaciones instaladas, la resolución de dependencias pares y las versiones. La identificación de JavaScript estático cubre jQuery, jQuery UI y Fancytree. Go necesita información de compilación integrada y Rust ELF necesita datos cargo-auditable. Para .NET se contrasta .deps.json con DLL administradas desplegadas y para Ruby se leen gemspecs instalados. Java conserva las rutas dentro de WAR, EAR y Spring Boot. Las coordenadas desconocidas quedan sin resolver.

## Comparar un despliegue con la lista del proveedor

Proporciona un WAR o EAR y un documento CycloneDX 1.4–1.7 o SPDX 2.3 con el SHA-256 de ese mismo archivo. Consulta `common`, `observedOnly`, `supplierOnly` y `unresolved` en `reconcile.json`. Envía a Tracker la lista observada. El límite es de 512 MiB para el despliegue y de 32 MiB para el documento del proveedor.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Comprobar la cobertura

En un equipo de compilación o pruebas, compara la misma copia inmutable del despliegue con KODA, Syft y Trivy. El script requiere Python 3.11 o posterior. Usa `--expected` para componentes y relaciones confirmados o `--baseline` para detectar regresiones. Las pruebas opcionales con Tracker cargan los datos en el servicio de pruebas indicado. Para comprobar el grafo almacenado, proporciona `--normalized-bom-command`.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Interpretar la recopilación

Asigna a `run_dir` la ruta que imprimió el recopilador. Los códigos de salida son 0 para una recopilación completa, 3 para resultados parciales y 2 para un fallo. Consulta límites, omisiones y errores en `collection.json`, relaciones en ejecución en `context.json` y evidencias de dispositivos o certificados en `assets.json`. Cada directorio de contenedor o imagen tiene sumas propias. La versión y la fecha no bastan para determinar si existe una vulnerabilidad.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Compilar en otro equipo

La compilación de la distribución usa Go y Python 3. Esta versión se compiló con Go 1.26.11. Si usas otro ejecutable de Go, facilita su ruta y el SHA-256 verificado. Una compilación sin conexión necesita una caché de módulos completa. El archivo distribuido es para Linux amd64 y el código también se compila para Linux ARM64. La procedencia de la compilación se guarda en `release.json`.

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Documentación

- [Instalación sin conexión y comprobación de resultados](air-gapped.es.md)
- [Evidencias de hardware, criptografía y funcionamiento](asset-inventory.es.md)
- [Manifiestos de servicios, modelos de IA y fabricación](additional-bom.es.md)
- [Plataformas compatibles y límites de recopilación](support-matrix.es.md)
- [Procedimientos de compilación y verificación](verification.es.md)
- [Resultados y alcance de las pruebas](verification-results.es.md)
