# Guía de compilación y verificación

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 distribuye un archivo sin conexión para Linux amd64 y su SHA-256. Identifique el ejecutable probado mediante su hash exacto y el entorno. La recopilación Linux admite x86_64 y ARM64. Los archivos Docker/OCI se examinan como linux/amd64. El inventario básico de macOS y Windows usa comandos fijos de solo lectura. La ejecución en Windows sigue sin verificar. Los resultados históricos corresponden a sus compilaciones.

[Publicación 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Formatos e integridad

Los formatos predeterminados son CycloneDX 1.6 y SPDX 2.3. `--cyclonedx-17` añade 1.7 desde el mismo inventario. Con `--format cyclonedx` genera dos documentos y con `--format spdx` se rechaza antes de escribirlos. Lo admiten `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` y los dos scripts auxiliares. Compruebe los archivos esperados según las opciones.

| Salida | Formato |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` valida esquemas locales, identidades, evidencias, propiedades, semántica de licencias, relaciones, alcance y entradas ausentes o duplicadas del manifiesto. Los esquemas 1.7 proceden de 1.7.1, commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`, con procedencia en `tests/schemas/provenance.json`. Hay 704 identificadores de licencia en 1.6 y 811 en 1.7. Los 107 adicionales usan `license.name` en 1.6 y `license.id` en 1.7. Revise también el estado parcial de `collection.json`.

## Comprobaciones en el equipo de compilación

Prepare Go, Python, Docker, módulos en caché y dependencias de los esquemas. `trusted_go_sha256` debe contener el hash verificado de Go. `GOPROXY=off` utiliza la caché. El control de publicación rechaza `python3 -O` y `PYTHONOPTIMIZE`. El servidor ejecuta el binario empaquetado. En macOS compruebe las sumas con `shasum -a 256 -c SHA256SUMS`.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Pruebas de integración

Ejecute los comandos sobre la distribución final extraída. Prepare las cachés antes de desconectar la red. .NET/Ruby necesita el SDK .NET 10. Go/Rust requiere módulos en caché y el ELF fijado de ripgrep, o `--rust-binary`. Fancytree compara npm SHA-512 o GitHub SHA-256. Las pruebas compatibles aceptan `--tracker-root /path/to/tracker` para comprobar el analizador real de Tracker.

`domain_bom_integration.py` ejecuta el binario directamente. Ejecute esa prueba en Linux amd64.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

Las pruebas cubren Java anidado, pyz/pex, Go/Rust, procedencia, límites de directorios, hashes del proveedor, PURL y dependencias. Los casos Linux cubren sockets, contenedores, firmware, servicios, configuración, integridad y certificados. Los casos AIX verifican Oracle Home, Listener y OPatch. BMC/NIC/OT físicos, almacenamiento Kubernetes real y clientes de parches con suscripción necesitan evidencia de su entorno.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## Núcleos Linux y reproducción de VM

Ejecute las pruebas exclusivas de Linux en Linux. Desde macOS puede compilarlas para la arquitectura del contenedor. Use el ejecutable final en las VM. RHCK `4.18.0-193.el8.x86_64` y UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` arrancan por separado desde RPM firmados fijados en `tests/oracle-vm/kernels.json`. Conserve procedencia, firmas, ID de imágenes, registros serie, referencia y validaciones.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

El ejecutor Oracle usa QEMU system TCG, 4 GiB, dos CPU y un PID 1 estático propio, sin red ni disco del invitado. Comprueba uname, proc, carga real de loop y núcleos instalados y activos. Ubuntu arranca `6.8.0-47-generic` desde paquetes autenticados. GRUB, UEFI/Secure Boot, systemd completo, SELinux enforcing, controladores físicos y servicios requieren pruebas adicionales. Un contenedor Oracle comparte el núcleo del anfitrión.

[Oracle VM](tests/oracle-vm/README.es.md) · [Ubuntu VM](tests/ubuntu-vm/README.es.md)

## Llamadas al sistema, recursos y análisis posterior

Trace el binario final en un contenedor aislado. Si la emulación ARM64 no interpreta ptrace, `trace-network.sh` devuelve 77. Puede usar trazas de QEMU guest syscall indicando el entorno. Afirmar cero intentos requiere una traza válida. Los clientes y demonios invocados por el auxiliar livepatch tienen comportamiento de red propio.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

Los límites predeterminados son 1,000,000 archivos regulares seleccionados y 30 minutos. Pruebe límites, opciones inválidas, cancelación, permisos, corrupción y exclusiones. `--max-files 0 --timeout 0` elimina esos límites. Registre tiempo y RSS máximo del caso real. Dos tareas paralelas no fijan un límite de memoria. Tracker se verifica con una base temporal aislada y ambos formatos. Los avisos locales dependen de reglas y observaciones. El despliegue y la corrección de CVE necesitan evidencia propia.

## Documentación

[Ejecución sin conexión e inspección](air-gapped.es.md) · [Guía de compilación y verificación](verification.es.md) · [Resultados de verificación](verification-results.es.md)
