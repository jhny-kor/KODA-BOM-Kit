# Herramienta de validación de arranque directo del kernel Oracle Linux 8.2

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` es el **PID 1 de la VM de validación** de KODA BOM Kit. La restricción `//go:build ignore` lo excluye de las pruebas normales de paquetes Go. Compílelo explícitamente con el siguiente comando.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker y QEMU son herramientas de validación del PC de compilación. Entregue el ejecutable `koda-bom` al servidor aislado. Esta herramienta y el intérprete Python no son dependencias del ejecutable desplegado.

## Reproducción

El runner emula x86_64 mediante TCG en un contenedor QEMU sobre un host de compilación ARM64. La VM tiene 4 GiB de RAM y 2 vCPU, con límite de memoria del contenedor de 6 GiB. Ejecute desde la raíz del proyecto en el PC externo. Sustituya `<ID>` por el ID real de `run.py` y conserve informes anteriores.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

El host de validación requiere `jsonschema` y comprueba sin conexión los esquemas oficiales fijados en `tests/schemas`. Las descargas de preparación necesitan red. La VM del kernel funciona sin conectividad externa. Conserve el ID de imagen usado porque una etiqueta puede cambiar.

`prepare.py` verifica SHA-256 y tamaño de los cuatro RPM fijados en [kernels.json](kernels.json), un total de 120,245,036 bytes, y la huella de la clave de firma Oracle Linux 8. Importa la clave pública en la base RPM de un contenedor Oracle nuevo, verifica firmas con `rpm -Kv` e instala kernels con `--nodeps --noscripts --notriggers`. Se crea un sistema de archivos para validar imágenes de kernel, módulos y metadatos RPM. Los scripts normales de instalación, dracut y configuración GRUB quedan fuera del procedimiento.

Vuelva a ejecutar `prepare.py` con el binario final en el directorio de trabajo existente para reconstruir recopilador, PID 1 e initramfs desde el sistema de archivos de kernels/RPM en caché. Arranque ambas VM de nuevo y compare el **SHA-256 del binario final** con el baseline. Los resultados de una compilación anterior no validan una publicación nueva.

Conserve `input-provenance.json`, `rpm-signature-install.log` y, para cada ejecución, `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, ambos SBOM y sus checksums. La procedencia registra hashes de RPM, kernel, initramfs, PID 1 y recopilador, más ID de imágenes Oracle/QEMU. Un informe de validación de publicación separado vincula estas evidencias al SHA-256 del archivo distribuido.

## Preparación del invitado

El initramfs contiene el sistema de archivos Oracle Linux 8.2, la base RPM de ambos kernels instalados, imágenes en `/boot`, ambos árboles `/lib/modules`, `/koda-bom` bajo prueba y la herramienta como `/init`. RHCK y UEK deben arrancar directamente cada uno con su propia imagen. Ejecutar solo un contenedor o QEMU user-mode no aporta esta evidencia de arranque. Puede colocar un módulo de versión coincidente extraído del RPM oficial en la siguiente ruta.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

La herramienta registra SHA-256 del módulo e intenta cargarlo con `init_module`. Registra por separado estado y errores si falta, ya está cargado o falla por firma o dependencias. Compare `loadedModulesAfter` con `loadedModules` del recopilador para confirmar la carga real. No observar un módulo no demuestra que falte la función.

QEMU no recibe interfaz de red externa ni disco virtual. El runner usa `-accel tcg,thread=single -cpu max -smp 2 -m 4096`. El invitado de prueba usa `random.trust_cpu=on` para evitar esperas tempranas de `getrandom`. Este argumento de prueba no es una recomendación de producción. Conserve configuración real de CPU/aceleración y checksums de kernel, RPM, initramfs y recopilador en los registros del host.

## Ejecución y recopilación

La herramienta monta `/proc`, `/sys`, `/dev`, `/tmp`, `/results` y fija un hostname sintético. El baseline independiente registra uname, `/proc/sys/kernel/osrelease`, OS release, módulos antes/después, línea de comandos del kernel y checksum del recopilador. Hostname y línea de comandos pertenecen solo a esta evidencia sintética de VM. Se mantiene la política normal del producto. El recopilador se ejecuta una vez con el siguiente comando.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

Use live-host predeterminado sin `--target /payload`. La validación 0.1.3 desactiva los límites de archivos y tiempo del recopilador fijándolos en 0. Se mantienen el watchdog independiente de 11 minutos del PID 1 y el timeout QEMU del host para liberar recursos. stdout y stderr se limitan cada uno a 1 MiB y se guardan por separado. Código de salida, tiempos y errores se guardan en `/results/baseline.json`. La salida 3 significa recopilación parcial y debe conservarse.

Los resultados viajan por la salida serie como **base64(gzip(tar))** entre estos marcadores.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

Si el total descomprimido supera 256 MiB o 10,000 archivos, se exporta únicamente un baseline con el motivo del fallo. Tras exportar se intentan sync y poweroff. Si fallan, PID 1 permanece vivo para evitar un kernel panic. El runner del host debe terminar QEMU si la ejecución del invitado supera el plazo.

## Comprobaciones obligatorias

- El uname del baseline coincide con proc release y RHCK/UEK arrancan cada uno la versión prevista.
- `context.json.mode=live-host` y `runningKernel` coinciden exactamente con el baseline independiente.
- UEK informa `kernelFlavor=UEK` y RHCK cumple el contrato actual `RHCK-compatible`.
- El inventario nativo conserva ambos kernels instalados y epoch/version/release/arch/source package de cada RPM.
- Se distinguen los kernels instalados del kernel en ejecución que identifica context.
- `metadata.kernelVersion` y `versionMagic` coinciden con cada árbol instalado. Los módulos cargados coinciden con el baseline del kernel activo.
- Ambos esquemas SBOM y checksums pasan. Se informan fielmente fallos y estados parciales.

## Límites de validación

- Se arrancan kernels invitados Oracle RHCK/UEK reales. La validación en servidores físicos x86_64 se realiza por separado.
- Se usan espacio de usuario Oracle Linux 8.2 y kernels oficiales en un initramfs personalizado. Quedan fuera el arranque completo systemd, instalación GRUB, UEFI/Secure Boot, SELinux enforcing e integración de servicios de producción.
- La prueba `loop` comprueba carga y observación de un módulo real. No cubre todos los controladores o configuraciones de hardware. Los módulos instalados de kernels inactivos no deben considerarse cargados.
- Se aceptan salida `3` y `collection.status=partial`, conservando sus motivos. Superar identificación del kernel, salida estándar e integridad no demuestra la recopilación completa de todos los archivos.
