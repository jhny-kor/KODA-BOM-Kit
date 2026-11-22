# Validación de VM con kernel real Ubuntu 24.04.1

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Esta es una herramienta de prueba de KODA BOM Kit. No es una dependencia del ejecutable desplegado en el servidor aislado. Arranca directamente Ubuntu Base **24.04.1 amd64** y el kernel oficial Ubuntu **6.8.0-47-generic / paquete 6.8.0-47.47** mediante un initramfs personalizado. QEMU user-mode y fixtures de directorio no demuestran el arranque de un kernel real.

Ubuntu Base se obtiene de un espejo archivado de la distribución. SHA256SUMS.gpg se verifica con Ubuntu CD Image Automatic Signing Key (2012), `843938DF228D22F7B3742BC0D94AA3F0EFE21092`. El keyring del archivo Ubuntu contenido en ese rootfs autenticado verifica noble-updates InRelease del 2024-10-18 del servicio Snapshot oficial. La cadena conecta Release firmado → Packages.xz → SHA-256 y tamaño de ambos DEB. Conserve todas las URL de entrada, checksums, registros de firmas e ID de imágenes Docker.

El host requiere Go, Python 3 con `jsonschema`, Docker y GnuPG (`gpg`/`gpgv`). Reutiliza la imagen de herramientas Oracle VM. Estas herramientas no se instalan en el servidor de destino. Ejecute desde la raíz del proyecto, sustituyendo `<ID>` por el ID real.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` reutiliza la exportación acotada y el baseline independiente de Oracle. Ubuntu integra el controlador loop, así que la prueba carga un `dummy.ko` real para comprobar la observación de módulos. Registra de forma independiente uname y proc release en ejecución, SO, SHA del recopilador y módulos cargados. Compara ambos SBOM con esquemas oficiales fijados, checksums, versiones/source/PURL originales DEB y kernels/módulos instalados. Repita prepare, run y validate cada vez que proporcione un binario final nuevo.

El rootfs usa `dpkg --unpack` para extraer DEB originales y crear una base dpkg real. Se permiten excepciones de dependencias y los paquetes quedan desempaquetados. Esto no demuestra una instalación apt normal ni configuración completada. Arranque completo systemd, GRUB, UEFI/Secure Boot, servicios de producción y hardware físico requieren pruebas separadas. QEMU no tiene NIC ni disco. Docker usa `--network none`, rootfs de solo lectura y capabilities eliminadas. La instalación de live patches comerciales o por suscripción queda fuera de la prueba.

La validación 0.1.3 usa `--max-files 0 --timeout 0` para desactivar los dos límites del recopilador. Se mantienen el watchdog de 11 minutos del PID 1 y el timeout QEMU del host.

Conserve juntos procedencia, registros de firmas y dpkg, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, ambos SBOM y `validation.json`. Mantenga la salida parcial 3. No la convierta en salida 0 de recopilación completa.
