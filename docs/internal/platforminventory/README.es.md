# Observaciones nativas de la plataforma

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`Collect(ctx)` de KODA BOM Kit recopila observaciones acotadas mediante herramientas ya instaladas en el destino. Usa argumentos fijos, un plazo de 60 segundos por comando y un límite de salida de 32 MiB. Selecciona los campos antes de escribirlos en el SBOM. Omite números de serie, UUID, nombres de usuario y rutas completas de aplicaciones. Las rutas locales solo intervienen en el hash de identidad del componente.

En macOS, `/usr/sbin/system_profiler` proporciona metadatos de hardware, software y aplicaciones. El recopilador emite firmware del sistema, cargador del SO, CPU y aplicaciones, conservando la compilación del SO en su cadena de versión. Algunas aplicaciones pueden carecer de versión o metadatos.

En Windows, PowerShell del sistema se ejecuta sin perfiles y lee registros CIM de computer, BIOS, OS y QuickFixEngineering, además de las entradas de desinstalación del equipo y del usuario actual. Conserva compilación y arquitectura del SO. QuickFixEngineering solo cubre las actualizaciones que reporta. El inventario del registro no enumera todos los perfiles de usuario, aplicaciones Store o dependencias integradas. El recopilador registra una incidencia de cobertura por estas limitaciones.

Ejecute la verificación nativa de macOS con `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Los fixtures de análisis de Windows y la compilación cruzada verifican la estructura del código. La ejecución real requiere un destino Windows.
