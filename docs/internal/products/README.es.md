# Recopilador de evidencias de productos

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

`Collect(context.Context, root string, paths []string)` de KODA BOM Kit recibe una lista previamente comprobada de archivos normales con rutas relativas. No descubre archivos, ejecuta programas instalados, extrae archivos comprimidos, contacta servidores ni lee secretos de entorno o configuración. `os.OpenRoot` limita la resolución de rutas y se rechazan rutas absolutas o con recorrido al directorio padre. Las lecturas de contenido y metadatos de archivos están acotadas. Una lista vacía no inicia descubrimiento de archivos.

## Evidencias estáticas aceptadas

- Campos autorizados de versión, runtime, compilación, proveedor y arquitectura en `release` de JDK/JRE.
- Comprobación cruzada de versiones entre `ServerInfo.properties` y `MANIFEST` en `catalina.jar` de Tomcat.
- Manifiesto de producto de WebLogic `weblogic.jar` e identidad del componente en `inventory/ContentsXML/comps.xml` de la instalación actual. Los ID de parches se conservan como observaciones. XML genérico o entradas de `.patch_storage` no prueban la aplicación de un parche CPU/PSU. `patchState` permanece `unknown`.
- Manifiestos de versión de JBoss EAP/WildFly en el módulo del producto instalado.
- Archivos ELF de OpenSSH, OpenSSL, PHP y Node.js con firmas de versión incrustadas específicas del producto. Esta clasificación complementa Syft. No se ha demostrado cobertura de todos los binarios stripped o personalizados. La entrada nativa se limita a 32 MiB y los candidatos mayores se marcan explícitamente como incompletos.

Metadatos contradictorios de Tomcat, JDK o WebLogic en la misma instalación se marcan en conflicto y no afirman una versión. Instalaciones distintas nunca se fusionan. Bibliotecas, clientes y servidores nativos conservan ID separados, incluso con igual versión y directorio. No se generan inferencias CPE ni juicios CVE.

Los metadatos de producto y parches de JEUS **no están soportados**. El catalogador Java genérico puede recoger bibliotecas JAR, que no prueban la identidad de JEUS ni su nivel de parche aplicado.

Las pruebas construyen estructuras representativas de metadatos sin imágenes de productos licenciados. Validar instalaciones comerciales requiere fixtures del proveedor de destino.
