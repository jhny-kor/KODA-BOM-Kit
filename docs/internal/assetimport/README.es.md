# Evidencias de dispositivos sin conexión

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

`Load` de KODA BOM Kit lee un archivo JSON normal de hasta 8 MiB y 4096 registros. Admite exportaciones de fwupd `get-devices --json` (`Devices`), objetos Redfish `SoftwareInventory`, `Manager` y `ComputerSystem` expandidos, y colecciones de esos objetos. Los miembros Redfish que solo contienen URI generan incidencias de recopilación incompleta. Los valores importados son observaciones exportadas por el administrador. Se conserva el `ImageState` del firmware cuando está disponible y, en caso contrario, queda desconocido. Los hashes identifican los bytes de la evidencia y no autentican su procedencia.

Los proveedores de inventario de Windows, macOS, OT y otras plataformas pueden exportar el siguiente formato explícito.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id":"board", "kind":"device", "name":"Controller", "vendor":"Vendor", "model":"Model", "revision":"A"},
    {"id":"firmware", "parentId":"board", "kind":"firmware", "name":"Controller firmware", "version":"1.2", "properties":{"applicationState":"Active", "storedVersion":"1.3"}}
  ]
}
```

Los tipos admitidos son `device`, `firmware` y `device-driver`. Las propiedades permitidas son `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` y `updateState`. Los identificadores quedan limitados al resumen de la evidencia para evitar fusiones accidentales de importaciones distintas. La ausencia de versión del firmware genera una incidencia de recopilación incompleta. Nunca se infieren valores CPE. Las marcas de tiempo describen la exportación original. Si se omiten, quedan desconocidas.

El formato genérico también admite `library`, `application`, `operating-system` y `container`. El `purl` opcional se analiza y su versión, si la contiene, debe coincidir con la versión explícita. Los calificadores se limitan a `arch`, `distro`, `epoch`, `type` y `classifier`. El `sha256` opcional debe tener 64 caracteres hexadecimales e identifica el componente importado. El importador calcula por separado el hash del archivo de evidencia. Windows y macOS pueden usar el comando de inventario nativo. Este formato permite añadir evidencias de otros proveedores.

Las exportaciones `devlink -j dev info` se aceptan mediante su objeto `info`. Las referencias de bus identifican las entradas. Los grupos de versiones fixed, running y stored se conservan por separado. Un `fw` en ejecución reportado pasa a ser la versión del componente. Las claves alternativas propias del controlador se conservan como propiedades. La ausencia de `fw` genera una incidencia de versión desconocida. Se omiten los números de serie.
