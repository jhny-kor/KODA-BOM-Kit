# Offline device evidence

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
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

KODA BOM Kit’s `Load` reads one regular JSON file, up to 8 MiB and 4096 records. It accepts fwupd `get-devices --json` exports (`Devices`), expanded Redfish `SoftwareInventory`, `Manager` and `ComputerSystem` objects, and collections of those expanded objects. URI-only Redfish members produce incomplete issues. Imported values are administrator-exported observations. Firmware `ImageState` is retained when available and otherwise stays unknown. Export hashes identify evidence bytes and do not authenticate their source.

Windows, macOS, OT and other inventory providers can export the following explicit format.

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

Supported kinds are `device`, `firmware` and `device-driver`. Allowed properties are `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` and `updateState`. IDs are scoped to the evidence digest to prevent accidental merging of distinct imports. Missing firmware versions produce incomplete issues. CPE values are never inferred. Observation timestamps describe the source export. An omitted timestamp stays unknown.

The generic format also accepts `library`, `application`, `operating-system` and `container`. Optional `purl` is parsed and, if it contains a version, must agree with the explicit version. Allowed qualifiers are `arch`, `distro`, `epoch`, `type` and `classifier`. Optional `sha256` must contain 64 hexadecimal characters and identifies the imported component. The importer separately calculates the evidence file hash. Windows and macOS can use the native platform inventory command. This format supports additional evidence from other providers.

`devlink -j dev info` exports are accepted through their `info` object. Bus references identify entries. Fixed, running and stored version groups remain separate. A reported running `fw` becomes the component version. Alternative driver-specific version keys remain in properties. Missing `fw` produces an unknown-version issue. Serial numbers are omitted.
