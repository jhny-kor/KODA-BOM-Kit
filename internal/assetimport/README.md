# Offline device evidence

`Load` reads one regular JSON file, up to 8 MiB and 4096 records. It supports fwupd `get-devices --json` exports (`Devices`), expanded Redfish `SoftwareInventory`, `Manager`, and `ComputerSystem` objects, and collections containing those expanded objects. URI-only Redfish members produce incomplete issues. Imported values remain administrator-exported observations. Firmware `ImageState` is retained when available and otherwise stays unknown. Export hashes identify evidence bytes and do not authenticate their source.

Windows, macOS, OT and other inventory providers may export this explicit format.

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

Supported kinds are `device`, `firmware`, and `device-driver`. Properties are allowlisted to runningVersion, storedVersion, versionFormat, rawVersion, applicationState, platform, productCode, pciVendor, pciDevice, pciSubsystem and updateState. IDs are scoped to the evidence digest, preventing accidental merging of distinct imports. Missing firmware versions produce incomplete issues. No CPE is inferred. Observed timestamps describe the source export and an omitted timestamp remains unknown.

The generic format also accepts `library`, `application`, `operating-system`, and `container`. Optional `purl` is parsed and must agree with the explicit version when it contains one. Qualifiers are restricted to arch, distro, epoch, type and classifier. Optional `sha256` must be 64 hexadecimal characters and describes the imported component. It is distinct from the importer-generated evidence file hash. Windows and macOS can use the native platform inventory command. Use this format for additional evidence exported by other providers.

`devlink -j dev info` exports are accepted through their `info` object. Bus references identify entries; fixed, running, and stored version groups are preserved separately. A reported running `fw` is the component version. Driver-specific alternate version keys remain in properties, and missing `fw` yields an unknown-version issue. Serial numbers are omitted.
