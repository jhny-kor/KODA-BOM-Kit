# Preuves de périphériques hors ligne

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
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

`Load` de KODA BOM Kit lit un fichier JSON ordinaire de 8 MiB et 4096 enregistrements au maximum. Il accepte les exports fwupd `get-devices --json` (`Devices`), les objets Redfish développés `SoftwareInventory`, `Manager` et `ComputerSystem`, ainsi que leurs collections. Les membres Redfish contenant seulement une URI produisent un signalement de collecte incomplète. Les valeurs importées sont des observations exportées par un administrateur. Le champ `ImageState` du micrologiciel est conservé lorsqu’il est disponible, sinon il reste inconnu. Les empreintes identifient les octets de preuve sans authentifier leur provenance.

Les fournisseurs d’inventaire Windows, macOS, OT et autres peuvent exporter le format explicite suivant.

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

Les types acceptés sont `device`, `firmware` et `device-driver`. Les propriétés autorisées sont `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` et `updateState`. Les identifiants sont limités à l’empreinte de la preuve pour éviter la fusion accidentelle d’imports distincts. Une version de micrologiciel absente produit un signalement de collecte incomplète. Aucune valeur CPE n’est déduite. Les horodatages décrivent l’export source. Un horodatage omis reste inconnu.

Le format générique accepte aussi `library`, `application`, `operating-system` et `container`. Le champ facultatif `purl` est analysé et sa version, s’il en contient une, doit correspondre à la version explicite. Les qualifiers sont limités à `arch`, `distro`, `epoch`, `type` et `classifier`. Le champ facultatif `sha256` doit contenir 64 caractères hexadécimaux et identifie le composant importé. L’importateur calcule séparément l’empreinte du fichier de preuve. Windows et macOS peuvent utiliser la commande d’inventaire native. Ce format permet d’ajouter des preuves d’autres fournisseurs.

Les exports `devlink -j dev info` sont acceptés via leur objet `info`. Les références de bus identifient les entrées. Les groupes de versions fixed, running et stored restent séparés. Le `fw` en cours d’exécution, s’il est signalé, devient la version du composant. Les autres clés de version propres au pilote restent dans les propriétés. Un `fw` absent produit un signalement de version inconnue. Les numéros de série sont omis.
