# Evidências de dispositivos offline

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

O `Load` do KODA BOM Kit lê um arquivo JSON comum de até 8 MiB e 4096 registros. Aceita exportações fwupd `get-devices --json` (`Devices`), objetos Redfish expandidos `SoftwareInventory`, `Manager` e `ComputerSystem` e suas coleções. Membros Redfish contendo apenas URI geram ocorrências de coleta incompleta. Os valores importados são observações exportadas pelo administrador. O `ImageState` do firmware é preservado quando disponível e fica desconhecido caso contrário. Os hashes identificam os bytes da evidência e não autenticam sua origem.

Provedores de inventário Windows, macOS, OT e de outras plataformas podem exportar o formato explícito abaixo.

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

Os tipos aceitos são `device`, `firmware` e `device-driver`. As propriedades permitidas são `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` e `updateState`. Os IDs ficam restritos ao resumo da evidência para evitar a mesclagem acidental de importações distintas. Versões de firmware ausentes geram ocorrências de coleta incompleta. Valores CPE nunca são inferidos. Os horários de observação descrevem a exportação original. Um horário omitido permanece desconhecido.

O formato genérico também aceita `library`, `application`, `operating-system` e `container`. O `purl` opcional é analisado e sua versão, quando presente, deve corresponder à versão explícita. Os qualificadores se limitam a `arch`, `distro`, `epoch`, `type` e `classifier`. O `sha256` opcional deve conter 64 caracteres hexadecimais e identifica o componente importado. O importador calcula separadamente o hash do arquivo de evidência. Windows e macOS podem usar o comando de inventário nativo. Este formato permite acrescentar evidências de outros provedores.

Exportações `devlink -j dev info` são aceitas pelo objeto `info`. Referências de barramento identificam as entradas. Os grupos de versões fixed, running e stored são preservados separadamente. O `fw` em execução informado passa a ser a versão do componente. Chaves alternativas de versão específicas do driver permanecem nas propriedades. A ausência de `fw` gera uma ocorrência de versão desconhecida. Números de série são omitidos.
