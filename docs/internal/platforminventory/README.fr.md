# Observations natives de la plateforme

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

`Collect(ctx)` de KODA BOM Kit recueille des observations bornées avec les outils déjà installés sur la cible. Il utilise des arguments fixes, un délai de 60 secondes par commande et une limite de sortie de 32 MiB. Les champs sont sélectionnés avant leur écriture dans le SBOM. Numéros de série, UUID, noms d’utilisateur et chemins complets des applications sont omis. Les chemins locaux servent uniquement à calculer l’identité hachée des composants.

Sous macOS, `/usr/sbin/system_profiler` fournit les métadonnées du matériel, des logiciels et des applications. Le collecteur produit le micrologiciel système, le chargeur du système d’exploitation, le CPU et les applications, en conservant le numéro de build dans la version du système. Certaines applications peuvent manquer de version ou de métadonnées.

Sous Windows, PowerShell système s’exécute sans profils et lit les enregistrements CIM computer, BIOS, OS et QuickFixEngineering, ainsi que les entrées de désinstallation du registre machine et de l’utilisateur courant. Le build et l’architecture du système sont conservés. QuickFixEngineering couvre uniquement les mises à jour qu’il signale. L’inventaire du registre ne recense pas tous les profils utilisateur, applications Store ou dépendances intégrées. Le collecteur signale ces limites de couverture.

Lancez la vérification native macOS avec `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Les fixtures d’analyse Windows et la compilation croisée vérifient la structure du code. Une exécution réelle exige une cible Windows.
