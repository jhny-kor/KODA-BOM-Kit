# Collecteur de preuves de produits

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
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

`Collect(context.Context, root string, paths []string)` de KODA BOM Kit reçoit une liste préalablement contrôlée de fichiers ordinaires à chemins relatifs. Il ne recherche pas de fichiers, n’exécute pas de programmes installés, n’extrait pas d’archives, ne contacte pas de serveurs et ne lit pas de secrets d’environnement ou de configuration. `os.OpenRoot` borne la résolution des chemins. Les chemins absolus ou remontant vers un parent sont rejetés. Les lectures de contenu et de métadonnées d’archives sont limitées. Une liste vide ne déclenche aucune recherche.

## Preuves statiques acceptées

- Champs autorisés de version, runtime, build, fournisseur et architecture des fichiers `release` JDK/JRE.
- Contrôle croisé des versions de `ServerInfo.properties` et `MANIFEST` dans `catalina.jar` de Tomcat.
- Manifeste de produit WebLogic `weblogic.jar` et identité des composants dans `inventory/ContentsXML/comps.xml` de l’installation courante. Les identifiants de correctifs restent des observations. Un XML générique ou une entrée `.patch_storage` ne prouve pas l’application d’un correctif CPU/PSU. `patchState` reste `unknown`.
- Manifestes de version JBoss EAP/WildFly sous le module du produit installé.
- Fichiers ELF OpenSSH, OpenSSL, PHP et Node.js contenant des signatures de version intégrées propres au produit. Cette classification complète Syft. La couverture de tous les binaires stripped ou personnalisés n’est pas établie. L’entrée native est limitée à 32 MiB et les candidats plus volumineux sont explicitement incomplets.

Les métadonnées contradictoires de Tomcat, JDK ou WebLogic dans une même installation sont marquées en conflit et aucune version n’est affirmée. Des installations distinctes ne sont jamais fusionnées. Bibliothèques, clients et serveurs natifs conservent des identifiants séparés, même à version et répertoire identiques. Aucune déduction CPE ou décision CVE n’est générée.

Les métadonnées de produit et de correctif JEUS sont **non prises en charge**. Le catalogueur Java générique peut collecter des bibliothèques JAR, qui ne prouvent ni l’identité du produit JEUS ni son niveau de correctif appliqué.

Les tests construisent des structures de métadonnées représentatives sans images de produits sous licence. La validation d’installations commerciales exige des fixtures du fournisseur cible.
