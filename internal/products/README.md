# Product evidence collector

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
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

KODA BOM Kit’s `Collect(context.Context, root string, paths []string)` accepts a preflighted list of relative regular files. It does not discover files, run installed programs, extract archives, contact servers or read environment/configuration secrets. `os.OpenRoot` confines path resolution, and absolute paths or parent traversal components are rejected. File-content and archive-metadata reads are bounded. An empty path list performs no file discovery.

## Qualified static evidence

- JDK/JRE `release` files provide approved version, runtime, build, vendor and architecture fields.
- Tomcat `catalina.jar` provides a version cross-check between `ServerInfo.properties` and `MANIFEST`.
- WebLogic `weblogic.jar` provides product manifest data and component identity from `inventory/ContentsXML/comps.xml` in the current installation home. Patch IDs remain observations. Generic XML or `.patch_storage` entries cannot prove that a CPU/PSU patch is applied. `patchState` remains `unknown`.
- JBoss EAP/WildFly provides product release manifests under the installed product module.
- OpenSSH, OpenSSL, PHP and Node.js ELF files qualify only when product-specific embedded version signatures exist. This classification supplements Syft. Coverage of all stripped or custom binaries is not established. Native scan input is capped at 32 MiB, and oversized candidates are explicitly incomplete.

Conflicting Tomcat, JDK or same-home WebLogic metadata is marked conflicting and carries no asserted version. Different installation homes are never merged. Native library, client and server artifacts retain separate IDs, including equal-version artifacts in the same directory. No CPE inference or CVE judgment is generated.

JEUS product and patch metadata is **unsupported**. The separate generic Java cataloger may collect JAR libraries, which do not prove JEUS product identity or applied patch level.

Tests build representative metadata structures rather than licensed product images. Validation of commercial installations requires target vendor fixtures.
