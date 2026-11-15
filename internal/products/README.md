# Product evidence collector

`Collect(context.Context, root string, paths []string)` receives a preflighted
list of relative regular files. It does not walk, execute installed programs,
extract archives, contact servers, or read environment/configuration secrets.
`os.OpenRoot` confines path resolution; every input is also rejected if absolute
or containing a parent traversal component. File content and archive metadata
reads are bounded. Passing no paths performs no file discovery.

Qualified static evidence currently includes:

- JDK/JRE `release`: approved version/runtime/build/vendor/architecture fields.
- Tomcat `catalina.jar`: ServerInfo.properties and MANIFEST version cross-check.
- WebLogic `weblogic.jar`: product manifest and current-home
  `inventory/ContentsXML/comps.xml` component identity. Patch IDs are retained as
  observations only. No generic XML or `.patch_storage` entry proves application
  of a CPU/PSU patch; `patchState` remains `unknown`.
- JBoss EAP/WildFly product release manifests under the installed product module.
- OpenSSH, OpenSSL, PHP and Node.js ELF files only when product-specific embedded
  version signatures are present. The classifier is supplemental to Syft, not
  a promise that stripped/custom binaries are all identified. Native scan input
  is capped at 32 MiB; oversized candidates are explicitly incomplete.

Contradictory Tomcat, JDK, or same-home WebLogic metadata is marked conflicting
and carries no asserted version. Different installation homes are never merged.
Native library/client/server artifacts retain separate IDs, including artifacts
with matching versions in the same directory. No inferred CPE or CVE judgment
is generated.

JEUS product and patch metadata remains **not supported**. JAR libraries may be
collected by the separate generic Java cataloger, but are not proof of an
identified JEUS product or applied patch level.

Tests build representative metadata structures, not licensed product images.
Commercial installation validation still requires target vendor fixtures.
