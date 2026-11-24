# Alcance y límites de las evidencias

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


La matriz describe evidencias identificables. Consulte estados y motivos en `collection.json`. La exhaustividad depende de metadatos legibles, formato y permisos. La evaluación de vulnerabilidades necesita avisos coincidentes.

## Siete BOM CycloneDX

El host `/` genera documentos individuales en `boms/` y uno combinado `bom.cdx.json`. `--cyclonedx-17` añade 1.7. Se explicitan dominios sin evidencia mediante `no-evidence` y cobertura desconocida. [Categorías CycloneDX](https://github.com/CycloneDX/specification#readme)

| BOM | Evidencias disponibles | Aportaciones necesarias |
|---|---|---|
| SBOM | Paquetes OS/lenguaje, versiones/PURL, licencias/dependencias, JAR, módulos y contenedores | CycloneDX/SPDX del proveedor/CI ligado a SHA-256 para dependencias estáticas/de compilación, en `build-sbom.cdx.json` |
| HBOM | CPU/placa/dispositivos/drivers/firmware, DIMM EDAC y sensores, módulos de memoria SMBIOS (fabricante, número de pieza, velocidad), fuentes de alimentación y ranuras | Redfish/registros para piezas invisibles, números, proveedores y ciclo de vida |
| CBOM | Certificados/claves/algoritmos públicos, emisores comprobados, TLS/SSH, JKS, claves públicas de host SSH, política criptográfica del sistema y declaraciones de protocolo/cifrado/grupo de OpenSSL | TLS medido y metadatos públicos exportados de HSM/KMS/almacenes protegidos |
| OBOM | Host/contenedor/proceso/archivo/paquete/socket y systemd, destinos TCP salientes por proceso, temporizadores systemd, tareas cron y reglas de cortafuegos declaradas | Kubernetes del mismo clúster, Pod/workload/Service/Ingress, etiquetas y `--network-evidence` del host |
| SaaSBOM | Especificaciones/OpenAPI a `saasbom.cdx.json`. También OpenAPI YAML y backends declarados en nginx, Apache y HAProxy | Proveedor/catálogo/API, dependencias externas, autenticación, confianza y flujos clasificados |
| AI-BOM | Configuración, cuantización/contexto, índices, encabezados/tamaños GGUF/safetensors, Ollama. SHA-256 completo de artefactos explícitos. `aibom.cdx.json`. También encabezados ONNX, seguridad de importaciones pickle de PyTorch, tarjetas de modelo y refs de caché de Hugging Face, y el modelo indicado al iniciar un servidor de modelos | Identidad/revisión/pesos, linaje, tarjetas/licencias y fuentes de entrenamiento/evaluación |
| MBOM | SLSA coincidente o montaje/pruebas declarados, en `mbom.cdx.json` `formulation` | Pasos/herramientas/entradas/salidas/registros CI o historia de fabricación/inspección |

## Capas

| Capa | Evidencias y límites |
|---|---|
| OS | os-release/vendor release, DB RPM/DEB/APK. Permisos, corrupción y falta de source package/module stream pueden limitar |
| Hardware/firmware | CPU/microcódigo/CPUID/topología/ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM. RAID/HBA, RDMA, GPU VBIOS y NIC dependen del driver. megaraid_sas requiere exportación, BMC root/IPMI y cotejo de revisión. VM/contenedor puede mostrar el host físico |
| Externos | Redfish expandido, fwupd/devlink/JSON común. Conserva estado/versión comunicados, revise activos no asociados |
| Windows/macOS | Sistema/OS/firmware/aplicaciones. Windows incluye comprobaciones de compilación cruzada. Dependencias internas/actualizaciones requieren más datos |
| Software activo | Ejecutables/bibliotecas y propiedad dentro del mismo alcance. Sustituciones justifican revisión de reinicio |
| Identidad | SHA-256 machine-id/UUID/series y etiqueta explícita del host `/`. Depende de permisos/valores genéricos. Es seudonimización |
| Sockets | TCP LISTEN/UDP del mismo espacio y FD. Bind no determina cortafuegos. Sin dueño, `unattributedSockets` |
| Conexiones salientes | TCP establecido cuyo puerto local no escucha, por proceso y destino remoto, hasta 16.384 sockets. Un puerto local fijo hacia un puerto efímero del par cuenta como conexión aceptada. Solo se ven las conexiones abiertas al recopilar. Solo procesos del host. Una conexión a un puerto en el que escucha este host vincula el proceso cliente con ese socket y su proceso propietario |
| Tareas programadas | `/etc/crontab`, `/etc/cron.d`, crontabs de usuario y scripts de `cron.{hourly,daily,weekly,monthly}`, más temporizadores systemd habilitados con su calendario `On*`. Solo se guarda la ruta absoluta del programa; los argumentos se descartan |
| Cortafuegos | Archivos iptables-save (RHEL/Debian/ufw), la zona predeterminada de firewalld con sus servicios y cadenas nftables con hook input e includes literales. Son declaraciones de archivo; no se lee el conjunto de reglas cargado en el kernel. Una cadena base sin política acepta; ufw con `ENABLED=no` se registra como `disabled`, y un framework cuya unidad systemd está instalada pero no habilitada ni en ejecución, o enmascarada, como `not-enabled`; ninguno cuenta como activo. Las reglas solo de loopback, de estado establecido y negadas no cuentan como puertos abiertos; una aceptación TCP/UDP de todo el protocolo abre todos sus puertos. Los sockets que escuchan fuera de loopback en el espacio de nombres de red del host reciben `firewall-declared`: `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined` o `none-observed` cuando no se leyó ninguna declaración activa. Los sockets de contenedores tienen su propio espacio de nombres de red y no reciben valor. Los puertos que los contenedores publican mediante NAT pasan por reglas FORWARD, que no se evalúan |
| Ajustes/reinicio | SELinux, AppArmor, lockdown, FIPS, arranque permitido, kernel `y`/`m`, reboot-required, módulos/kernel más nuevo de familia. Ausencia de señales no demuestra que no haga falta reiniciar |
| SSH | Declaraciones globales, excluye `Match`, no calcula precedencia efectiva de `Include` |
| Taint/módulos | `kernel.tainted`, `/proc/modules`, sysfs version/srcversion cuando existen |
| Ejecutables desconocidos | Mismo root sin paquete/componente/producto. Excluye otros espacios de montaje, requiere investigación |
| Origen | apt plano/gz/lz4 por nombre, dnf/yumdb. Listas eliminadas, dnf5/apk sin soporte. Omite URL/rutas |
| Servicios | systemd wants/requires, units/drop-ins, cgroup v1/v2. Primer ExecStart. Ejecutable relativo sin paquete. Slice propio puede parecer detenido. Sin SysV. Los temporizadores habilitados registran su calendario `On*` y el servicio que inician |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge dispositivo/BIOS, Lenovo ThinkSystem. Vacíos de diccionario/modelo impiden coincidencias. Sin HPE/BMC |
| Integridad | Hashes de ejecutables/bibliotecas RPM/dpkg/apk. Excluye config/ghost. 8 GiB host, 1 GiB contenedor. prelink puede dar falsos cambios |
| CBOM | PEM/DER, claves/algoritmos públicos, cadenas JKS v1/v2 y hashes de alias. Omite claves cifradas e integridad JKS sin verificar. Excluye nombres, claves privadas, PKCS#12, almacenes OS y paquetes >20 certificados. Incluye claves públicas de host SSH. `crypto-policies` y MinProtocol/CipherString/Ciphersuites/Groups de `openssl.cnf` son declaraciones; no se resuelven `.include` ni la activación de secciones |
| Kernel | uname, imágenes/módulos instalados, vermagic, RPM. Distingue activo e instalado. Módulo ausente puede ser función integrada |
| Livepatch | sysfs, Oracle raw Ksplice y helper Ksplice/Uptrack/Canonical opcional. Diferencias boot/kernel/hora invalidan evidencia de aplicación. CVE necesita análisis |
| Java | JDK/JRE release, manifiestos JAR/WAR/EAR, Maven. Shaded modificado/eliminado limita identificación |
| PHP | Paquete/intérprete, Composer instalado, PEAR. Excluye paquetes solo en lock. Explotabilidad depende de configuración |
| snap/flatpak/conda | snap current/DEB, flatpak active/AppStream, conda-meta. PURL generic para snap/flatpak, sin versión si falta AppStream, solo nombre de canal conda |
| Python | dist-info/egg-info, venv, metadatos reales `.pyz`/`.pex`. Ausencia/permisos limita |
| Node/JS | node_modules/runtime, jQuery/jQuery UI/Fancytree en archivos y EAR/WAR/ZIP/JAR. Nombre solo es insuficiente. Límites de diseño/inspección |
| Go/Rust | Build info Go y cargo-auditable ELF. Sin datos, dependencias desconocidas. Corrupción/exceso da parcial |
| .NET | `.deps.json`, DLL administradas y recursos de versión. DLL aislada sin NuGet PURL, single-file necesita comprobación |
| Ruby | specifications/gems instalados y default. Solo Gemfile.lock o metadatos eliminados son insuficientes |
| Servidores nativos | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB. Binarios propios/strip/copias estáticas pueden quedar desconocidos |
| Servidores Java | Tomcat ServerInfo/manifest/catalina.jar, WebLogic/JBoss/WildFly instalación/parches. `.patch_storage` solo no demuestra aplicación. JEUS sin fixtures reales queda sin verificar |
| Detenidos/imágenes | Docker overlay2, containerd overlayfs/k3s/RKE2, Podman/CRI-O rootful. Reconstrucción temporal 16 GiB/root y control de espacio. Sin otros drivers/rootless ni sockets |
| Contenedores activos | Roots procfs, metadatos en disco, `containers/<name>/`. Excluye volúmenes/bind mounts y sandbox Kubernetes. Root invisible con motivo. Sin API, sockets solo de procesos del contenedor |
| Archivos imagen | Docker/OCI tar Linux amd64 explícito, hash y digest verificado. Contenido de imagen, kernel/ejecución del host por separado |
| AIX/Oracle | `aix-import` filesets, fixes, OPatch por Home y SQL opcional. Hasta ocho Homes de un servidor. Ejecución requiere evidencia adicional |

Las instalaciones manuales conservan ubicación/instancia. Igual nombre y versión pueden tener parches distintos. CPE desconocido queda vacío. Use identificadores confirmados y evidencia para la revisión posterior.

Formatos predeterminados CycloneDX 1.6/SPDX 2.3, con 1.7 opcional. [Inventario y evaluación](asset-inventory.es.md) explica `assess`, OSV/CSAF exactos y esquemas. [Evidencias adicionales](additional-bom.es.md) cubre servicios, modelos y fabricación.

## Escenarios de regresión

Se prueban PHP/Composer, Node runtime/node_modules, builds JDK completos, instalación/parches WebLogic, Tomcat manual/AJP/HTTP2, releases httpd/mod_http2, origen/alias/rewrite nginx, copias OpenSSL CLI/libssl/libcrypto y kernels UEK/RHCK activos/instalados. Estos escenarios prueban identificación. Una conclusión de vulnerabilidad requiere cotejo con avisos.
