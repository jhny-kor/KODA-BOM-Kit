# Resultados de verificación

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Estos registros de KODA BOM Kit y versiones anteriores incluyen fecha, hash, entorno, resultados parciales y áreas pendientes. La publicación oficial 0.1.8 identifica el archivo, checksum y alcance. Cada nuevo ejecutable requiere sus propias pruebas.

[Publicación 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 2026-11-21 — separación y combinación

`f0610ca-worktree-00ed83f2acd8` probó `scan --separate-boms`, `bom-split`, `bom-merge` y `domain-bom` con dos archivos 0.1.6. Se compararon todos los componentes y relaciones, añadiendo una relación entre raíces por combinación. Diez pares de ID de certificados Ubuntu correspondían a 20 ubicaciones preservadas. El resultado tuvo cero ID duplicados. Linux ARM64 combinó cuatro BOM observados con entradas sintéticas OpenAPI, modelo, SLSA y fabricación. TCP 18443 real se vinculó a Perl y su paquete. Esquemas y hashes pasaron. Autenticidad y evidencia de campo requieren comprobación propia.

| Archivo | Componentes antes / después | Relaciones antes / después |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — relaciones operativas

`f0610ca-worktree-06f22395e26f` regeneró OBOM desde dos recopilaciones parciales. Los sockets se cuentan por espacio de nombres/proceso. Debian ARM64 vinculó `127.0.0.1:18443/tcp` a `/usr/bin/perl` y `perl-base`, comprobó tres referencias Redfish, ejemplos TLS, dos relaciones de compilación y 11 sumas. Los OBOM regenerados eran idénticos. Cinco recursos Kubernetes sintéticos se vincularon a ID completos archivados. Clústeres, inventario físico y sesiones TLS reales quedaron fuera.

| Archivo | Contenedores | Sockets host + contenedores | Paquete host + contenedores | Relaciones comparadas |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — 12 correcciones Daybreak

Se atendieron hallazgos de KODA-SBOM-Maker `cc86c1b`. Incluyen aislamiento de Go, hash del mismo flujo extraído, límite de 256 capas y reutilización de hashes, índices ZIP/ZIP64 limitados, whiteouts validados, directorios exclusivos, comparación de avisos indexada y limitada, rechazo de Python optimizado, lectura dentro de raíces verificadas, ID cortos seguros, conflictos RPM con epoch y recorrido cancelable por bloques de 256 entradas.

Go, vet y controles de publicación pasaron en macOS ARM64. Go 1.26.11 / Syft 1.57.1 generó Linux amd64 estático sin red. Pasaron 306 sumas y las pruebas CLI/directorios en Debian aislado. Antes y después coincidieron 88 paquetes, un SO, 20 dispositivos y 15 controladores. Ambas recopilaciones fueron parciales con motivos. Otras plataformas se compilaron de forma cruzada. Su ejecución y nuevas VM quedaron pendientes.

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Linux, Go y vet pasaron en Docker Desktop `7.0.14-linuxkit`. CPU coincidió con lscpu y se leyeron 1,736 opciones del núcleo. Debian tuvo un paquete local sin registro entre 147. Rocky identificó 167 paquetes de repositorio y las instalaciones locales/sin registro. Nueve contenedores activos, 14 detenidos y 11 imágenes sin usar produjeron 35 SBOM en unos 3 min 30 s. Las cantidades 796, 71 y 51 coincidieron. Overlay2 conservó curl y recogió busybox sin usar. Un contenedor eliminado quedó `not_collected`. x86 real, systemd, Kubernetes/k3s/Podman/CRI-O y nuevas VM no se verificaron.

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` verificó identidad, sockets reales, 16 contenedores y cinco módulos externos. Se examinaron 735 archivos, unos 89 MB, detectando exactamente uno modificado y uno movido/ausente. RSA-1024 y ECDSA P-384 comprobaron caducidad y claves débiles sin exportar claves privadas. Hardware, snap/flatpak/conda y parte de la configuración usaron datos sintéticos. RAID/NIC/BMC físicos, SELinux real, otros motores y nuevas VM quedaron pendientes.

## 2026-11-18 — 0.1.6-dev

Go, vet, auxiliares y shell pasaron. Linux amd64/ARM64 y el inventario básico macOS ARM64 real validaron esquemas y sumas. Windows solo se compiló. Se probaron ejecutables eliminados/reemplazados, hashes y avisos locales. El analizador local de Tracker leyó ambas versiones CycloneDX. Despliegue y navegador no se verificaron. Se preservó la semántica de 704/811 licencias y las 107 adicionales. La cantidad de sumas depende del alcance.

## Historial 0.1.2–0.1.5

0.1.5 añadió relaciones pnpm y Maven POM, 0.1.4 el auxiliar de directorios y 0.1.3 límites de archivos/tiempo. Relacione hashes con `release.json`, `VERIFICATION.json` y `dist/evidence/v0.1.x/final-verification.json` cuando se suministren. 0.1.2 repitió Ubuntu y ambos núcleos Oracle con su binario final. La instalación de clientes suscritos y parches reales quedó fuera de las pruebas sintéticas.

## 2026-10-29 — implementación y VM Oracle

Pasaron 68 comprobaciones Linux y vet. Casos uid 65534 con entradas/rootfs de solo lectura, sin capacidades ni red validaron esquemas, PURL, canarios y errores. El contenedor Oracle tenía RPM 182, Python 5 y binary 2. La traza guest syscall mostró cero intentos de red y execve adicionales. Ambos formatos recibieron HTTP 202 en Tracker SQLite aislado. Un caso pequeño 0.1.0 tardó 0.78 s y alcanzó 219,644 KiB RSS.

Las VM Oracle Linux 8.2 arrancaron RHCK/UEK firmados y coincidieron uname/proc y loop. Cada una produjo 5,516 componentes, con RPM 186, núcleos 2, módulos 5,321, Python 5 y binary 2. Los árboles tenían RHCK 2,478 y UEK 2,843 módulos. Pasaron esquemas y cinco sumas por VM. Salida 3, parcial y contexto completo conservaron archivos protegidos, enlaces fuera del alcance, conflictos OpenSSH y avisos Syft.

| Kernel | Recopilación / total segundos |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## Límites de la evidencia

Las primeras VM usaron el hash 0.1.0 indicado abajo. Las siguientes versiones tienen informes propios. Servidores x86 físicos, arranque completo, servicios y parches del proveedor quedaron fuera. QEMU guest trace y ptrace nativo tienen entornos diferentes. Una recopilación en vivo puede mezclar momentos. Use una ventana estable o instantánea de solo lectura. Versiones y ausencia de observaciones no bastan para determinar aplicabilidad o corrección de CVE.

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## Documentación

[Ejecución sin conexión e inspección](air-gapped.es.md) · [Guía de compilación y verificación](verification.es.md) · [Resultados de verificación](verification-results.es.md)
