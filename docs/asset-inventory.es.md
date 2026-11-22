# Inventario de hardware y software

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Use `koda-bom` compilado para el sistema y CPU de destino. En Linux, `scan` recopila paquetes y hardware. `platform-inventory` en Windows/macOS invoca herramientas locales del sistema.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

En PowerShell, use `.\koda-bom.exe platform-inventory --output-dir .\reports`. Los análisis de directorios/imágenes usan el sistema de archivos seleccionado. El hardware activo se observa en el host `/` con contexto habilitado. Los archivos Docker/OCI admiten Linux amd64. Importe un CycloneDX verificado en Tracker y conserve versiones y sumas juntas.

## Evidencias recopiladas

| Área | Contenido e interpretación |
|---|---|
| Hardware | CPU/microcódigo, mitigaciones, placa, BIOS/UEFI, ESRT, PCI/controladores, NVMe/SCSI, USB, TPM. RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS y amdgpu `vbios_version`. NIC mediante ioctl de lectura equivalente a `ethtool -i`. megaraid_sas requiere exportaciones |
| BMC | IPMI `Get Device ID` de lectura en `/dev/ipmi0`, con root y `ipmi_si`/`ipmi_devintf`. Revisión, fabricante IANA, producto y revisión auxiliar. Se explica la ausencia. Use Redfish para comparar etiquetas de compilación del fabricante |
| CPU | x86 `cpuidSignature`/`familyModelStepping`, topología, proveedor/núcleo ARM y revisión como `r3p1`. Los núcleos desconocidos conservan códigos originales. USB `bcdDevice` identifica la revisión del dispositivo |
| Activos externos | Objetos Redfish expandidos, fwupd/devlink JSON y esquema común. Firmware activo y almacenado por separado. Campos dependientes del modelo |
| Ejecución | Sustituciones de ejecutables/bibliotecas, identidad de archivo y paquete propietario único. `restart_review` indica sustitución. La versión instalada necesita evidencia adicional para confirmar la que está en memoria |
| Identidad | SHA-256 de machine-id y UUID/series DMI normalizados en host `/`, incluso con `--no-context`. machine-id/UUID en minúsculas, series sin espacios extremos. Se omiten valores genéricos/UUID cero. Los hashes son seudónimos potencialmente deducibles. `--asset-tag` admite una línea de 128 caracteres. Alcance de contenedor `container-visible` |
| Sockets | TCP LISTEN/UDP sin conexión en el espacio de red del recopilador, atribuidos por descriptores. `bindScope` es `all-interfaces`, `loopback`, `address`. Alcance de cortafuegos/rutas requiere evidencia. Sin propietario pasan a `context.json.unattributedSockets` |
| Seguridad/reinicio | SELinux actual/configurado, AppArmor/perfiles, lockdown, FIPS y opciones de arranque permitidas. Se excluyen credenciales. `kernelConfig` lee `y`/`m` en `/proc/config.gz` o `/boot/config-<running-kernel>`. Reboot-required, módulos actuales ausentes y kernel más nuevo de la misma familia dan señales. Con señales, `reboot.recommended=true`, si no `not_observed`. La familia se infiere de la cadena de versión |
| SSH | Declaraciones globales de `sshd_config`/`sshd_config.d/*.conf`, incluidas `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. Excluye `Match`. Los valores efectivos dependen de `Include` |
| Módulos/programas | `kernel.tainted`, `taintedModules`, nombres, `O`/`E`/`P`, version/srcversion. Ejecutables del mismo root sin paquete/componente/producto se registran con ruta/PID en `unidentifiedExecutables`. Se contempla usr-merge |
| Integridad | Hashes RPM/dpkg/apk frente a ejecutables/`.so`. Excluye configuración/ghost. `modified`/`missing` en `collection.json.integrity.findings` y propiedades. Presupuesto 8 GiB/host y 1 GiB/contenedor, luego `partial`. prelink puede provocar diferencias |
| Origen | apt Packages plano/gz/lz4 por nombre, historial dnf y yum `from_repo`. Estados `repository`, `local-file`, `not-recorded`. Sin historial, dnf5 y apk no se clasifican. Se omiten URL/rutas. DB dnf copiada temporalmente y abierta en lectura |
| Arranque | systemd wants/requires, unidades/drop-ins, primer `ExecStart`, activación por socket y PURL. Excluye unidades enmascaradas. Procesos de `system.slice` determinan el estado. Slices propios pueden aparecer detenidos |
| CPE | Patrones Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge dispositivo/BIOS y Lenovo ThinkSystem dispositivo. Modelos desconocidos, HPE y BMC quedan sin CPE inferido |
| Certificados | Huella X.509, validez, algoritmos, tamaño y estado. Señales SHA-1/MD5, RSA menor de 2048, DSA. Criptografía clásica `nistQuantumSecurityLevel=0`. Excluye nombres de sujeto/emisor y claves privadas, almacenes de confianza y paquetes de más de 20 certificados |
| Aplicaciones | snap activo/DEB incluido, flatpak activo/AppStream, conda con nombre de canal, `.pyz`/`.pex`, JAR, JS estático, Go/Rust. Hashes Docker/OCI y digests verificados |

## Contenedores y resultados

Cada contenedor activo tiene `containers/<name>/`. Kubernetes usa namespace/pod/contenedor y añade 12 caracteres de ID si hay colisión. Lee metadatos en disco de Docker/containerd/Podman/CRI-O. No conecta con APIs. Localiza el root por dispositivos de mountinfo, incluye capas de imagen/escritura y excluye volúmenes/bind mounts. Atribuye sockets al proceso del contenedor, prioriza paquetes y usa main module para Go. Root invisible/tiempo agotado genera `not_collected` con motivo. `--no-containers` deshabilita esta recopilación.

Contenedores detenidos e imágenes sin uso admiten Docker overlay2, containerd overlayfs con k3s/RKE2 y Podman/CRI-O rootful. Reconstruye capas temporalmente aplicando whiteout/opaque y elimina la copia después. Omite dispositivos y bits set-ID. Se salta un root mayor de 16 GiB o si falta espacio para tamaño + 1 GiB. Usa `state: stopped` o `state: image`, sin sockets. Cambios concurrentes pueden impedir la lectura. Otros drivers y Podman rootless no están admitidos. `--no-images` deshabilita esta vía.

Genera siete perfiles en `boms/` y los combina en `bom.cdx.json`. AI-BOM usa `aibom.cdx.json`. Conserva CycloneDX 1.6 `sbom.cdx.json` y SPDX 2.3 `sbom.spdx.json`, con 1.7 opcional mediante `--cyclonedx-17`. SPDX usa `OTHER` y anotaciones para tipos sin equivalente. Identidad de host `koda:host:*`, contenedor `koda:container:*`, sockets `koda:runtime:listening`/`koda:runtime:bind-scope`. Revise `assets.json`, `context.json`, `collection.json`, `inventory.syft.json` y verifique `SHA256SUMS`.

## Evidencia común de activos

Hasta ocho archivos de 8 MiB. `parentId` referencia `id` del mismo archivo. Omita versiones desconocidas. Redfish necesita objetos expandidos más allá de listas URI. SHA-256 identifica el archivo importado.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

## Activos criptográficos y TLS

Certificados, claves públicas y algoritmos se emiten como `cryptographic-asset`. Los emisores candidatos se comprueban por firma. Directivas permitidas Nginx/Apache/sshd aportan configuración. JKS v1/v2 conserva cadenas públicas y SHA-256 de alias, omite claves cifradas y marca integridad `not-verified` sin contraseña.

Importe metadatos públicos PKCS#12/HSM/KMS con `--asset-evidence`. `related-crypto-material` admite tipo/tamaño/estado de clave, `algorithmRef`, `properties.storageType` y `keyAlias`. El `dependsOn` del consumidor referencia la clave en el mismo archivo.

Ejemplo de negociación TLS medida externamente. Sustituya huellas, destino y hora. Un hash coincidente enlaza servicio → protocolo → certificado.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## Evaluación sin conexión

Reevalúe resultados guardados al recibir nuevos avisos.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--context`/`--kev` son opcionales. Contexto verifica ambos documentos mediante `SHA256SUMS`. KEV añade prioridad. Se admiten reglas explícitas, OSV con versiones/PURL exactos y CSAF 2.0 con IDs exactos/estado incondicional. Rangos o combinaciones/condiciones no admitidos detienen la evaluación con explicación.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "Verify firmware activation according to the vendor advisory"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Use distro con release y versiones exactas. Contradicciones SBOM/PURL dan `review_required`. Se considera epoch RPM. Máximo 1.000.000 entradas exactas por ejecución. Reglas admiten `supportEndsAt` y `affectedSemver` en ecosistemas compatibles. Archivos sustituidos/firmware almacenado requieren revisión de activación, versiones/activos desconocidos requieren revisión. Compare equipos Linux físicos y Windows con inventarios del fabricante. La recopilación nativa Windows/macOS se centra en OS, hardware y aplicaciones instaladas.

## Observaciones TCP

`--network-evidence` compara mediciones previas con sockets del host/OBOM guardado. `hostField` admite `machineIdSha256`, `productUuidSha256`, `assetTag` explícito. `scope` es `host` o ID de contenedor de 64 caracteres.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

Resultados `connected`, `refused`, `timed-out`. Propietarios ambiguos o sockets ausentes quedan sin asociar. Cada ubicación/hora requiere su observación. El recopilador no realiza sondeos. [Matriz de soporte](support-matrix.es.md) · [Evidencia adicional](additional-bom.es.md)
