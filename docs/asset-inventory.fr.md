# Inventaire matériel et logiciel

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Utilisez `koda-bom` compilé pour le système et le CPU cibles. Sous Linux, `scan` collecte paquets et matériel. Sous Windows/macOS, `platform-inventory` appelle les outils locaux du système.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

Sous PowerShell, utilisez `.\koda-bom.exe platform-inventory --output-dir .\reports`. Les analyses de répertoires/images couvrent le système de fichiers choisi. Le matériel actif est observé sur l'hôte `/` avec contexte activé. Les archives Docker/OCI prennent en charge Linux amd64. Importez un CycloneDX vérifié dans Tracker et conservez versions et sommes de contrôle ensemble.

## Preuves collectées

| Domaine | Contenu et interprétation |
|---|---|
| Matériel | CPU/microcode, atténuations, carte, BIOS/UEFI, ESRT, PCI/pilotes, NVMe/SCSI, USB, TPM. RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS, amdgpu `vbios_version`. NIC par ioctl en lecture équivalent à `ethtool -i`. megaraid_sas nécessite un export. En root, la table SMBIOS brute fournit fabricant, référence, capacité et vitesse des modules mémoire, modèle et puissance des alimentations, et emplacements avec leur adresse PCI ; les numéros de série sont enregistrés en SHA-256 |
| BMC | IPMI `Get Device ID` en lecture via `/dev/ipmi0`, avec root et `ipmi_si`/`ipmi_devintf`. Révision, fabricant IANA, produit et révision auxiliaire. Absences expliquées. Redfish permet de rapprocher les versions publiques du fabricant |
| CPU | x86 `cpuidSignature`/`familyModelStepping`, topologie, fabricant/cœur ARM, révision telle que `r3p1`. Cœurs inconnus conservés en codes bruts. USB `bcdDevice` reste un identifiant de révision |
| Actifs externes | Redfish développé, fwupd/devlink JSON, schéma commun. Firmwares actif et stocké distincts. Champs propres au modèle |
| Exécution | Remplacements d'exécutables/bibliothèques, identité de fichier et paquet propriétaire unique. `restart_review` signale un remplacement. Une preuve supplémentaire est nécessaire pour connaître la version en mémoire |
| Identité | SHA-256 normalisé de machine-id et UUID/numéros de série DMI sur l'hôte `/`, même avec `--no-context`. machine-id/UUID en minuscules, séries sans espaces périphériques. Valeurs génériques/UUID zéro omis. Hashes pseudonymisés, potentiellement devinables. `--asset-tag` accepte une ligne de 128 caractères. Conteneur `container-visible` |
| Sockets | TCP LISTEN et UDP non connecté dans l'espace réseau du collecteur, attribués via les descripteurs. `bindScope` vaut `all-interfaces`, `loopback`, `address`. Accessibilité réseau à vérifier séparément. Sans propriétaire, `context.json.unattributedSockets`. Les connexions TCP sortantes établies sont enregistrées par processus et destination dans `outboundConnections`, avec `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`) |
| Sécurité/redémarrage | SELinux courant/configuré, AppArmor/profils, lockdown, FIPS, options d'amorçage autorisées. Identifiants exclus. `kernelConfig` lit `y`/`m` depuis `/proc/config.gz` ou `/boot/config-<running-kernel>`. Signaux reboot-required, modules actifs absents, noyau plus récent de même famille. Signal positif `reboot.recommended=true`, sinon `not_observed`. Famille déduite du nom de version |
| SSH | Déclarations globales de `sshd_config`/`sshd_config.d/*.conf`, dont `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. Exclut `Match`. Valeurs effectives dépendantes d'`Include` |
| Modules/programmes | `kernel.tainted`, `taintedModules`, noms, `O`/`E`/`P`, version/srcversion. Exécutables de même root sans attribution paquet/composant/produit dans `unidentifiedExecutables`, chemin/PID. usr-merge pris en compte |
| Intégrité | Hashes RPM/dpkg/apk comparés aux exécutables/`.so`. Configuration/ghost exclus. `modified`/`missing` dans `collection.json.integrity.findings` et propriétés. 8 GiB/hôte, 1 GiB/conteneur, puis `partial`. prelink peut créer des écarts |
| Origine | apt Packages texte/gz/lz4 par nom, historique dnf, yum `from_repo`. `repository`, `local-file`, `not-recorded`. Historique absent, dnf5 et apk non classés. URL/chemins omis. DB dnf copiée temporairement et lue seule |
| Démarrage | systemd wants/requires, unités/drop-ins, premier `ExecStart`, activation socket, PURL. Unités masquées exclues. `system.slice` détermine l'état, un slice spécifique peut sembler arrêté. Les minuteurs activés enregistrent leur calendrier `On*` et le service qu'ils démarrent |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge matériel/BIOS et Lenovo ThinkSystem matériel. Modèles inconnus, HPE, BMC sans CPE déduit |
| Certificats | Empreinte X.509, validité, algorithmes, taille/état de clé. Indicateurs SHA-1/MD5, RSA <2048, DSA. Algorithmes classiques `nistQuantumSecurityLevel=0`. Noms sujet/émetteur et clés privées exclus. Magasins système et ensembles >20 certificats ignorés. Les clés publiques d'hôte SSH (`etc/ssh/ssh_host_*_key.pub`) sont aussi enregistrées avec leur empreinte SHA-256 OpenSSH |
| Applications | snap actif/DEB inclus, flatpak actif/AppStream, conda avec nom du canal, `.pyz`/`.pex`, JAR, JS statique, Go/Rust. Hashes Docker/OCI et digests vérifiés |

## Conteneurs et résultats

Chaque conteneur actif reçoit `containers/<name>/`. Kubernetes utilise namespace/pod/conteneur, avec 12 caractères d'ID en cas de collision. Les métadonnées Docker/containerd/Podman/CRI-O sont lues sur disque sans API. Le root est trouvé via les périphériques mountinfo. Couches image/écriture incluses, volumes/bind mounts exclus. Sockets attribués aux processus du conteneur, priorité au paquet, main module pour Go. Root invisible/délai dépassé donne `not_collected` avec motif. `--no-containers` désactive cette collecte.

Les conteneurs arrêtés et images inutilisées prennent en charge Docker overlay2, containerd overlayfs avec k3s/RKE2 et Podman/CRI-O rootful. Reconstruction temporaire avec whiteout/opaque, puis suppression de la copie. Fichiers périphériques et bits set-ID omis. Root >16 GiB ou espace inférieur à taille +1 GiB ignoré. État `state: stopped` ou `state: image`, sans sockets. Les changements simultanés peuvent empêcher la collecte. Autres pilotes/rootless Podman non pris en charge. `--no-images` désactive ce parcours.

Sept profils sont créés dans `boms/`, puis fusionnés en `bom.cdx.json`. AI-BOM utilise `aibom.cdx.json`. Résultats compatibles CycloneDX 1.6 `sbom.cdx.json`, SPDX 2.3 `sbom.spdx.json`, 1.7 avec `--cyclonedx-17`. SPDX utilise `OTHER` et annotations pour les types sans équivalent. Hôte `koda:host:*`, conteneur `koda:container:*`, sockets `koda:runtime:listening`/`koda:runtime:bind-scope`. Consultez `assets.json`, `context.json`, `collection.json`, `inventory.syft.json`, vérifiez `SHA256SUMS`.

## Format commun d'actifs

Huit fichiers maximum, chacun limité à 8 MiB. `parentId` référence `id` dans le même fichier. Omettez les versions inconnues. Redfish nécessite les objets développés, au-delà des listes URI. SHA-256 identifie l'entrée importée.

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

## Actifs cryptographiques et TLS

Certificats, clés publiques et algorithmes deviennent `cryptographic-asset`. Les signatures vérifient les émetteurs candidats. Les directives autorisées Nginx/Apache/sshd sont des preuves de configuration. JKS v1/v2 conserve chaînes publiques et SHA-256 des alias, ignore les clés chiffrées, indique `not-verified` pour l'intégrité sans mot de passe.

Importez les métadonnées publiques PKCS#12/HSM/KMS via `--asset-evidence`. `related-crypto-material` accepte type/taille/état, `algorithmRef`, `properties.storageType`, `keyAlias`. Le `dependsOn` du consommateur référence la clé du même fichier.

Cet exemple décrit une négociation TLS mesurée séparément. Remplacez empreintes, destination et heure. Un hash concordant relie service → protocole → certificat.

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

## Évaluation hors ligne

Réévaluez les résultats archivés avec de nouveaux avis.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`/`--context`/`--kev` sont facultatifs. Le contexte vérifie SBOM et contexte dans `SHA256SUMS`. KEV ajoute des informations de priorité. Entrées acceptées, règles explicites, OSV à versions/PURL exacts, CSAF 2.0 à IDs exacts et statut inconditionnel. Expressions conditionnelles, combinaisons ou plages non prises en charge arrêtent l'évaluation avec motif.

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

Utilisez distro avec release et versions exactes. Conflit SBOM/PURL donne `review_required`. Epoch RPM pris en compte. Limite de 1 000 000 entrées exactes par exécution. `supportEndsAt` et `affectedSemver` sont admis dans les écosystèmes compatibles. Fichiers remplacés/firmware stocké nécessitent une revue d'activation. Actifs inconnus/versions absentes des avis nécessitent une revue. Comparez les matériels Linux physiques et Windows aux inventaires des fabricants. L'inventaire natif Windows/macOS cible système, matériel et applications installées.

Le tableau `risks` du rapport liste les risques que le collecteur a enregistrés dans le BOM, avec la source `KODA collection evidence` ; ils ne nécessitent aucun fichier d'avis et restent séparés des `findings` issus des avis. `sbom.cdx.json` et `sbom.spdx.json` portent les risques cryptographiques, et le `bom.cdx.json` fusionné ajoute ceux de l'AI-BOM et de l'OBOM. Dans `bom.cdx.json`, les avis ignorent les nœuds OBOM qui répètent un paquet de l'hôte ; les paquets des conteneurs en cours d'exécution sont rapprochés via leurs nœuds OBOM, qui ne couvrent que les paquets utilisés par leurs processus. Évaluez `containers/<name>/sbom.cdx.json` pour l'inventaire complet d'un conteneur. `risk_observed` signifie que la preuve enregistrée montre la condition ; `review_required`, qu'elle n'a pas pu être écartée.

| ID du constat | Statut | Preuve enregistrée |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | Certificat ou clé d'hôte SSH utilisant RSA de moins de 2048 bits, ou DSA |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | Certificat signé avec MD5 ou SHA-1, sauf si le collecteur l'a vérifié comme auto-signé |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | Configuration autorisant des protocoles antérieurs à TLS 1.2, ou politique cryptographique système LEGACY |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | Le pickle d'un fichier de modèle, ou d'un checkpoint d'un répertoire de modèle, importe des appelables capables d'exécuter du code |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | Le pickle importe des modules hors de la liste autorisée, ou l'inspection est incomplète |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | Écoute de l'hôte hors loopback acceptée par les règles de pare-feu déclarées ; les sources restreintes, les règles non évaluées ou l'absence de déclaration de pare-feu active (`none-observed`) demandent une revue |

## Tableau NIS-SBOM

`nis-sbom` convertit un SBOM CycloneDX collecté en 20 champs de base NIS-SBOM 1.0 (tableau 35 du guide coréen « SW 공급망 보안 가이드라인 1.0 »). Le guide définit les champs et une forme de tableau, pas un schéma de fichier ; le résultat est donc un CSV UTF-8 avec une ligne par composant logiciel. Seuls les composants logiciels sont listés. Le matériel, les fichiers et les actifs cryptographiques sont exclus.

```sh
./koda-bom nis-sbom \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --organization EXAMPLE \
  --output ./nis-sbom.csv
```

`--organization` et `--sequence` (1 par défaut) forment l'identifiant du SBOM `EXAMPLE-YYYYMMDD-000001`. `--product`, `--product-version` et `--author` remplacent le nom de la cible analysée et celui du collecteur. Le fournisseur est celui enregistré dans le SBOM, sinon l'espace de noms du PURL. Seuls les hachages SHA-256 ou plus forts sont indiqués. `SBOM Type` suit la phase du cycle de vie enregistrée dans le SBOM et vaut `Deployed` en son absence. `SPDX Doc. ID` et `Component Alias` restent vides. `Vul. DB` et `Vul. Info` restent vides, car le collecteur ne compare pas les vulnérabilités. Une valeur qu'un tableur exécuterait comme formule reçoit un `'` initial.

## Observations TCP

`--network-evidence` rapproche les mesures préexistantes des sockets de l'hôte/OBOM archivé. `hostField` accepte `machineIdSha256`, `productUuidSha256`, `assetTag` explicite. `scope` vaut `host` ou un ID conteneur complet de 64 caractères.

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

Résultats `connected`, `refused`, `timed-out`. Propriétaires ambigus ou sockets absents restent sans association. Chaque point de mesure et heure demande son observation. Le collecteur ne lance aucun test de connexion. [Matrice](support-matrix.fr.md) · [Preuves complémentaires](additional-bom.fr.md)
