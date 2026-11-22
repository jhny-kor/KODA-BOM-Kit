# Périmètre de collecte et limites

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Cette matrice décrit les preuves identifiables. Consultez l'état et les motifs dans `collection.json`. L'exhaustivité dépend des métadonnées, formats et permissions. L'évaluation des vulnérabilités exige des avis concordants.

## Sept BOM CycloneDX

L'hôte `/` produit des documents dans `boms/` et la fusion `bom.cdx.json`. `--cyclonedx-17` ajoute 1.7. Les domaines sans preuve sont indiqués par `no-evidence` et couverture inconnue. [Catégories CycloneDX](https://github.com/CycloneDX/specification#readme)

| BOM | Preuves disponibles | Compléments |
|---|---|---|
| SBOM | Paquets système/langage, versions/PURL, licences/dépendances, JAR, modules et conteneurs | CycloneDX/SPDX fournisseur/CI lié au SHA-256 pour dépendances statiques/de compilation, dans `build-sbom.cdx.json` |
| HBOM | CPU/carte/périphériques/pilotes/firmware, DIMM EDAC, alimentation/ventilateurs, modules mémoire SMBIOS (fabricant, référence, vitesse), alimentations et emplacements | Redfish/registres pour pièces invisibles, références, fournisseurs et cycle de vie |
| CBOM | Certificats/clés/algorithmes publics, émetteurs vérifiés, TLS/SSH, JKS, clés publiques d'hôte SSH, politique cryptographique du système et déclarations OpenSSL de protocole/chiffrement/groupe | TLS mesuré, export public HSM/KMS/magasins protégés |
| OBOM | Hôte/conteneur/processus/fichier/paquet/socket et systemd, destinations TCP sortantes par processus, minuteurs systemd, tâches cron et règles de pare-feu déclarées | Kubernetes du même cluster, Pod/workload/Service/Ingress, labels et `--network-evidence` du même hôte |
| SaaSBOM | Spécifications/OpenAPI dans `saasbom.cdx.json`. Également OpenAPI YAML et backends déclarés dans la configuration nginx, Apache et HAProxy | Fournisseur/catalogue/API, dépendances externes, authentification, confiance, flux classifiés |
| AI-BOM | Configuration, quantification/contexte, index, en-têtes/tailles GGUF/safetensors, Ollama. SHA-256 complet des artefacts explicites. `aibom.cdx.json`. Également en-têtes ONNX, sûreté des imports pickle PyTorch, fiches de modèle et refs de cache Hugging Face, et modèle indiqué au démarrage d'un serveur de modèles | Identité/révision/poids, filiation, fiches/licences, sources entraînement/évaluation |
| MBOM | SLSA concordant ou assemblage/tests déclarés dans `mbom.cdx.json` `formulation` | Étapes/outils/entrées/sorties/exécutions CI ou historique de fabrication/inspection |

## Couches

| Couche | Preuves et limites |
|---|---|
| OS | os-release/vendor release et DB RPM/DEB/APK. Permissions, corruption, source package/module stream manquants peuvent limiter |
| Matériel/firmware | CPU/microcode/CPUID/topologie/ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM. RAID/HBA, RDMA, GPU VBIOS et NIC dépendent du pilote. megaraid_sas nécessite export, BMC root/IPMI et rapprochement des révisions. VM/conteneur peut refléter l'hôte physique |
| Externes | Redfish développé, fwupd/devlink/JSON commun. Versions/états rapportés préservés, actifs sans correspondance à revoir |
| Windows/macOS | Système/OS/firmware/apps. Windows inclut vérifications de compilation croisée. Dépendances internes et mises à jour nécessitent des apports |
| Exécution | Exécutables/bibliothèques et paquet propriétaire dans le même périmètre. Remplacement justifie une revue de redémarrage |
| Identité | SHA-256 machine-id/UUID/séries et tag explicite sur hôte `/`. Permissions et valeurs génériques limitent. Pseudonymisation |
| Sockets | TCP LISTEN/UDP dans le même espace et FD. Bind seul ne détermine pas le pare-feu. Sans propriétaire `unattributedSockets` |
| Connexions sortantes | TCP établi dont le port local n'écoute pas, par processus et destination distante, jusqu'à 16 384 sockets. Un port local fixe vers un port éphémère du pair compte comme connexion acceptée. Seules les connexions ouvertes lors de la collecte sont vues. Processus de l'hôte uniquement. Une connexion vers un port sur lequel cet hôte écoute relie le processus client à ce socket et à son processus propriétaire |
| Tâches planifiées | `/etc/crontab`, `/etc/cron.d`, crontabs utilisateur et scripts `cron.{hourly,daily,weekly,monthly}`, ainsi que les minuteurs systemd activés avec leur calendrier `On*`. Seul le chemin absolu du programme est conservé ; les arguments sont supprimés |
| Pare-feu | Fichiers iptables-save (RHEL/Debian/ufw), zone par défaut de firewalld avec ses services et chaînes nftables à hook input avec includes littéraux. Ce sont des déclarations de fichiers ; le jeu de règles chargé dans le noyau n'est pas lu. Une chaîne de base sans politique accepte ; ufw avec `ENABLED=no` est enregistré comme `disabled`. Les règles limitées au loopback, à l'état établi ou négatives ne comptent pas comme ports ouverts ; une acceptation TCP/UDP de tout le protocole ouvre tous ses ports. Les sockets en écoute hors loopback reçoivent `firewall-declared` : `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared` ou `undetermined` |
| Réglages/redémarrage | SELinux, AppArmor, lockdown, FIPS, démarrage autorisé, noyau `y`/`m`, reboot-required, modules/noyau plus récent de même famille. Absence de signal ne prouve pas l'inutilité d'un redémarrage |
| SSH | Déclarations globales, `Match` exclu, priorité effective d'`Include` non calculée |
| Taint/modules | `kernel.tainted`, `/proc/modules`, version/srcversion sysfs disponibles |
| Exécutables inconnus | Même root sans paquet/composant/produit. Autres espaces de montage exclus. Enquête complémentaire nécessaire |
| Origine | apt texte/gz/lz4 par nom, dnf/yumdb. Listes supprimées, dnf5/apk non pris en charge. URL/chemins omis |
| Services | systemd wants/requires, unités/drop-ins, cgroup v1/v2. Premier ExecStart, exécutable relatif sans paquet. Slice spécifique peut sembler arrêté. Pas de SysV. Les minuteurs activés enregistrent leur calendrier `On*` et le service qu'ils démarrent |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge matériel/BIOS, Lenovo ThinkSystem. Lacunes modèle/dictionnaire peuvent empêcher la concordance. Pas de HPE/BMC |
| Intégrité | Hashes exécutables/bibliothèques RPM/dpkg/apk. Config/ghost exclus. 8 GiB hôte, 1 GiB conteneur. prelink peut créer de faux écarts |
| CBOM | PEM/DER, clés/algorithmes publics, chaînes JKS v1/v2 et hashes d'alias. Clés chiffrées ignorées, intégrité JKS non vérifiée. Noms, clés privées, PKCS#12, magasins système, ensembles >20 exclus. Clés publiques d'hôte SSH incluses. `crypto-policies` et MinProtocol/CipherString/Ciphersuites/Groups de `openssl.cnf` sont des déclarations ; `.include` et l'activation des sections ne sont pas résolus |
| Noyau | uname, images/modules installés, vermagic, RPM. Actif et installé distingués. Module absent peut correspondre à une fonction intégrée |
| Livepatch | sysfs, Oracle raw Ksplice et helper Ksplice/Uptrack/Canonical facultatif. Divergences boot/noyau/heure invalident la preuve d'application. CVE à analyser séparément |
| Java | JDK/JRE release, manifestes JAR/WAR/EAR, Maven. Métadonnées shaded modifiées/supprimées limitent |
| PHP | Paquet/interpréteur, Composer installé, PEAR. Exclut lock seul. Exploitabilité selon configuration |
| snap/flatpak/conda | snap current/DEB, flatpak active/AppStream, conda-meta. PURL generic snap/flatpak, version absente sans AppStream, nom de canal conda seul |
| Python | dist-info/egg-info, venv, métadonnées réelles `.pyz`/`.pex`. Absence/permissions limitent |
| Node/JS | node_modules/runtime, jQuery/jQuery UI/Fancytree dans fichiers et EAR/WAR/ZIP/JAR. Nom seul insuffisant. Structures prises en charge et limites d'inspection |
| Go/Rust | Build info Go, cargo-auditable ELF. Absence laisse dépendances inconnues, corruption/excès produit un résultat partiel |
| .NET | `.deps.json`, DLL gérées et ressources de version. DLL isolée sans NuGet PURL, single-file à vérifier |
| Ruby | specifications/gems installés et default. Gemfile.lock seul ou métadonnées supprimées insuffisants |
| Serveurs natifs | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB. Binaires personnalisés/strip/copies statiques peuvent rester inconnus |
| Serveurs Java | Tomcat ServerInfo/manifest/catalina.jar, WebLogic/JBoss/WildFly installation/correctifs. `.patch_storage` seul ne prouve pas l'activation. JEUS sans fixtures réelles non vérifié |
| Arrêtés/images | Docker overlay2, containerd overlayfs/k3s/RKE2, Podman/CRI-O rootful. Reconstruction temporaire limitée à 16 GiB/root et espace vérifié. Autres pilotes/rootless non pris en charge, pas de sockets |
| Conteneurs actifs | Roots procfs, métadonnées disque, `containers/<name>/`. Volumes/bind mounts et sandbox Kubernetes exclus. Root invisible expliqué. Sans API, sockets appartenant au conteneur seulement |
| Archives image | Docker/OCI tar Linux amd64 explicite, hash/digest vérifié. Contenu de l'image, noyau/exécution hôte observés séparément |
| AIX/Oracle | `aix-import` filesets, correctifs temporaires, OPatch par Home, SQL facultatif. Huit Homes maximum d'un serveur. Exécution nécessite une preuve |

Les installations manuelles conservent leur emplacement/instance. Un nom et une version identiques peuvent avoir des correctifs différents. CPE inconnu laissé vide. Utilisez les identifiants confirmés et leurs preuves pour la revue.

Formats par défaut CycloneDX 1.6/SPDX 2.3, avec 1.7 facultatif. [Inventaire et évaluation](asset-inventory.fr.md) détaille `assess`, OSV/CSAF exacts et schémas. [Preuves complémentaires](additional-bom.fr.md) couvre services, modèles et fabrication.

## Scénarios de régression

Les cas couvrent PHP/Composer, Node runtime/node_modules, builds JDK complets, installation/correctifs WebLogic, Tomcat manuel/AJP/HTTP2, versions httpd/mod_http2, origine/alias/rewrite nginx, copies OpenSSL CLI/libssl/libcrypto et noyaux UEK/RHCK actifs/installés. Ils vérifient les preuves d'identification. Une conclusion de vulnérabilité exige un rapprochement avec un avis.
