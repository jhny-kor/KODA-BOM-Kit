# Résultats de vérification

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Ces comptes rendus datés de KODA BOM Kit et des anciennes versions précisent empreinte, environnement, résultats partiels et points non vérifiés. La publication officielle 0.1.9 identifie archive, somme et périmètre. Chaque nouveau binaire exige ses propres tests.

[Publication 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 2026-11-21 — séparation et fusion

`f0610ca-worktree-00ed83f2acd8` a testé `scan --separate-boms`, `bom-split`, `bom-merge` et `domain-bom` sur deux collectes 0.1.6 archivées. Tous les composants et liens ont été comparés, avec un lien ajouté entre racines par fusion. Dix paires d’ID de certificats Ubuntu représentaient 20 emplacements conservés. Aucun ID dupliqué dans la fusion. Linux ARM64 a combiné quatre BOM observés avec des données synthétiques OpenAPI, modèle, SLSA et fabrication. TCP 18443 réel a été relié à Perl et son paquet. Schémas et sommes ont réussi. Authenticité et preuves terrain restent à contrôler.

| Archive | Composants avant / après | Relations avant / après |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — relations opérationnelles

`f0610ca-worktree-06f22395e26f` a régénéré les OBOM de deux collectes partielles. Les sockets sont comptés par espace de noms/processus. Debian ARM64 a relié `127.0.0.1:18443/tcp` à `/usr/bin/perl` et `perl-base`, vérifié trois références Redfish, des exemples TLS, deux liens de build et 11 sommes. Les OBOM régénérés étaient identiques. Cinq ressources Kubernetes synthétiques ont été reliées aux ID complets archivés. Clusters réels, matériel et sessions TLS restaient hors périmètre.

| Archive | Conteneurs | Sockets hôte + conteneurs | Paquet hôte + conteneurs | Relations comparées |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — 12 corrections Daybreak

Les constats de KODA-SBOM-Maker `cc86c1b` ont été traités. Ils couvrent isolation Go, hachage du flux extrait, limite de 256 couches et réutilisation des empreintes, index ZIP/ZIP64 bornés, whiteouts validés, répertoires exclusifs, correspondance d’avis indexée et bornée, refus de Python optimisé, lecture dans les racines vérifiées, ID courts sûrs, conflits RPM avec epoch et parcours annulable par blocs de 256 entrées.

Go, vet et contrôles de publication ont réussi sur macOS ARM64. Go 1.26.11 / Syft 1.57.1 a produit un binaire Linux amd64 statique hors ligne. Les 306 sommes et les tests CLI/répertoires Debian isolés ont réussi. Avant/après, 88 paquets, un OS, 20 équipements et 15 pilotes concordaient. Les deux collectes étaient partielles avec motifs. Les autres plateformes ont été compilées, leur exécution et de nouvelles VM restaient à vérifier.

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Linux, Go et vet ont réussi sur Docker Desktop `7.0.14-linuxkit`. CPU concordait avec lscpu et 1,736 options noyau ont été lues. Debian avait un paquet local non enregistré sur 147. Rocky distinguait 167 paquets de dépôt, installations locales et sans trace. Neuf conteneurs actifs, 14 arrêtés et 11 images inutilisées ont produit 35 SBOM en environ 3 min 30 s. Les nombres 796, 71 et 51 concordaient. Overlay2 conservait curl et collectait busybox inutilisé. Un conteneur supprimé était `not_collected`. x86 réel, systemd, Kubernetes/k3s/Podman/CRI-O et nouvelles VM restaient non vérifiés.

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` a vérifié identité, sockets réels, 16 conteneurs et cinq modules externes. Sur 735 fichiers, environ 89 MB, exactement un modifié et un déplacé/manquant ont été détectés. RSA-1024 et ECDSA P-384 ont vérifié expiration et clés faibles sans exporter de clés privées. Matériel, snap/flatpak/conda et certains réglages utilisaient des cas synthétiques. RAID/NIC/BMC physiques, SELinux en production, autres moteurs et nouvelles VM restaient non vérifiés.

## 2026-11-18 — 0.1.6-dev

Go, vet, auxiliaires et shell ont réussi. Linux amd64/ARM64 et l’inventaire de base réel macOS ARM64 ont validé schémas et sommes. Windows a seulement été compilé. Fichiers supprimés/remplacés, empreintes d’images et règles locales ont été testés. Le parseur local Tracker lisait les deux CycloneDX. Production et navigateur restaient non vérifiés. La sémantique des 704/811 licences et des 107 nouvelles a été conservée. Le nombre de sommes varie selon le périmètre.

## Historique 0.1.2–0.1.5

0.1.5 a ajouté les relations pnpm et Maven POM, 0.1.4 le script de répertoires et 0.1.3 les limites fichiers/temps. Reliez les empreintes à `release.json`, `VERIFICATION.json` et `dist/evidence/v0.1.x/final-verification.json` lorsqu’ils sont fournis. 0.1.2 a retesté Ubuntu et les deux noyaux Oracle avec son binaire final. Installation des clients sous abonnement et application réelle des correctifs étaient hors des tests synthétiques.

## 2026-10-29 — implémentation et VM Oracle

Les 68 contrôles Linux et vet ont réussi. Les cas uid 65534, entrées/rootfs en lecture seule, sans capacités ni réseau ont validé schémas, PURL, canaris et erreurs. Le conteneur Oracle comptait RPM 182, Python 5 et binary 2. La trace guest syscall montrait zéro tentative réseau et execve supplémentaire. Les deux formats obtenaient HTTP 202 dans un Tracker SQLite isolé. Un petit cas 0.1.0 a pris 0.78 s et 219,644 KiB de RSS maximal.

Les VM Oracle Linux 8.2 ont démarré RHCK/UEK signés. uname/proc et le module loop concordaient. Chacune avait 5,516 composants, dont RPM 186, noyaux 2, modules 5,321, Python 5 et binary 2. Les arbres comptaient RHCK 2,478 et UEK 2,843 modules. Schémas et cinq sommes par VM ont réussi. Sortie 3, collecte partielle et contexte complet conservaient fichiers protégés, liens hors périmètre, conflits OpenSSH et avertissements Syft.

| Kernel | Collecte / total secondes |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## Limites des preuves

Les premières VM utilisaient l’empreinte 0.1.0 ci-dessous. Les versions suivantes ont leurs propres rapports. Serveurs x86 physiques, OS complet, services et correctifs fournisseur restaient hors périmètre. QEMU guest trace et ptrace natif ont des environnements différents. Une collecte en direct peut mélanger plusieurs instants. Choisissez une période stable ou un instantané en lecture seule. Versions et absence d’observations ne suffisent pas à établir l’applicabilité ou la correction des CVE.

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## Documentation

[Exécution hors ligne et inspection](air-gapped.fr.md) · [Compilation et vérification](verification.fr.md) · [Résultats de vérification](verification-results.fr.md)
