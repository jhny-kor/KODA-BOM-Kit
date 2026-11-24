# Validation VM avec noyau réel Ubuntu 24.04.1

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Ceci est un outil de test KODA BOM Kit. Il n’est pas une dépendance de l’exécutable déployé sur un serveur isolé. Il démarre directement Ubuntu Base **24.04.1 amd64** et le noyau Ubuntu officiel **6.8.0-47-generic / paquet 6.8.0-47.47** avec un initramfs personnalisé. QEMU user-mode et les fixtures de répertoire ne prouvent pas le démarrage d’un noyau réel.

Ubuntu Base provient d’un miroir archivé de la distribution. SHA256SUMS.gpg est vérifié avec Ubuntu CD Image Automatic Signing Key (2012), `843938DF228D22F7B3742BC0D94AA3F0EFE21092`. Le trousseau de clés d’archive Ubuntu de ce rootfs authentifié vérifie noble-updates InRelease du 2024-10-18, fourni par le service Snapshot officiel. La chaîne relie Release signé → Packages.xz → SHA-256 et taille des deux DEB. Conservez toutes les URL d’entrée, sommes de contrôle, journaux de signatures et ID d’images Docker.

L’hôte exige Go, Python 3 avec `jsonschema`, Docker et GnuPG (`gpg`/`gpgv`). Il réutilise l’image d’outils Oracle VM. Ces outils ne sont pas installés sur le serveur cible. Exécutez depuis la racine du projet en remplaçant `<ID>` par l’ID réel.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` reprend l’export borné et le baseline indépendant du dispositif Oracle. Ubuntu intègre le pilote loop. Le test charge donc un vrai `dummy.ko` pour vérifier l’observation des modules. Il enregistre indépendamment uname et proc release actifs, système, SHA du collecteur et modules chargés. Il compare les deux SBOM aux schémas officiels figés, sommes de contrôle, versions/source/PURL DEB d’origine et noyaux/modules installés. Relancez prepare, run et validate à chaque nouveau binaire final.

Le rootfs utilise `dpkg --unpack` pour extraire les DEB d’origine et créer une vraie base dpkg. Les dérogations de dépendances sont permises et les paquets restent décompressés. Cela ne prouve pas une installation apt normale ou une configuration achevée. Démarrage systemd complet, GRUB, UEFI/Secure Boot, services de production et matériel physique nécessitent des tests distincts. QEMU n’a ni NIC ni disque. Docker utilise `--network none`, un rootfs en lecture seule et des capabilities supprimées. L’installation de live patches commerciaux ou sous abonnement est hors périmètre.

La validation 0.1.3 utilise `--max-files 0 --timeout 0` pour désactiver les deux limites du collecteur. Le watchdog distinct de 11 minutes du PID 1 et le délai QEMU de l’hôte restent actifs.

Conservez ensemble provenance, journaux de signatures et dpkg, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, les deux SBOM et `validation.json`. Gardez la sortie 3 de collecte partielle. Ne la convertissez pas en sortie 0 de collecte complète.
