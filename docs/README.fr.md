<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.fr.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Recueillez les données logicielles, matérielles et opérationnelles d’un hôte Linux avec un seul exécutable hors ligne. KODA BOM Kit produit sept nomenclatures CycloneDX, une nomenclature fusionnée et un inventaire logiciel au format SPDX.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>Télécharger la v0.1.8</b></a> ·
  Auteur d’origine <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Dépôt officiel</a>
</p>

## Démarrage rapide

Téléchargez l’archive Linux amd64 et son fichier SHA-256. Transférez les deux fichiers dans un répertoire vide du serveur cible, puis exécutez les commandes ci-dessous. Le serveur n’a besoin ni de Go, ni de télécharger des paquets, ni d’une base de vulnérabilités.

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## Fichiers produits

La dernière ligne indique le répertoire créé dans `bom-output/`. Ouvrez `bom.cdx.json` pour consulter l’inventaire fusionné. Les sept nomenclatures individuelles se trouvent dans `boms/`.

| Fichier | Contenu |
|---|---|
| `boms/sbom.cdx.json` | Paquets, bibliothèques et applications installés |
| `boms/hbom.cdx.json` | Périphériques, micrologiciels et pilotes |
| `boms/cbom.cdx.json` | Actifs cryptographiques tels que certificats et algorithmes |
| `boms/obom.cdx.json` | Relations observées entre services, processus, sockets et paquets |
| `boms/aibom.cdx.json` | Fichiers de modèles locaux, poids et métadonnées fournis |
| `boms/saasbom.cdx.json` | Services décrits par un document OpenAPI ou un manifeste de service, et backends déclarés dans la configuration des proxys |
| `boms/mbom.cdx.json` | Processus de fabrication et de compilation décrits par les éléments fournis |

Une nomenclature peut rester vide en l’absence d’éléments observables. Consultez son état et `collection.json` pour en connaître la raison. Tracker accepte `sbom.cdx.json` ou `sbom.spdx.json` à la racine du résultat. Les formats par défaut sont CycloneDX 1.6 et SPDX 2.3. Ajoutez `--cyclonedx-17` pour produire également CycloneDX 1.7.

Pour relancer la fusion, copiez le répertoire `boms/` entier avec son manifeste, ses relations et ses sommes de contrôle. Affectez à `run_dir` le chemin affiché par le collecteur.

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Documentation

- [Installation hors ligne et contrôle des résultats](air-gapped.fr.md)
- [Commandes du collecteur et fichiers produits](collector-guide.fr.md)
- [Données matérielles, cryptographiques et opérationnelles](asset-inventory.fr.md)
- [Manifestes de services, de modèles d’IA et de fabrication](additional-bom.fr.md)
- [Plateformes prises en charge et limites de la collecte](support-matrix.fr.md)
- [Procédures de compilation et de vérification](verification.fr.md)
- [Résultats et périmètre des essais](verification-results.fr.md)

### Code source et environnements de test

- [Import de données externes](internal/assetimport/README.fr.md)
- [Inventaire des plateformes](internal/platforminventory/README.fr.md)
- [Identification des produits](internal/products/README.fr.md)
- [Oracle Linux VM](tests/oracle-vm/README.fr.md)
- [Ubuntu VM](tests/ubuntu-vm/README.fr.md)

## Licence et attribution

KODA BOM Kit est distribué sous licence Apache-2.0. Les mentions ci-dessous identifient l’auteur d’origine et les licences des dépendances fournies. [Apache-2.0](../LICENSE) · [Mention de l’auteur](../NOTICE) · [Mentions relatives aux tiers](THIRD_PARTY_NOTICES.fr.md)
