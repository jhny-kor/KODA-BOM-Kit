# KODA BOM Kit — Commandes de collecte et fichiers produits

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Choisir le périmètre

Sur un hôte actif, le collecteur inventorie le système, les paquets, les conteneurs et le matériel accessible. L’analyse d’un répertoire couvre son arborescence. Celle d’une image lit une archive Docker ou OCI exportée. Choisissez un type d’entrée par exécution. Les limites par défaut sont d’un million de fichiers ordinaires et de 30 minutes. `--max-files 0 --timeout 0` lève ces deux limites. Les droits d’accès et les limites du système de fichiers et des archives continuent de s’appliquer.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Analyser un ou plusieurs répertoires

Le script prend un répertoire cible et, en option, le répertoire parent des résultats. Il utilise `--no-context` et refuse `/`. Placez les chemins contenant des espaces entre guillemets. Employez `--exclude-dir` pour un répertoire et `--exclude` pour un motif. Avec plusieurs cibles, choisissez des arborescences distinctes et des chemins absolus pour les exclusions de répertoires. Les emplacements restent identifiés par `target-1`, `target-2` après fusion.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Lire l’état des correctifs à chaud

L’analyse de l’hôte lit l’état du noyau dans sysfs. Le script facultatif interroge les clients Canonical Livepatch, Ksplice ou Uptrack installés et filtre leurs sorties. Un rapport importé compte comme actuel s’il correspond au même démarrage et au même noyau et date de 24 heures au plus. L’absence d’entrée ne permet pas de conclure sur la correction d’une CVE.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Recréer le graphe opérationnel ou fusionner un jeu de données

L’OBOM relie sockets en écoute, processus et paquets installés. L’adresse d’écoute locale ne suffit pas à établir la joignabilité depuis l’extérieur. Ajoutez des observations exportées avec `--kubernetes-evidence` ou `--network-evidence`. Affectez à `set_dir` le répertoire de découpage contenant `bom-set.json`. Conservez les relations et les sommes de contrôle. Les jeux archivés sous l’ancien nom `mlbom.cdx.json` restent utilisables.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Fournir des données aux autres nomenclatures

Indiquez le répertoire du modèle installé au collecteur d’IA. Fournissez un manifeste de service ou de processus pour les services SaaS ou la fabrication. `--asset-evidence` importe les données de périphériques Redfish, de micrologiciels ou de cryptographie. Une nomenclature de compilation est associée à l’artefact analysé quand le SHA-256 concorde. Les formats figurent dans les guides en fin de page.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## Importer des relevés IBM AIX et Oracle

Exécutez le script sur AIX, puis l’importateur sur l’hôte d’analyse Linux. Fournissez la sortie OPatch conservée par le propriétaire de l’Oracle Home et, au besoin, l’historique des correctifs SQL exporté par l’administrateur. Huit Homes distincts sont admis. La version du Listener nécessite des éléments du même Home. Rapprochez les identifiants de correctifs de l’avis du fournisseur.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Identifier les dépendances déployées

Pour npm et pnpm, les liens dépendent des emplacements installés, de la résolution des pairs et des versions. La détection du JavaScript statique couvre jQuery, jQuery UI et Fancytree. Go utilise les données de compilation intégrées, Rust ELF les données cargo-auditable. Pour .NET, comparez .deps.json aux DLL managées déployées. Ruby utilise les gemspec installées. Java conserve les chemins des bibliothèques imbriquées dans WAR, EAR et Spring Boot. Les coordonnées inconnues restent indéterminées.

## Comparer un déploiement à la nomenclature du fournisseur

Fournissez un WAR ou un EAR et un document CycloneDX 1.4–1.7 ou SPDX 2.3 portant le SHA-256 de cette archive. Examinez `common`, `observedOnly`, `supplierOnly` et `unresolved` dans `reconcile.json`. Transmettez à Tracker la nomenclature observée. La limite est de 512 Mio pour le déploiement et de 32 Mio pour la nomenclature du fournisseur.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Vérifier la couverture

Sur une machine de compilation ou de test, comparez la même copie immuable du déploiement avec KODA, Syft et Trivy. Le script nécessite Python 3.11 ou ultérieur. Utilisez `--expected` pour les composants et relations vérifiés ou `--baseline` pour les régressions. Les tests Tracker facultatifs envoient les données au service de test spécifié. Pour examiner le graphe enregistré, fournissez `--normalized-bom-command`.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Interpréter une collecte

Affectez à `run_dir` le chemin indiqué par le collecteur. Les codes de sortie sont 0 pour une collecte complète, 3 pour des résultats partiels et 2 pour un échec. Consultez `collection.json` pour les limites, omissions et erreurs, `context.json` pour les relations à l’exécution et `assets.json` pour les périphériques ou certificats. Chaque conteneur ou image dispose de ses propres sommes de contrôle. La version et la date seules ne permettent pas d’établir la présence d’une vulnérabilité.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Compiler sur une autre machine

La machine de compilation utilise Go et Python 3. Cette version a été compilée avec Go 1.26.11. Pour un autre exécutable Go, fournissez son chemin et son SHA-256 vérifié. La compilation hors ligne requiert un cache de modules préchargé. L’archive distribuée cible Linux amd64 et le code source se compile également pour Linux ARM64. La provenance est enregistrée dans `release.json`.

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Documentation

- [Installation hors ligne et contrôle des résultats](air-gapped.fr.md)
- [Données matérielles, cryptographiques et opérationnelles](asset-inventory.fr.md)
- [Manifestes de services, de modèles d’IA et de fabrication](additional-bom.fr.md)
- [Plateformes prises en charge et limites de la collecte](support-matrix.fr.md)
- [Procédures de compilation et de vérification](verification.fr.md)
- [Résultats et périmètre des essais](verification-results.fr.md)
