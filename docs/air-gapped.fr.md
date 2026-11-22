# Exécution hors ligne et inspection

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 fournit une archive Linux x86_64 (amd64), noyau 3.2 ou ultérieur. Transférez l’archive et son `.tar.gz.sha256` depuis la publication officielle. Le serveur n’exige pas d’installation de Go, Python, Docker ou jq. NOTICE cite jhny-kor et le dépôt officiel.

[Publication 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Vérifier et extraire

Placez une seule archive correspondante et sa somme dans un répertoire local exécutable. Vérifiez l’archive avant extraction, puis les fichiers internes. Les sommes vérifient les octets transférés. Utilisez une publication officielle de confiance. Un support USB noexec exige une copie vers un système de fichiers exécutable.

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## Inspecter le serveur

Contrôlez architecture, noyau et `doctor`. `supported=true` indique que les prérequis sont remplis. `doctor.kernel` et `context.json.runningKernel` identifient le noyau observé. `kernelFlavor=unknown/unconfirmed` peut accompagner une version connue. root améliore la visibilité DMI, BMC, processus et conteneurs.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Choisir le périmètre

Sans arguments, `koda-bom` crée un dossier sous `bom-output/`, avec `bom.cdx.json` fusionné et sept documents sous `boms/`. AI-BOM s’appelle `aibom.cdx.json`. Le contenu dépend des preuves locales. Pour Qwen, indiquez le véritable répertoire du modèle. H100 apparaît dans HBOM. Configuration, en-têtes et paquets ne déterminent pas l’allocation GPU courante ou les réglages effectifs du service.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

La collecte de répertoires applique `--no-context`. Placez la sortie hors de l’entrée. Le script refuse `/` et accepte des exclusions relatives pour une seule cible. Plusieurs cibles doivent être disjointes et les exclusions absolues. Les limites sont partagées. Les dépendances extérieures peuvent rester inobservées.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Collecter livepatch

Le script optionnel interroge les clients Ksplice, Uptrack ou Canonical existants, nettoie les preuves et lance scan. Les preuves nettoyées sont conservées près du résultat. Capturez `$?` immédiatement. Les délais clients de 30 s et noyau effectif de 10 s restent actifs lorsque le délai scan est levé. Clients et démons ont leur propre comportement réseau.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Limites et codes de sortie

Les valeurs par défaut sont 1,000,000 fichiers ordinaires et 30 minutes. `--max-files 0 --timeout 0` les lève, Ctrl+C annule. Permissions, exclusions, liens, 2 GiB par fichier et limites d’extraction subsistent. `--no-containers` omet conteneurs et images inutilisées. `--no-images` omet conteneurs arrêtés et images inutilisées. 0 signifie complet, 3 partiel avec résultats et 2 échec. Examinez aussi les autres sorties anormales.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Trouver et vérifier les résultats

Utilisez le chemin exact affiché. Le script affiche doctor et preuves avant sa dernière ligne de résultat. Affectez ce chemin à `result`. Les fichiers root peuvent nécessiter sudo. Vérifiez le manifeste principal et ceux des conteneurs/images. Conservez les motifs de collecte partielle.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## Lire les états de collecte et correctifs

`collection.json` contient `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, identité, provenance, intégrité et conteneurs. Le nombre de fichiers correspond à la sélection du parcours. `file_limit_exceeded` fournit `limit` et `observed`. `context.json` contient noyau, processus, sockets, services, réglages et correctifs. `assets.json` conserve matériel, firmware et certificats.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` provient du noyau, `reported-applied` du client. `disabled` et `transitioning` conservent leur sens. `stale`, `identity_mismatch` et `unknown` demandent davantage de preuves. Lisez l’état courant et `patches[].state`, car `reportedState` peut être ancien. Une capture de plus de 24 heures, d’un autre démarrage/noyau ou trop future ne prouve pas l’application actuelle. Last-Check/CheckState de Canonical sont aussi contrôlés. Interprétez absence et `not-reported-patched` avec les preuves noyau/fournisseur.

`integrity.findings[].state=modified` ou `missing` indique différence ou absence. `bindScope=all-interfaces` décrit les adresses d’écoute. L’exposition au-delà du pare-feu demande d’autres preuves. `unidentifiedExecutables` indique une association paquet manquante. `reboot.recommended=not_observed` indique l’absence de signal. Examinez contexte et limites ensemble.

## Comparer au fournisseur et conserver

Le SBOM fournisseur WAR/EAR doit contenir le SHA-256 réel. Une empreinte absente ou différente donne sortie 2. Examinez `reconcile.json` et les motifs partiels. Archivez le répertoire parent complet avec les preuves livepatch nettoyées et calculez sa somme.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Importer et analyser

Envoyez `sbom.cdx.json` ou `sbom.spdx.json` à un Tracker compatible. Chaque conteneur/image possède son SBOM. Gardez collection, context et Syft comme preuves jointes. Le délai d’import est indépendant. La collecte alimente l’analyse ultérieure. Efficacité des correctifs et remédiation CVE nécessitent leurs preuves. Consultez les comptes rendus pour le périmètre exact des versions et VM.

## Documentation

[Exécution hors ligne et inspection](air-gapped.fr.md) · [Compilation et vérification](verification.fr.md) · [Résultats de vérification](verification-results.fr.md)
