# Compilation et vérification

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 fournit une archive hors ligne Linux amd64 et son SHA-256. Identifiez le binaire testé par son empreinte exacte et son environnement. La collecte Linux vise x86_64 et ARM64, les archives Docker/OCI linux/amd64. L’inventaire macOS et Windows utilise des commandes système fixes en lecture seule. L’exécution Windows reste non vérifiée. Les résultats historiques concernent leurs propres builds.

[Publication 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Formats et intégrité

Les formats par défaut sont CycloneDX 1.6 et SPDX 2.3. `--cyclonedx-17` ajoute 1.7 depuis le même inventaire. Avec `--format cyclonedx`, deux documents sont produits. Avec `--format spdx`, la combinaison est refusée avant écriture. `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` et les deux scripts de collecte acceptent l’option. Vérifiez les fichiers attendus selon les options.

| Sortie | Format |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` contrôle les schémas locaux, identités, preuves, propriétés, licences, relations, périmètre et entrées manquantes ou dupliquées du manifeste. Les schémas 1.7 sont figés sur 1.7.1, commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`, avec provenance dans `tests/schemas/provenance.json`. Les 704 licences de 1.6 deviennent 811 en 1.7. Les 107 nouvelles utilisent `license.name` en 1.6 et `license.id` en 1.7. Contrôlez aussi l’état partiel dans `collection.json`.

## Contrôles sur la machine de compilation

Préparez Go, Python, Docker, les modules en cache et les dépendances des schémas. `trusted_go_sha256` contient l’empreinte Go vérifiée indépendamment. `GOPROXY=off` utilise le cache. La QA refuse `python3 -O` et `PYTHONOPTIMIZE`. Le serveur cible utilise le binaire fourni. Sous macOS, utilisez `shasum -a 256 -c SHA256SUMS`.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Tests d’intégration

Exécutez les commandes sur la distribution finale extraite. Préparez les caches avant de couper le réseau. .NET/Ruby demande le SDK .NET 10. Go/Rust utilise les modules en cache et le fichier ELF ripgrep fixé, ou `--rust-binary`. Fancytree compare npm SHA-512 ou GitHub SHA-256. Les tests compatibles acceptent `--tracker-root /path/to/tracker` pour vérifier le véritable parseur local.

`domain_bom_integration.py` exécute directement le binaire. Lancez ce test sous Linux amd64.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

Les tests couvrent Java imbriqué, pyz/pex, Go/Rust, provenance, limites de répertoires, empreintes fournisseur, PURL et dépendances. Les cas Linux couvrent sockets, conteneurs, firmware, services, réglages, intégrité et certificats. Les cas AIX vérifient Oracle Home, Listener et OPatch. Les équipements BMC/NIC/OT, le stockage Kubernetes réel et les clients de correctifs sous abonnement nécessitent des preuves de terrain.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## Noyaux Linux et reproduction des VM

Exécutez les tests Linux sous Linux. macOS peut les compiler pour l’architecture du conteneur. Utilisez le binaire final dans les VM. RHCK `4.18.0-193.el8.x86_64` et UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` démarrent séparément depuis les RPM signés de `tests/oracle-vm/kernels.json`. Conservez provenance, signatures, ID d’images, journaux série, référence et validation.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

L’exécuteur Oracle utilise QEMU system TCG, 4 GiB, deux CPU et un PID 1 statique dédié, sans réseau ni disque invité. Il contrôle uname, proc, le chargement réel de loop et les noyaux installés et actifs. Ubuntu démarre `6.8.0-47-generic` depuis des paquets authentifiés. GRUB, UEFI/Secure Boot, systemd complet, SELinux enforcing, pilotes physiques et services exigent d’autres tests. Un conteneur Oracle partage le noyau de l’hôte.

[Oracle VM](tests/oracle-vm/README.fr.md) · [Ubuntu VM](tests/ubuntu-vm/README.fr.md)

## Appels système, ressources et analyse ultérieure

Tracez le binaire final dans un conteneur isolé. Si l’émulation ARM64 ne décode pas ptrace, `trace-network.sh` retourne 77. Une trace QEMU guest syscall doit préciser son environnement. Affirmer zéro tentative exige une trace fonctionnelle. Les clients et démons lancés par le script livepatch ont leur propre comportement réseau.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

Les limites sont 1,000,000 fichiers ordinaires sélectionnés et 30 minutes. Testez limites, options invalides, annulation, permissions, corruption et exclusions. `--max-files 0 --timeout 0` lève ces limites. Mesurez durée et RSS maximal sur les données réelles. Deux tâches parallèles ne fixent pas un plafond mémoire. Tracker utilise une base temporaire isolée pour les deux formats. Les avis locaux dépendent des règles et observations. Déploiement et correction de CVE nécessitent leurs propres preuves.

## Documentation

[Exécution hors ligne et inspection](air-gapped.fr.md) · [Compilation et vérification](verification.fr.md) · [Résultats de vérification](verification-results.fr.md)
