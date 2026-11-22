# Outil de validation du démarrage direct des noyaux Oracle Linux 8.2

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` est le **PID 1 de la VM de validation** de KODA BOM Kit. La contrainte `//go:build ignore` l’exclut des tests Go ordinaires. Compilez-le explicitement avec la commande suivante.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker et QEMU sont des outils de validation du PC de compilation. Livrez l’exécutable `koda-bom` au serveur isolé. Cet outil et l’interpréteur Python ne sont pas des dépendances de l’exécutable déployé.

## Reproduction

Le runner émule x86_64 avec TCG dans un conteneur QEMU sur un hôte ARM64. La VM utilise 4 GiB de RAM et 2 vCPU, avec une limite de 6 GiB pour le conteneur. Exécutez depuis la racine du projet sur le PC externe. Remplacez `<ID>` par l’ID réel affiché par `run.py` et conservez les rapports précédents.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

L’hôte exige `jsonschema` et vérifie hors ligne les schémas officiels figés dans `tests/schemas`. Les téléchargements de préparation nécessitent le réseau. La VM fonctionne sans connexion externe. Conservez l’ID d’image utilisé, car une étiquette peut changer.

`prepare.py` vérifie le SHA-256 et la taille des quatre RPM figés dans [kernels.json](../../../tests/oracle-vm/kernels.json), soit 120,245,036 octets, ainsi que l’empreinte de la clé Oracle Linux 8. Il importe la clé publique dans la base RPM d’un nouveau conteneur Oracle, vérifie les signatures avec `rpm -Kv`, puis installe les noyaux avec `--nodeps --noscripts --notriggers`. Il crée un système de fichiers pour vérifier images de noyau, modules et métadonnées RPM. Les scripts d’installation ordinaires, dracut et la configuration GRUB sont hors périmètre.

Relancez `prepare.py` avec le binaire final dans le répertoire existant pour reconstruire collecteur, PID 1 et initramfs depuis le système de fichiers noyaux/RPM en cache. Redémarrez les deux VM et comparez le **SHA-256 du binaire final** au baseline. Les résultats d’une ancienne compilation ne valident pas une nouvelle publication.

Conservez `input-provenance.json`, `rpm-signature-install.log` et, pour chaque exécution, `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, les deux SBOM et leurs sommes de contrôle. La provenance contient les empreintes RPM, noyau, initramfs, PID 1, collecteur et les ID d’images Oracle/QEMU. Un rapport de validation de publication distinct relie ces preuves au SHA-256 de l’archive distribuée.

## Préparation de l’invité

L’initramfs contient le système de fichiers Oracle Linux 8.2, la base RPM des deux noyaux installés, les images dans `/boot`, les deux arbres `/lib/modules`, `/koda-bom` à tester et l’outil comme `/init`. RHCK et UEK doivent chacun démarrer directement leur propre image. Un conteneur ou QEMU user-mode seul ne fournit pas cette preuve. Vous pouvez placer un module de version correspondante extrait du RPM officiel à l’emplacement suivant.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

L’outil enregistre le SHA-256 du module et tente son chargement avec `init_module`. Il distingue les états et erreurs si le module manque, est déjà chargé ou échoue à cause des signatures ou dépendances. Comparez `loadedModulesAfter` au `loadedModules` du collecteur pour confirmer le chargement. Une absence d’observation ne prouve pas l’absence de fonctionnalité.

QEMU ne reçoit ni interface réseau externe ni disque virtuel. Le runner utilise `-accel tcg,thread=single -cpu max -smp 2 -m 4096`. L’invité de test utilise `random.trust_cpu=on` pour éviter l’attente de `getrandom` au début du démarrage. Ce paramètre de test n’est pas une recommandation de production. Conservez sur l’hôte les réglages réels de CPU/accélération et les sommes de contrôle noyau, RPM, initramfs et collecteur.

## Exécution et collecte

L’outil monte `/proc`, `/sys`, `/dev`, `/tmp`, `/results` et définit un nom d’hôte synthétique. Le baseline indépendant enregistre uname, `/proc/sys/kernel/osrelease`, OS release, modules avant/après, ligne de commande du noyau et somme de contrôle du collecteur. Nom d’hôte et ligne de commande appartiennent uniquement à cette preuve de VM synthétique. La politique normale du produit reste applicable. Le collecteur est exécuté une fois avec la commande suivante.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

Utilisez le mode live-host par défaut sans `--target /payload`. La validation 0.1.3 fixe les limites de fichiers et de temps du collecteur à 0 pour les désactiver. Le watchdog distinct de 11 minutes du PID 1 et le délai QEMU de l’hôte restent actifs pour libérer les ressources. stdout et stderr sont chacun limités à 1 MiB et stockés séparément. Code de sortie, durée et erreurs vont dans `/results/baseline.json`. La sortie 3 représente une collecte partielle et doit rester 3.

Les résultats transitent sur la sortie série en **base64(gzip(tar))** entre ces marqueurs.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

Si le total décompressé dépasse 256 MiB ou 10,000 fichiers, seul un baseline expliquant l’échec est exporté. Après export, sync et poweroff sont tentés. En cas d’échec, PID 1 reste vivant pour éviter un kernel panic. Le runner de l’hôte doit terminer QEMU si l’invité dépasse son délai.

## Contrôles obligatoires

- Le uname du baseline correspond à proc release et RHCK/UEK démarrent chacun la version prévue.
- `context.json.mode=live-host` et `runningKernel` correspondent exactement au baseline indépendant.
- UEK rapporte `kernelFlavor=UEK` et RHCK respecte le contrat actuel `RHCK-compatible`.
- L’inventaire natif conserve les deux noyaux installés et epoch/version/release/arch/source package de chaque RPM.
- Les noyaux installés sont distingués du noyau en cours identifié par context.
- `metadata.kernelVersion` et `versionMagic` correspondent à chaque arbre installé. Les modules chargés correspondent au baseline du noyau actif.
- Les deux schémas SBOM et sommes de contrôle passent. Échecs et états partiels sont rapportés fidèlement.

## Limites de validation

- De vrais noyaux invités Oracle RHCK/UEK démarrent. La validation de serveurs physiques x86_64 reste distincte.
- L’espace utilisateur Oracle Linux 8.2 et les noyaux officiels tournent dans un initramfs personnalisé. Démarrage systemd complet, installation GRUB, UEFI/Secure Boot, SELinux enforcing et intégration des services de production sont hors périmètre.
- Le test `loop` vérifie le chargement et l’observation d’un module réel. Il ne couvre pas tous les pilotes ou matériels. Les modules installés d’un noyau inactif ne doivent pas être considérés comme chargés.
- La sortie `3` et `collection.status=partial` sont acceptées avec leurs raisons conservées. Réussir l’identification du noyau, la sortie standard et l’intégrité ne démontre pas une collecte complète de tous les fichiers.
