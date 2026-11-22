# Preuves complémentaires pour SaaSBOM, AI-BOM et MBOM

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <strong>Français</strong>
  <a href="additional-bom.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="additional-bom.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="additional-bom.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="additional-bom.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


`domain-bom` lit des preuves et artefacts locaux pour créer `saasbom.cdx.json`, `aibom.cdx.json` et `mbom.cdx.json`. `--cyclonedx-17` ajoute les versions 1.7. `scan` accepte les mêmes options. La collecte de l'hôte place les sept BOM dans `boms/` et le document fusionné dans `bom.cdx.json`.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

Les preuves comprennent SHA-256, périmètre et distinction entre déclaration et rapport. L'authenticité des signatures reste non vérifiée dans `koda:domain:authenticity`. Les preuves fournies utilisent `compositions.aggregate=incomplete`. Un hash concordant produit `artifact-binding=sha256-matched`. Un domaine sans preuve lors de la collecte complète porte `no-evidence` avec une couverture inconnue.

Limites cumulées des trois domaines, 12 entrées, 16 MiB par JSON et 10 000 éléments par liste. Les clés JSON dupliquées, identifiants/requêtes/fragments d'URL et modèles de serveur non résolus sont refusés. Les artefacts sont hachés en flux. Les poids et exécutables ne sont jamais exécutés.

## SaaSBOM

`--saas-evidence` accepte OpenAPI 3.x JSON ou `koda-services-1`. OpenAPI fournit titre, version, serveurs absolus déclarés à la racine/au chemin/à l'opération et authentification par opération. L'emplacement des serveurs relatifs reste inconnu. Une opération explicitement anonyme donne `authenticated=false`, toutes les opérations inspectées exigeant une authentification donnent `true`. Si les déclarations sont insuffisantes, le champ est omis. Exemples de corps, contenu des schémas de sécurité, descriptions et secrets sont exclus. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI peut aussi être en YAML. Le YAML doit contenir un seul document ; les clés en double sont rejetées et les nombres gardent leur texte littéral, `version: 1.0` reste donc `1.0`.

La collecte de l'hôte lit aussi la configuration des proxys inverses et répartiteurs de charge : `upstream`, `proxy_pass` et `grpc_pass` de nginx, `ProxyPass` et `BalancerMember` d'Apache, et les `server` des `backend` HAProxy. Chaque backend devient un service avec `observation=declared-proxy-backend` et le fichier et la ligne qui le déclarent. Seuls le schéma, l'hôte et le port sont conservés ; chemins, requêtes et identifiants sont supprimés, et les cibles utilisant des variables sont signalées comme non résolues. L'accessibilité d'un backend se voit dans les connexions sortantes de l'OBOM, pas dans cette déclaration. Les fichiers Debian `*-available` ne comptent qu'au travers de leurs liens `*-enabled`, y compris pour les déclarations TLS du CBOM. Si une analyse de répertoire ne peut pas suivre ces liens, les fichiers sont tout de même lus et un incident signale que leur activation n'est pas résolue.

Utilisez ce format pour les fournisseurs, frontières de confiance, classifications et dépendances.

```json
{
  "schema": "koda-services-1",
  "services": [
    {
      "id": "app",
      "name": "Application",
      "provider": "Example",
      "endpoints": ["https://app.example.invalid/api"],
      "authenticated": true,
      "trustBoundary": true,
      "trustZone": "production",
      "data": [{"flow": "outbound", "classification": "personal-data", "name": "customer-record"}],
      "dependsOn": ["database"]
    },
    {
      "id": "database",
      "name": "Database service",
      "endpoints": ["https://database.example.invalid"],
      "authenticated": true
    }
  ]
}
```

`id` et `name` sont obligatoires. Les autres champs illustrés et `version` sont facultatifs. `dependsOn` référence un service du même fichier. `flow` vaut `inbound`, `outbound`, `bi-directional` ou `unknown`, du point de vue du service. Authentification, confiance et appels reflètent les déclarations fournies.

## AI-BOM

Indiquez le répertoire du modèle sur le serveur cible. La collecte de l'hôte inspecte aussi les chemins autorisés.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` fournit architecture, couches, têtes d'attention, contexte maximal et quantification. Les index de poids décrivent les nombres de tenseurs déclarés et les fragments.
- Les en-têtes safetensors/GGUF fournissent format, tenseurs et métadonnées disponibles. Modèles et fichiers sont reliés par dépendances. La lecture des en-têtes est bornée, même pour de gros poids. Les hashes de configuration/index/en-tête sont distingués du hash complet.
- Les manifestes Ollama relient les couches aux en-têtes des blobs locaux lisibles. L'état de chargement actuel nécessite des preuves d'exécution.
- Une fiche de modèle Hugging Face `README.md` à côté de `config.json` fournit licence, `base_model`, `datasets`, `pipeline_tag`, langue et bibliothèque. Les modèles de base et jeux de données deviennent des composants déclarés liés au modèle. Dans un cache Hugging Face, `refs/main` et les autres refs pointant vers l'instantané sont enregistrées comme `cache-ref`. Les champs de la fiche restent des déclarations de l'éditeur.
- Les fichiers ONNX indiquent version IR, producteur, version du modèle et jeux d'opérateurs. Les domaines d'opérateurs autres que `ai.onnx` et `ai.onnx.ml` sont listés comme `onnx:custom-operator-domain`, car ils exigent une bibliothèque native d'opérateurs personnalisés.
- Les points de contrôle PyTorch (`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt`, zip ou anciens) sont des pickles qui exécutent au chargement les fonctions qu'ils importent. KODA parcourt les opcodes pickle sans les exécuter et enregistre `pickle:safety` : `allowlisted-imports-only`, `unknown-imports` ou `dangerous-imports`, avec chaque `pickle:dangerous-import` tel que `os.system`. Un fichier que l'analyseur ne peut parcourir jusqu'au bout est signalé avec `pickle:inspection=incomplete` et jamais comme uniquement autorisé ; les imports trouvés avant l'échec sont conservés. Les pickles de protocole 0/1 et les cinq flux d'un ancien fichier `torch.save` sont aussi examinés. Préférez safetensors pour tout fichier qui n'est pas uniquement autorisé. Les fichiers pickle et ONNX d'un dossier de modèle Hugging Face, comme `pytorch_model.bin`, `training_args.bin` ou `optimizer.pt`, sont liés à ce modèle, qui indique le résultat le moins sûr dans `artifact-pickle-safety`. Un fichier impossible à inspecter fait passer le modèle au moins à `unknown-imports`, avec `artifact-inspection=incomplete`.
- Sur un hôte en fonctionnement, un processus vLLM, TGI, llama.cpp, SGLang, Triton ou LMDeploy démarré avec un chemin de modèle ou un identifiant de dépôt marque le modèle correspondant avec `runtime-state=referenced-by-running-process` et `serving-process`, et le processus OBOM porte `model-reference`. Cela reflète les arguments de démarrage ; Ollama choisit le modèle à chaque requête et n'est pas rapproché.

### Qwen sous Linux avec GPU NVIDIA

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Remplacez `/srv/models/Qwen` par le chemin réel. Lorsque `snapshots/<revision>/` pointe vers `blobs/`, sélectionnez le répertoire englobant `models--organization--model`. Pour les montages de conteneurs, utilisez le stockage visible depuis l'hôte.

| Preuve | Résultat |
|---|---|
| Architecture, contexte, précision, quantification, fragments, tenseurs | Composants/dépendances de `boms/aibom.cdx.json`, selon le format et les champs présents |
| H100, identifiants PCI, pilote, firmware | `boms/hbom.cdx.json`, à partir de PCI sysfs et du pilote NVIDIA |
| Versions PyTorch, Transformers, vLLM, CUDA | SBOM hôte/conteneur lorsque les métadonnées installées sont lisibles |
| Processus de service et sockets d'écoute | `boms/obom.cdx.json` si le processus et l'exécutable sont observés |

Les données d'entraînement/évaluation et la filiation absentes de la fiche du modèle exigent des déclarations de provenance. Usage GPU/VRAM, allocation MIG et contexte réellement servi nécessitent des observations d'exécution distinctes.

Un artefact de poids seul fournit le SHA-256 complet et les en-têtes safetensors ou GGUF v2/v3 avec `artifact-binding=sha256-calculated`. safetensors fournit dtype et plages de données. GGUF peut fournir `general.name`, `general.architecture`, `general.file_type`. Les données des tenseurs et les calculs exigent une validation supplémentaire. [Format safetensors](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

`koda-model-1` déclare identité, révision, licence, source, modèles de base et jeux de données. Remplacez `sha256` par le hash réel de 64 caractères. Associez dans l'ordre chaque déclaration à `--model-artifact`. Une déclaration concordante permet aussi d'associer d'autres formats.

```json
{
  "schema": "koda-model-1",
  "name": "example-model",
  "version": "revision-2",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "license": "Apache-2.0",
  "source": "https://models.example.invalid/example-model",
  "task": "classification",
  "architecture": "transformer",
  "baseModels": [{"name": "base-model", "version": "revision-1"}],
  "datasets": [{"name": "training-data", "version": "v1", "source": "https://data.example.invalid/training"}]
}
```

Les modèles utilisent `machine-learning-model`, les jeux de données `data`. Dépendances et références `modelCard.modelParameters.datasets` sont conservées. Chaque modèle de base/jeu de données exige `name` et accepte `version`, `sha256`, `source`, `license`. Ces métadonnées sont déclarées par le fournisseur. Le hash de l'artefact principal fourni est vérifié directement.

## MBOM

### Provenance de compilation

`--provenance` accepte un in-toto Statement v1 contenant SLSA provenance v1. Fournissez le produit par `--provenance-artifact`. Exactement un `subject` doit correspondre au SHA-256. Constructeur, type, entrées, identifiant d'exécution et horaires alimentent `formulation.workflows`. Les paramètres internes/externes bruts sont omis. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Champs obligatoires `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType`, `predicate.runDetails.builder.id`. `resolvedDependencies` et `runDetails.metadata` avec `invocationId`, `startedOn`, `finishedOn` sont lus si présents. Vérifiez et extrayez les enveloppes DSSE avant de fournir le Statement JSON.

### Fabrication physique

Utilisez `koda-manufacturing-1` avec `--provenance`. Identifiants et références de pièces désignent les objets physiques.

```sh
./koda-bom domain-bom --output-dir ./results \
  --provenance ./manufacturing.json
```

```json
{
  "schema": "koda-manufacturing-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "observation": "reported",
  "product": {"id": "server", "name": "Server", "model": "R1", "partNumber": "SRV-R1", "manufacturer": "Example"},
  "parts": [{"id": "board", "name": "Mainboard", "partNumber": "MB-1"}],
  "steps": [
    {"name": "Install board", "action": "assembly", "inputIds": ["board"]},
    {"name": "Acceptance test", "action": "test", "inputIds": ["board"]}
  ]
}
```

`observation` vaut `declared` pour un plan ou `reported` pour une exécution rapportée. `observedAt` indique la capture du relevé. Actions acceptées `assembly`, `inspection`, `test`, `packaging`. Jusqu'à 1 000 étapes sont reliées dans l'ordre du tableau. `startedOn`/`finishedOn` sont facultatifs. `inputIds` référence `parts`. Produits et pièces peuvent avoir `version`.

## Exemples exécutables du dépôt

`internal/domainbom/testdata/` contient de petites données synthétiques de services/OpenAPI, modèles, SLSA et fabrication.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./internal/domainbom/testdata/services.json \
  --saas-evidence ./internal/domainbom/testdata/openapi.json \
  --model-evidence ./internal/domainbom/testdata/model.json \
  --model-artifact ./internal/domainbom/testdata/model.safetensors \
  --provenance ./internal/domainbom/testdata/provenance.json \
  --provenance-artifact ./internal/domainbom/testdata/product.bin

./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --provenance ./internal/domainbom/testdata/manufacturing.json
```

[Périmètre de collecte](support-matrix.fr.md) · [Inventaire des actifs](asset-inventory.fr.md)
