# Additional evidence for SaaSBOM, AI-BOM and MBOM

<!-- koda-doc-nav -->
<p align="center">
  <strong>English</strong>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="additional-bom.fr.md"><img src="badges/fr.svg" alt="Français"></a>
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


`domain-bom` reads local evidence and artifacts to create `saasbom.cdx.json`, `aibom.cdx.json` and `mbom.cdx.json`. `--cyclonedx-17` adds version 1.7 files. The same evidence flags are accepted by `scan`. Default host collection places the seven individual BOMs in `boms/` and the merged document in `bom.cdx.json`.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

Evidence records contain SHA-256, observation scope and whether data was declared or reported. Signature authenticity remains unverified in `koda:domain:authenticity`. Supplied evidence produces `compositions.aggregate=incomplete`. A matching declaration and artifact produce `artifact-binding=sha256-matched`. A domain without evidence in a full host scan is marked `no-evidence` with unknown coverage.

A command accepts up to 12 inputs across these three domains. Each JSON evidence file is limited to 16 MiB, each list to 10,000 entries. Duplicate JSON keys, URL user information, query strings, fragments and unresolved server templates are rejected. Artifact hashes are streamed. Model weights and executable artifacts are never executed.

## SaaSBOM

`--saas-evidence` accepts OpenAPI 3.x JSON or `koda-services-1`. OpenAPI supplies title, version, explicit absolute servers at root/path/operation level and operation authentication declarations. Relative default servers have an unknown deployment location. Explicit anonymous operations set `authenticated=false`. If all inspected operations require authentication, the value is `true`. Insufficient declarations leave it absent. Body examples, security scheme contents, descriptions and secrets are omitted. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI may also be YAML. YAML must be one document; duplicate keys are rejected and numbers keep their literal text, so `version: 1.0` stays `1.0`.

A host scan also reads reverse proxy and load balancer configuration: nginx `upstream`, `proxy_pass` and `grpc_pass`, Apache `ProxyPass` and `BalancerMember`, and HAProxy `backend` servers. Each backend becomes a service with `observation=declared-proxy-backend` and the file and line that declared it. Only scheme, host and port are kept; paths, queries and credentials are dropped, and targets that use variables are reported as unresolved. Whether a backend is reachable is shown by OBOM outbound connections, not by this declaration. Debian `*-available` files count only through their `*-enabled` links, for these backends and for CBOM TLS declarations alike. When a directory scan cannot follow those links, the files are still read and an issue notes that their enablement is unresolved.

Use this schema for providers, trust boundaries, data classification and service dependencies.

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

`id` and `name` are required. The other illustrated fields and `version` are optional. `dependsOn` references service IDs in the same file. Data `flow` is `inbound`, `outbound`, `bi-directional` or `unknown`, relative to the service. Authentication, trust and call relationships reflect the supplied declarations.

## AI-BOM

Inspect a model directory on the target server. Host collection applies the same inspections to admitted paths.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` supplies architecture, text-model layers and attention heads, maximum context and quantization. Weight indexes supply declared tensor counts and shard lists.
- safetensors and GGUF headers supply format, tensor counts and available metadata. Model and weight file components are linked through dependencies. Discovery reads bounded headers even for large weights. Configuration, index and header hashes are identified separately from full-file hashes.
- Ollama manifests link model layers to readable local blob headers. Confirming the model server's current loading state requires runtime evidence.
- A Hugging Face `README.md` model card next to `config.json` supplies license, `base_model`, `datasets`, `pipeline_tag`, language and library. Base models and datasets become declared components linked to the model. In a Hugging Face cache, `refs/main` and other refs that point at the snapshot are recorded as `cache-ref`. Model card fields remain publisher declarations.
- ONNX files report IR version, producer, model version and operator sets. Operator domains outside `ai.onnx` and `ai.onnx.ml` are listed as `onnx:custom-operator-domain`, because they need a native custom operator library.
- PyTorch checkpoints (`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt`, zip or legacy) are pickles that run the callables they import when loaded. KODA walks the pickle opcodes without executing them and records `pickle:safety`: `allowlisted-imports-only`, `unknown-imports` or `dangerous-imports` with each `pickle:dangerous-import` such as `os.system`. A file the scanner cannot walk to the end, including protocol 0/1 pickles and every stream of a legacy `torch.save` file, is reported with `pickle:inspection=incomplete` and never as allowlisted-only; imports found before the failure are kept. Prefer safetensors for any file that is not allowlisted-only. Pickle and ONNX files in a Hugging Face model folder, such as `pytorch_model.bin`, `training_args.bin` or `optimizer.pt`, are linked to that model, which reports the least safe result as `artifact-pickle-safety`. A file that cannot be inspected raises the model to at least `unknown-imports` with `artifact-inspection-status=incomplete`.
- On a live host, a vLLM, TGI, llama.cpp, SGLang, Triton or LMDeploy process started with a model path or repository ID marks the matching model `runtime-state=referenced-by-running-process` with `serving-process`, and the OBOM process carries `model-reference`. This reflects the start-up arguments; Ollama chooses models per request and is not matched.

### Qwen on a Linux server with NVIDIA GPUs

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Replace `/srv/models/Qwen` with the server's actual path. For Hugging Face symlinks from `snapshots/<revision>/` to `blobs/`, select the enclosing `models--organization--model` directory. For container bind mounts, use the storage path visible from the host.

| Evidence | Output |
|---|---|
| Model architecture, context, precision, quantization, shards and tensors | Components and dependencies in `boms/aibom.cdx.json`, depending on the stored format and available fields |
| H100 model, PCI identifiers, driver and firmware | `boms/hbom.cdx.json`, using Linux PCI sysfs and NVIDIA driver information |
| PyTorch, Transformers, vLLM and CUDA package versions | Host or container SBOM when installed metadata is readable |
| Serving process and listening sockets | `boms/obom.cdx.json` when the process and executable are observed |

Training/evaluation data and lineage beyond the model card require provenance declarations. Current GPU/VRAM usage, MIG allocation and serving context need separate runtime observations.

A standalone weight artifact records full-file SHA-256 and available safetensors or GGUF v2/v3 header metadata with `artifact-binding=sha256-calculated`. safetensors supplies dtype and data ranges. GGUF may supply `general.name`, `general.architecture` and `general.file_type`. Tensor data and model computations require separate validation. [safetensors format](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

Use `koda-model-1` to declare identity, revision, license, source, base models and datasets. Replace the example `sha256` with the actual 64-character artifact hash. Pair every declaration with `--model-artifact` in order. A matching declaration can bind other model file formats too.

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

Models use component type `machine-learning-model`, datasets use `data`. Dependencies and `modelCard.modelParameters.datasets` references are retained. Each base model/dataset requires `name` and can include `version`, `sha256`, `source` and `license`. Their metadata is supplier-declared. The separately supplied primary artifact's hash is verified directly.

## MBOM

### Software build provenance

`--provenance` accepts an in-toto Statement v1 containing SLSA provenance v1. Supply the actual product through `--provenance-artifact`. Exactly one `subject` must match its SHA-256. Builder, build type, resolved inputs, invocation ID and start/end timestamps populate CycloneDX `formulation.workflows`. Raw external/internal parameters are omitted. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Required fields are `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType` and `predicate.runDetails.builder.id`. `resolvedDependencies` and `runDetails.metadata` fields `invocationId`, `startedOn`, `finishedOn` are used when present. Verify and extract DSSE envelopes externally before supplying Statement JSON.

### Physical manufacturing

Use `koda-manufacturing-1` with `--provenance`. Product/part IDs and part numbers identify physical items.

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

`observation` is `declared` for planned steps or `reported` for reported execution. Set `observedAt` to the record capture time. Supported actions are `assembly`, `inspection`, `test`, `packaging`. Up to 1,000 steps are linked in array order. Optional `startedOn`/`finishedOn` describe each step. `inputIds` must refer to `parts`. Products and parts may include `version`.

## Runnable source examples

The source repository includes small synthetic service/OpenAPI, model, SLSA and manufacturing fixtures in `internal/domainbom/testdata/`.

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

[Collection support](support-matrix.md) · [Asset inventory](asset-inventory.md)
