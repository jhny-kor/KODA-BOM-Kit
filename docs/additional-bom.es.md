# Evidencias adicionales para SaaSBOM, AI-BOM y MBOM

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <strong>Español</strong>
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


`domain-bom` lee evidencias y artefactos locales para generar `saasbom.cdx.json`, `aibom.cdx.json` y `mbom.cdx.json`. `--cyclonedx-17` añade archivos 1.7. `scan` acepta las mismas opciones. La recopilación del host guarda siete BOM individuales en `boms/` y el documento combinado en `bom.cdx.json`.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

Se registran SHA-256, alcance y origen declarado o comunicado de los datos. La autenticidad de la firma queda sin verificar en `koda:domain:authenticity`. Las evidencias aportadas usan `compositions.aggregate=incomplete`. La coincidencia entre declaración y artefacto produce `artifact-binding=sha256-matched`. Un dominio sin evidencia durante el análisis completo se marca `no-evidence`, con cobertura desconocida.

Se admiten 12 entradas entre los tres dominios, 16 MiB por JSON y 10.000 elementos por lista. Se rechazan claves JSON duplicadas, credenciales, consultas y fragmentos en URL y plantillas de servidor sin resolver. Los hashes se calculan en flujo. Los pesos y ejecutables se inspeccionan sin ejecutarlos.

## SaaSBOM

`--saas-evidence` acepta OpenAPI 3.x JSON o `koda-services-1`. OpenAPI aporta título, versión, servidores absolutos de raíz/ruta/operación y declaraciones de autenticación. La ubicación de servidores relativos queda desconocida. Una operación anónima explícita establece `authenticated=false`. Si todas las operaciones inspeccionadas exigen autenticación, se registra `true`. Si faltan declaraciones, se omite el campo. Se excluyen ejemplos de cuerpos, contenidos de esquemas de seguridad, descripciones y secretos. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI también puede ser YAML. El YAML debe contener un solo documento; se rechazan las claves duplicadas y los números conservan su texto literal, de modo que `version: 1.0` queda como `1.0`.

La recopilación del host también lee la configuración de proxies inversos y balanceadores: `upstream`, `proxy_pass` y `grpc_pass` de nginx, `ProxyPass` y `BalancerMember` de Apache, y los `server` de cada `backend` de HAProxy. Cada backend se registra como servicio con `observation=declared-proxy-backend` y el archivo y la línea que lo declaran. Solo se conservan esquema, host y puerto; se descartan rutas, consultas y credenciales, y los destinos con variables se informan como no resueltos. Si un backend es alcanzable lo indican las conexiones salientes del OBOM, no esta declaración. Los archivos `*-available` de Debian solo cuentan a través de sus enlaces `*-enabled`, también para las declaraciones TLS del CBOM. Si un escaneo de directorio no puede seguir esos enlaces, los archivos se leen igualmente y una incidencia indica que su activación no está resuelta.

Este formato permite proveedores, límites de confianza, clasificación de datos y dependencias.

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

`id` y `name` son obligatorios. Los demás campos ilustrados y `version` son opcionales. `dependsOn` referencia servicios del mismo archivo. `flow` usa `inbound`, `outbound`, `bi-directional` o `unknown`, respecto al servicio. Autenticación, confianza y llamadas reflejan las declaraciones proporcionadas.

## AI-BOM

Indique el directorio del modelo en el servidor. La recopilación del host aplica estas comprobaciones a las rutas admitidas.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` aporta arquitectura, capas, cabezas de atención, contexto máximo y cuantización. Los índices aportan cantidades de tensores declaradas y fragmentos de pesos.
- Los encabezados safetensors/GGUF aportan formato, tensores y metadatos. Los modelos y archivos se enlazan mediante dependencias. Se leen encabezados acotados incluso para pesos grandes. Los hashes de configuración, índices y encabezados se distinguen del hash completo.
- Los manifiestos Ollama vinculan capas con encabezados de blobs locales legibles. Confirmar la carga actual del servidor requiere evidencia de ejecución.
- Una tarjeta de modelo `README.md` de Hugging Face junto a `config.json` aporta licencia, `base_model`, `datasets`, `pipeline_tag`, idioma y biblioteca. Los modelos base y los conjuntos de datos se convierten en componentes declarados vinculados al modelo. En una caché de Hugging Face, `refs/main` y otras refs que apuntan a la instantánea se registran como `cache-ref`. Los campos de la tarjeta siguen siendo declaraciones del publicador.
- Los archivos ONNX informan versión IR, productor, versión del modelo y conjuntos de operadores. Los dominios de operadores distintos de `ai.onnx` y `ai.onnx.ml` se listan como `onnx:custom-operator-domain`, porque requieren una biblioteca nativa de operadores personalizados.
- Los puntos de control de PyTorch (`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt`, zip o heredados) son pickles que ejecutan al cargarse las funciones que importan. KODA recorre los opcodes de pickle sin ejecutarlos y registra `pickle:safety`: `allowlisted-imports-only`, `unknown-imports` o `dangerous-imports`, con cada `pickle:dangerous-import`, como `os.system`. Un archivo que el escáner no puede recorrer hasta el final se informa con `pickle:inspection=incomplete` y nunca como solo permitido; se conservan las importaciones halladas antes del fallo. También se revisan los pickles de protocolo 0/1 y los cinco flujos de un archivo `torch.save` heredado. Prefiera safetensors para cualquier archivo que no sea solo permitido. Los archivos pickle y ONNX de una carpeta de modelo de Hugging Face, como `pytorch_model.bin`, `training_args.bin` u `optimizer.pt`, se vinculan a ese modelo, que informa el resultado menos seguro como `artifact-pickle-safety`. Un archivo que no se puede inspeccionar eleva el modelo al menos a `unknown-imports`, con `artifact-inspection-status=incomplete`.
- En un host en ejecución, un proceso vLLM, TGI, llama.cpp, SGLang, Triton o LMDeploy iniciado con una ruta de modelo o un ID de repositorio marca el modelo coincidente con `runtime-state=referenced-by-running-process` y `serving-process`, y el proceso del OBOM lleva `model-reference`. Refleja los argumentos de inicio; Ollama elige el modelo en cada solicitud y no se vincula.

### Qwen en Linux con GPU NVIDIA

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Sustituya `/srv/models/Qwen` por la ruta real. Si `snapshots/<revision>/` enlaza a `blobs/`, seleccione el directorio superior `models--organization--model`. Para montajes de contenedores, use la ruta de almacenamiento visible desde el host.

| Evidencia | Resultado |
|---|---|
| Arquitectura, contexto, precisión, cuantización, fragmentos y tensores | Componentes y dependencias de `boms/aibom.cdx.json`, según formato y campos disponibles |
| Modelo H100, identificadores PCI, controlador y firmware | `boms/hbom.cdx.json`, mediante PCI sysfs y datos del controlador NVIDIA |
| Versiones PyTorch, Transformers, vLLM y CUDA | SBOM del host/contenedor cuando se pueden leer los metadatos instalados |
| Proceso de servicio y sockets de escucha | `boms/obom.cdx.json` si se observan proceso y ejecutable |

Los datos de entrenamiento/evaluación y el linaje que no figuran en la tarjeta del modelo requieren declaraciones de procedencia. Uso GPU/VRAM, asignación MIG y contexto real del servicio necesitan observaciones de ejecución.

Un archivo de pesos independiente registra SHA-256 completo y encabezados safetensors o GGUF v2/v3 con `artifact-binding=sha256-calculated`. safetensors aporta dtype y rangos. GGUF puede aportar `general.name`, `general.architecture`, `general.file_type`. Los datos de tensores y cálculos requieren validación adicional. [Formato safetensors](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

`koda-model-1` declara identidad, revisión, licencia, fuente, modelos base y conjuntos de datos. Sustituya `sha256` por el hash real de 64 caracteres. Empareje cada declaración y `--model-artifact` en orden. Una declaración coincidente también vincula otros formatos.

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

Los modelos son `machine-learning-model` y los datos `data`. Se conservan dependencias y referencias `modelCard.modelParameters.datasets`. Cada modelo base/conjunto requiere `name` y admite `version`, `sha256`, `source`, `license`. Sus metadatos se consideran declaraciones del proveedor. El hash del artefacto principal se verifica directamente.

## MBOM

### Procedencia de compilación

`--provenance` acepta in-toto Statement v1 con SLSA provenance v1. Aporte el producto mediante `--provenance-artifact`. Exactamente un `subject` debe coincidir en SHA-256. Constructor, tipo, entradas, ID de ejecución y horas pasan a `formulation.workflows`. Se omiten parámetros internos/externos originales. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Son obligatorios `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType`, `predicate.runDetails.builder.id`. Se usan `resolvedDependencies` y `runDetails.metadata` con `invocationId`, `startedOn`, `finishedOn` si existen. Verifique y extraiga los sobres DSSE externamente antes de proporcionar el Statement JSON.

### Fabricación física

Use `koda-manufacturing-1` con `--provenance`. IDs y números de pieza identifican productos y componentes.

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

`observation` es `declared` para pasos planificados o `reported` para ejecución comunicada. `observedAt` indica cuándo se obtuvo el registro. Acciones admitidas son `assembly`, `inspection`, `test`, `packaging`. Hasta 1.000 pasos se enlazan en orden. Admiten `startedOn`/`finishedOn`. `inputIds` referencia `parts`. Productos y piezas pueden tener `version`.

## Ejemplos ejecutables del repositorio

`internal/domainbom/testdata/` contiene pequeñas muestras sintéticas de servicios/OpenAPI, modelos, SLSA y fabricación.

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

[Alcance de recopilación](support-matrix.es.md) · [Inventario de activos](asset-inventory.es.md)
