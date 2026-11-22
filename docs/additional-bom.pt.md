# Evidências adicionais para SaaSBOM, AI-BOM e MBOM

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="additional-bom.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="additional-bom.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="additional-bom.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="additional-bom.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


`domain-bom` lê evidências e artefatos locais para gerar `saasbom.cdx.json`, `aibom.cdx.json` e `mbom.cdx.json`. `--cyclonedx-17` acrescenta arquivos 1.7. `scan` aceita as mesmas opções. A coleta do host grava sete BOMs em `boms/` e o documento combinado em `bom.cdx.json`.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

São registrados SHA-256, escopo e origem declarada ou relatada. A autenticidade da assinatura permanece não verificada em `koda:domain:authenticity`. As evidências fornecidas usam `compositions.aggregate=incomplete`. A correspondência entre declaração e artefato produz `artifact-binding=sha256-matched`. Domínios sem evidência na coleta completa recebem `no-evidence`, com cobertura desconhecida.

Limites dos três domínios combinados, 12 entradas, 16 MiB por JSON e 10.000 itens por lista. Chaves duplicadas, informações de usuário/consulta/fragmento em URL e modelos de servidor não resolvidos são rejeitados. Hashes são calculados em fluxo. Pesos e executáveis são inspecionados sem execução.

## SaaSBOM

`--saas-evidence` aceita OpenAPI 3.x JSON ou `koda-services-1`. OpenAPI fornece título, versão, servidores absolutos declarados na raiz/caminho/operação e autenticação por operação. A localização dos servidores relativos fica desconhecida. Operação anônima explícita define `authenticated=false`. Se todas as operações inspecionadas exigem autenticação, registra `true`. Declarações insuficientes deixam o campo ausente. Exemplos de corpo, conteúdo dos esquemas de segurança, descrições e segredos são omitidos. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

Use este formato para provedores, fronteiras de confiança, classificação e dependências.

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

`id` e `name` são obrigatórios. Os demais campos ilustrados e `version` são opcionais. `dependsOn` referencia serviços do mesmo arquivo. `flow` é `inbound`, `outbound`, `bi-directional` ou `unknown`, em relação ao serviço. Autenticação, confiança e chamadas refletem as declarações fornecidas.

## AI-BOM

Informe o diretório do modelo no servidor. A coleta do host aplica as mesmas verificações aos caminhos admitidos.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` fornece arquitetura, camadas, cabeças de atenção, contexto máximo e quantização. Índices fornecem contagem declarada de tensores e fragmentos de pesos.
- Cabeçalhos safetensors/GGUF fornecem formato, tensores e metadados. Modelos e arquivos se conectam por dependências. A leitura é limitada ao cabeçalho, mesmo em pesos grandes. Hashes de configuração/índice/cabeçalho são diferenciados do arquivo inteiro.
- Manifestos Ollama associam camadas aos cabeçalhos de blobs locais legíveis. O estado atual de carregamento requer evidência de execução.

### Qwen no Linux com GPUs NVIDIA

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Substitua `/srv/models/Qwen` pelo caminho real. Se `snapshots/<revision>/` aponta para `blobs/`, escolha o diretório superior `models--organization--model`. Em bind mounts de contêiner, use o caminho de armazenamento visível pelo host.

| Evidência | Resultado |
|---|---|
| Arquitetura, contexto, precisão, quantização, fragmentos e tensores | Componentes/dependências em `boms/aibom.cdx.json`, conforme formato e campos disponíveis |
| H100, IDs PCI, driver e firmware | `boms/hbom.cdx.json`, usando PCI sysfs e dados do driver NVIDIA |
| Versões PyTorch, Transformers, vLLM, CUDA | SBOM do host/contêiner quando os metadados instalados são legíveis |
| Processo de serviço e sockets de escuta | `boms/obom.cdx.json` se processo e executável forem observados |

Dados de treinamento/avaliação, licenças, revisão de origem e linhagem exigem cartões ou declarações do modelo. Uso GPU/VRAM, alocação MIG e contexto efetivo do serviço precisam de observações de execução.

Um artefato de pesos isolado registra SHA-256 completo e cabeçalhos safetensors ou GGUF v2/v3 com `artifact-binding=sha256-calculated`. safetensors fornece dtype e intervalos. GGUF pode fornecer `general.name`, `general.architecture`, `general.file_type`. Dados de tensores e cálculos precisam de validação adicional. [Formato safetensors](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

`koda-model-1` declara identidade, revisão, licença, fonte, modelos base e conjuntos de dados. Substitua `sha256` pelo hash real de 64 caracteres. Associe cada declaração a `--model-artifact` na mesma ordem. A declaração correspondente também pode vincular outros formatos.

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

Modelos usam `machine-learning-model`, dados usam `data`. Dependências e referências `modelCard.modelParameters.datasets` são mantidas. Cada modelo base/conjunto exige `name` e aceita `version`, `sha256`, `source`, `license`. Seus metadados são declarações do fornecedor. O hash do artefato principal fornecido é verificado diretamente.

## MBOM

### Proveniência de compilação

`--provenance` aceita in-toto Statement v1 com SLSA provenance v1. Forneça o produto em `--provenance-artifact`. Exatamente um `subject` deve corresponder ao SHA-256. Construtor, tipo, entradas, ID de execução e horários alimentam `formulation.workflows`. Parâmetros internos/externos brutos são omitidos. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Campos obrigatórios `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType`, `predicate.runDetails.builder.id`. `resolvedDependencies` e `runDetails.metadata` com `invocationId`, `startedOn`, `finishedOn` são usados quando presentes. Verifique e extraia envelopes DSSE externamente antes de informar Statement JSON.

### Fabricação física

Use `koda-manufacturing-1` com `--provenance`. IDs e números de peça identificam os itens físicos.

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

`observation` é `declared` para etapas planejadas ou `reported` para execução relatada. `observedAt` indica a captura do registro. Ações aceitas são `assembly`, `inspection`, `test`, `packaging`. Até 1.000 etapas são conectadas na ordem, com `startedOn`/`finishedOn` opcionais. `inputIds` referencia `parts`. Produtos e peças aceitam `version`.

## Exemplos executáveis no código-fonte

`internal/domainbom/testdata/` contém pequenas amostras sintéticas de serviços/OpenAPI, modelos, SLSA e fabricação.

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

[Escopo de coleta](support-matrix.pt.md) · [Inventário de ativos](asset-inventory.pt.md)
