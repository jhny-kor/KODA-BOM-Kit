# SaaSBOM、AI-BOM 和 MBOM 的补充证据

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <strong>简体中文</strong>
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


`domain-bom` 读取本地证据和产物，生成 `saasbom.cdx.json`、`aibom.cdx.json` 和 `mbom.cdx.json`。`--cyclonedx-17` 增加1.7版本。`scan` 接受相同的证据选项。默认主机采集将7种独立BOM保存到 `boms/`，合并结果为 `bom.cdx.json`。

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

记录包含SHA-256、观察范围，以及信息是声明还是报告。`koda:domain:authenticity` 将签名真实性标记为未验证。提供证据的 `compositions.aggregate=incomplete`。声明与产物的哈希匹配时记录 `artifact-binding=sha256-matched`。完整主机扫描中没有证据的领域标记为 `no-evidence`，覆盖范围未知。

三个领域合计最多12个输入。每份JSON证据上限16 MiB，每个列表最多10,000项。重复JSON键、URL用户信息、查询、片段和未解析的服务器模板会被拒绝。产物采用流式哈希，模型权重和可执行文件均不会执行。

## SaaSBOM

`--saas-evidence` 接受OpenAPI 3.x JSON或 `koda-services-1`。从OpenAPI读取标题、版本、根/路径/操作明确声明的绝对服务器地址和操作认证声明。默认相对地址的部署位置保持未知。存在匿名操作则 `authenticated=false`，全部已检查操作要求认证则为 `true`，声明不足时省略。正文示例、安全方案内容、描述和秘密值不输出。[OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI也可以使用YAML。YAML只能包含一个文档，拒绝重复键，数字保留原文（`version: 1.0` 保持为 `1.0`）。

主机采集还会读取反向代理和负载均衡器配置：nginx `upstream`、`proxy_pass`、`grpc_pass`，Apache `ProxyPass`、`BalancerMember`，以及HAProxy `backend` 中的 `server`。每个后端记录为带有 `observation=declared-proxy-backend` 和声明所在文件、行号的服务。只保留协议、主机和端口，丢弃路径、查询和凭据；使用变量的目标报告为未解析。后端是否可达由OBOM的外部连接确认，而非此声明。Debian的 `*-available` 文件仅通过 `*-enabled` 链接生效，CBOM的TLS声明也适用同一规则。目录扫描无法跟随这些链接时，仍读取文件，并以问题记录其启用状态未确定。

使用以下格式提供供应者、信任边界、数据分类和服务依赖。

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

`id` 和 `name` 必填，其他示例字段及 `version` 可选。`dependsOn` 引用同一文件中的服务ID。`flow` 相对于服务，可为 `inbound`、`outbound`、`bi-directional`、`unknown`。认证、信任和调用关系依据输入声明。

## AI-BOM

指定目标服务器上的模型目录。主机采集对允许的路径执行相同检查。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face的 `config.json` 提供架构、文本模型层数、注意力头数、最大上下文和量化配置。权重索引提供声明的张量数量和分片列表。
- safetensors和GGUF头提供格式、张量数和可用元数据。模型与权重文件通过依赖关系连接。大型权重也只读取有限头部范围，配置/索引/头部哈希与完整文件哈希分别标记。
- Ollama清单连接模型层与可读本地blob头。模型服务器当前加载状态需要运行时证据。
- `config.json` 旁的Hugging Face `README.md` 模型卡提供许可证、`base_model`、`datasets`、`pipeline_tag`、语言和库。基础模型和数据集作为声明的组件与模型关联。在Hugging Face缓存中，指向该快照的 `refs/main` 等ref记录为 `cache-ref`。模型卡内容仍是发布者声明。
- ONNX文件提供IR版本、生成工具、模型版本和算子集。`ai.onnx`、`ai.onnx.ml` 以外的算子域需要原生自定义算子库，因此列为 `onnx:custom-operator-domain`。
- PyTorch检查点（`pytorch_model*.bin`、`.pt`、`.pth`、`.ckpt`，zip或旧格式）是加载时会执行其导入函数的pickle。KODA不执行文件，只遍历pickle操作码，并将 `pickle:safety` 记录为 `allowlisted-imports-only`、`unknown-imports` 或 `dangerous-imports`，`os.system` 等危险导入列为 `pickle:dangerous-import`。无法遍历到末尾的文件记为 `pickle:inspection=incomplete`，绝不判定为仅允许列表，并保留失败前找到的导入；协议0/1 pickle和旧版 `torch.save` 文件的全部五个流也会检查。非仅允许列表的文件建议改用safetensors。Hugging Face模型文件夹中的pickle和ONNX文件（如 `pytorch_model.bin`、`training_args.bin`、`optimizer.pt`）关联到该模型，模型以 `artifact-pickle-safety` 记录其中最不安全的结果。若有文件无法检查，模型至少标记为 `unknown-imports`，并记录 `artifact-inspection-status=incomplete`。
- 在运行中的主机上，以模型路径或仓库ID启动的vLLM、TGI、llama.cpp、SGLang、Triton或LMDeploy进程会使匹配的模型记录 `runtime-state=referenced-by-running-process` 和 `serving-process`，OBOM进程带有 `model-reference`。这基于启动参数；按请求选择模型的Ollama不做匹配。

### Linux 上的 Qwen 与 NVIDIA GPU

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

将 `/srv/models/Qwen` 替换为实际路径。如果Hugging Face的 `snapshots/<revision>/` 通过符号链接指向 `blobs/`，请选择包含两者的 `models--organization--model` 目录。容器bind mount应使用主机可见的实际存储路径。

| 证据 | 输出 |
|---|---|
| 模型架构、上下文、精度、量化、分片和张量 | `boms/aibom.cdx.json` 的组件与依赖，取决于存储格式和可用字段 |
| H100型号、PCI标识、驱动及固件 | `boms/hbom.cdx.json`，来自Linux PCI sysfs和NVIDIA驱动 |
| PyTorch、Transformers、vLLM、CUDA包版本 | 可读取安装元数据的主机或容器SBOM |
| 服务进程和监听套接字 | 观察到进程及可执行文件时的 `boms/obom.cdx.json` |

模型卡之外的训练/评估数据和谱系需要来源声明。当前GPU/VRAM使用、MIG分配和实际服务上下文需要另外的运行时观察。

仅指定权重产物会记录完整SHA-256及safetensors或GGUF v2/v3头信息，并标记 `artifact-binding=sha256-calculated`。safetensors读取dtype和数据范围，GGUF读取存在的 `general.name`、`general.architecture`、`general.file_type`。张量数据和模型计算需单独验证。[safetensors格式](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

使用 `koda-model-1` 声明身份、修订、许可证、来源、基础模型和数据集。将示例 `sha256` 替换为实际产物的64位十六进制哈希，按顺序配对每个声明和 `--model-artifact`。声明哈希匹配时也可以绑定其他模型文件格式。

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

模型类型为 `machine-learning-model`，数据集为 `data`。保留依赖及 `modelCard.modelParameters.datasets` 引用。每个基础模型/数据集要求 `name`，可附加 `version`、`sha256`、`source`、`license`，这些内容作为供应者声明记录。单独提供的主要产物哈希会直接验证。

## MBOM

### 软件构建来源

`--provenance` 接受包含SLSA provenance v1的in-toto Statement v1。用 `--provenance-artifact` 提供实际产物，必须恰有一个 `subject` 的SHA-256与其匹配。构建器、构建类型、输入、调用ID和起止时间写入 `formulation.workflows`，省略外部/内部参数原文。[SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

必填字段为 `_type=https://in-toto.io/Statement/v1`、`predicateType=https://slsa.dev/provenance/v1`、`subject[].name`、`subject[].digest.sha256`、`predicate.buildDefinition.buildType`、`predicate.runDetails.builder.id`。存在时读取 `resolvedDependencies` 和 `runDetails.metadata` 中的 `invocationId`、`startedOn`、`finishedOn`。DSSE应在外部验证并提取为Statement JSON后输入。

### 实物制造记录

通过 `--provenance` 提供 `koda-manufacturing-1`。产品/零件ID与零件编号识别实物。

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

计划工序的 `observation` 为 `declared`，执行报告为 `reported`。`observedAt` 是记录获取时间。支持 `assembly`、`inspection`、`test`、`packaging`，最多1,000步骤按数组顺序关联。每步可包含 `startedOn` 和 `finishedOn`。`inputIds` 引用 `parts` 中的ID，产品/零件可提供 `version`。

## 可运行的源码示例

源码的 `internal/domainbom/testdata/` 包含小型合成服务/OpenAPI、模型、SLSA和制造测试样本。

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

[采集支持范围](support-matrix.zh.md) · [资产清单](asset-inventory.zh.md)
