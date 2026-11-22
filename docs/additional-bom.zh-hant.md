# SaaSBOM、AI-BOM 和 MBOM 的補充證據

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
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


`domain-bom` 讀取本地證據和產物，生成 `saasbom.cdx.json`、`aibom.cdx.json` 和 `mbom.cdx.json`。`--cyclonedx-17` 增加1.7版本。`scan` 接受相同的證據選項。默認主機採集將7種獨立BOM保存到 `boms/`，合併結果為 `bom.cdx.json`。

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

記錄包含SHA-256、觀察範圍，以及信息是聲明還是報告。`koda:domain:authenticity` 將簽名真實性標記為未驗證。提供證據的 `compositions.aggregate=incomplete`。聲明與產物的哈希匹配時記錄 `artifact-binding=sha256-matched`。完整主機掃描中沒有證據的領域標記為 `no-evidence`，覆蓋範圍未知。

三個領域合計最多12個輸入。每份JSON證據上限16 MiB，每個列表最多10,000項。重復JSON鍵、URL用戶信息、查詢、片段和未解析的服務器模板會被拒絕。產物採用流式哈希，模型權重和可執行文件均不會執行。

## SaaSBOM

`--saas-evidence` 接受OpenAPI 3.x JSON或 `koda-services-1`。從OpenAPI讀取標題、版本、根/路徑/操作明確聲明的絕對服務器地址和操作認證聲明。默認相對地址的部署位置保持未知。存在匿名操作則 `authenticated=false`，全部已檢查操作要求認證則為 `true`，聲明不足時省略。正文示例、安全方案內容、描述和秘密值不輸出。[OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI也可以使用YAML。YAML只能包含一個文檔，拒絕重複鍵，數字保留原文（`version: 1.0` 保持為 `1.0`）。

主機採集還會讀取反向代理和負載均衡器配置：nginx `upstream`、`proxy_pass`、`grpc_pass`，Apache `ProxyPass`、`BalancerMember`，以及HAProxy `backend` 中的 `server`。每個後端記錄為帶有 `observation=declared-proxy-backend` 和聲明所在文件、行號的服務。只保留協議、主機和端口，丟棄路徑、查詢和憑據；使用變量的目標報告為未解析。後端是否可達由OBOM的外部連接確認，而非此聲明。Debian的 `*-available` 文件僅通過 `*-enabled` 鏈接生效，CBOM的TLS聲明也適用同一規則。

使用以下格式提供供應者、信任邊界、數據分類和服務依賴。

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

`id` 和 `name` 必填，其他示例字段及 `version` 可選。`dependsOn` 引用同一文件中的服務ID。`flow` 相對於服務，可為 `inbound`、`outbound`、`bi-directional`、`unknown`。認證、信任和調用關係依據輸入聲明。

## AI-BOM

指定目標服務器上的模型目錄。主機採集對允許的路徑執行相同檢查。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face的 `config.json` 提供架構、文本模型層數、注意力頭數、最大上下文和量化配置。權重索引提供聲明的張量數量和分片列表。
- safetensors和GGUF頭提供格式、張量數和可用元數據。模型與權重文件通過依賴關係連接。大型權重也只讀取有限頭部範圍，配置/索引/頭部哈希與完整文件哈希分別標記。
- Ollama清單連接模型層與可讀本地blob頭。模型服務器當前加載狀態需要運行時證據。
- `config.json` 旁的Hugging Face `README.md` 模型卡提供許可證、`base_model`、`datasets`、`pipeline_tag`、語言和庫。基礎模型和數據集作為聲明的組件與模型關聯。在Hugging Face緩存中，指向該快照的 `refs/main` 等ref記錄為 `cache-ref`。模型卡內容仍是發佈者聲明。
- ONNX文件提供IR版本、生成工具、模型版本和算子集。`ai.onnx`、`ai.onnx.ml` 以外的算子域需要原生自定義算子庫，因此列為 `onnx:custom-operator-domain`。
- PyTorch檢查點（`pytorch_model*.bin`、`.pt`、`.pth`、`.ckpt`，zip或舊格式）是加載時會執行其導入函數的pickle。KODA不執行文件，只遍歷pickle操作碼，並將 `pickle:safety` 記錄為 `allowlisted-imports-only`、`unknown-imports` 或 `dangerous-imports`，`os.system` 等危險導入列為 `pickle:dangerous-import`。無法遍歷到末尾的文件記為 `pickle:inspection=incomplete`，絕不判定為僅允許列表，並保留失敗前找到的導入；協議0/1 pickle和舊版 `torch.save` 文件的全部五個流也會檢查。非僅允許列表的文件建議改用safetensors。Hugging Face模型文件夾中的pickle和ONNX文件（如 `pytorch_model.bin`、`training_args.bin`、`optimizer.pt`）關聯到該模型，模型以 `artifact-pickle-safety` 記錄其中最不安全的結果。
- 在運行中的主機上，以模型路徑或倉庫ID啓動的vLLM、TGI、llama.cpp、SGLang、Triton或LMDeploy進程會使匹配的模型記錄 `runtime-state=referenced-by-running-process` 和 `serving-process`，OBOM進程帶有 `model-reference`。這基於啓動參數；按請求選擇模型的Ollama不做匹配。

### Linux 上的 Qwen 與 NVIDIA GPU

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

將 `/srv/models/Qwen` 替換為實際路徑。如果Hugging Face的 `snapshots/<revision>/` 通過符號鏈接指向 `blobs/`，請選擇包含兩者的 `models--organization--model` 目錄。容器bind mount應使用主機可見的實際存儲路徑。

| 證據 | 輸出 |
|---|---|
| 模型架構、上下文、精度、量化、分片和張量 | `boms/aibom.cdx.json` 的組件與依賴，取決於存儲格式和可用字段 |
| H100型號、PCI標識、驅動及固件 | `boms/hbom.cdx.json`，來自Linux PCI sysfs和NVIDIA驅動 |
| PyTorch、Transformers、vLLM、CUDA包版本 | 可讀取安裝元數據的主機或容器SBOM |
| 服務進程和監聽套接字 | 觀察到進程及可執行文件時的 `boms/obom.cdx.json` |

模型卡之外的訓練/評估數據和譜系需要來源聲明。當前GPU/VRAM使用、MIG分配和實際服務上下文需要另外的運行時觀察。

僅指定權重產物會記錄完整SHA-256及safetensors或GGUF v2/v3頭信息，並標記 `artifact-binding=sha256-calculated`。safetensors讀取dtype和數據範圍，GGUF讀取存在的 `general.name`、`general.architecture`、`general.file_type`。張量數據和模型計算需單獨驗證。[safetensors格式](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

使用 `koda-model-1` 聲明身份、修訂、許可證、來源、基礎模型和數據集。將示例 `sha256` 替換為實際產物的64位十六進制哈希，按順序配對每個聲明和 `--model-artifact`。聲明哈希匹配時也可以綁定其他模型文件格式。

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

模型類型為 `machine-learning-model`，數據集為 `data`。保留依賴及 `modelCard.modelParameters.datasets` 引用。每個基礎模型/數據集要求 `name`，可附加 `version`、`sha256`、`source`、`license`，這些內容作為供應者聲明記錄。單獨提供的主要產物哈希會直接驗證。

## MBOM

### 軟件構建來源

`--provenance` 接受包含SLSA provenance v1的in-toto Statement v1。用 `--provenance-artifact` 提供實際產物，必須恰有一個 `subject` 的SHA-256與其匹配。構建器、構建類型、輸入、調用ID和起止時間寫入 `formulation.workflows`，省略外部/內部參數原文。[SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

必填字段為 `_type=https://in-toto.io/Statement/v1`、`predicateType=https://slsa.dev/provenance/v1`、`subject[].name`、`subject[].digest.sha256`、`predicate.buildDefinition.buildType`、`predicate.runDetails.builder.id`。存在時讀取 `resolvedDependencies` 和 `runDetails.metadata` 中的 `invocationId`、`startedOn`、`finishedOn`。DSSE應在外部驗證並提取為Statement JSON後輸入。

### 實物製造記錄

通過 `--provenance` 提供 `koda-manufacturing-1`。產品/零件ID與零件編號識別實物。

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

計劃工序的 `observation` 為 `declared`，執行報告為 `reported`。`observedAt` 是記錄獲取時間。支持 `assembly`、`inspection`、`test`、`packaging`，最多1,000步驟按數組順序關聯。每步可包含 `startedOn` 和 `finishedOn`。`inputIds` 引用 `parts` 中的ID，產品/零件可提供 `version`。

## 可運行的源碼示例

源碼的 `internal/domainbom/testdata/` 包含小型合成服務/OpenAPI、模型、SLSA和製造測試樣本。

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

[採集支持範圍](support-matrix.zh-hant.md) · [資產清單](asset-inventory.zh-hant.md)
