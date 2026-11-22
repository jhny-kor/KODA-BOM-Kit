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

訓練/評估數據、許可證、上游修訂和譜系需要模型卡或來源聲明。當前GPU/VRAM使用、MIG分配和實際服務上下文需要另外的運行時觀察。

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
