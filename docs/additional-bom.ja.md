# SaaSBOM・AI-BOM・MBOMの追加証拠

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <strong>日本語</strong>
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


`domain-bom` はローカルの証拠と成果物を読み、`saasbom.cdx.json`、`aibom.cdx.json`、`mbom.cdx.json` を生成します。`--cyclonedx-17` で1.7版を追加します。`scan` も同じ証拠オプションを受け付けます。通常のホスト収集では7種の個別BOMを `boms/`、統合文書を `bom.cdx.json` に保存します。

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

SHA-256、観測範囲、宣言情報か報告情報かを記録します。署名の真正性は `koda:domain:authenticity` で未検証と表示します。提供された証拠の `compositions.aggregate` は `incomplete` です。宣言と成果物のハッシュが一致すれば `artifact-binding=sha256-matched` になります。ホスト収集で証拠のない領域は `no-evidence`、範囲は不明と記録します。

3領域合計で最大12入力、JSON証拠は1ファイル16 MiB、リストは10,000項目です。重複JSONキー、URLのユーザー情報・クエリ・フラグメント、未解決のサーバーテンプレートは拒否します。成果物はストリーミングでハッシュ化し、モデルの重みや実行ファイルは実行しません。

## SaaSBOM

`--saas-evidence` は OpenAPI 3.x JSON または `koda-services-1` を受け付けます。OpenAPIからタイトル、バージョン、ルート・パス・操作で明示された絶対サーバーURL、操作ごとの認証宣言を読みます。既定の相対URLの配置先は不明です。匿名操作があれば `authenticated=false`、調査した全操作が認証を要求すれば `true`、宣言不足なら省略します。本文例、セキュリティスキームの内容、説明、秘密情報は出力しません。[OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPIはYAMLでも指定できます。YAMLは1文書のみで、重複キーは拒否し、数値は記載どおり保持します（`version: 1.0` は `1.0` のまま）。

ホスト収集ではリバースプロキシとロードバランサーの設定も読みます。対象はnginxの `upstream`・`proxy_pass`・`grpc_pass`、Apacheの `ProxyPass`・`BalancerMember`、HAProxyの `backend` 内の `server` です。各バックエンドは `observation=declared-proxy-backend` と、宣言したファイル・行を持つサービスとして記録します。スキーム・ホスト・ポートのみを残し、パス・クエリ・認証情報は破棄し、変数を使う宛先は未解決として報告します。到達できるかどうかは、この宣言ではなくOBOMの外部接続で確認します。Debianの `*-available` ファイルは `*-enabled` のリンク経由でのみ反映し、CBOMのTLS宣言にも同じ規則を適用します。ディレクトリ収集でそのリンクをたどれない場合はファイルをそのまま読み、有効かどうか未確認である旨をissueに残します。

提供者、信頼境界、データ分類、サービス依存関係には次の形式を使用します。

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

`id` と `name` は必須です。他の例示フィールドと `version` は任意です。`dependsOn` は同じファイルのサービスIDを参照します。データの `flow` はサービスから見た `inbound`、`outbound`、`bi-directional`、`unknown` です。認証、信頼、呼び出し関係は提供された宣言に基づきます。

## AI-BOM

対象サーバーのモデルディレクトリを指定します。ホスト収集でも許可されたパスに同じ検査を適用します。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Faceの `config.json` からアーキテクチャ、層数、アテンションヘッド数、最大コンテキスト、量子化を読みます。重みインデックスは宣言されたテンソル数とシャード一覧を提供します。
- safetensors・GGUFヘッダーから形式、テンソル数、取得可能なメタデータを読み、モデルと重みファイルを依存関係で結びます。大きなファイルでも限定範囲のヘッダーを読みます。設定・インデックス・ヘッダーのハッシュと全体ハッシュは区別します。
- Ollamaマニフェストからモデルレイヤーと読めるローカルblobヘッダーを結びます。現在のロード状態には実行時の証拠が必要です。
- `config.json` と同じ場所にあるHugging Faceの `README.md` モデルカードから、ライセンス、`base_model`、`datasets`、`pipeline_tag`、言語、ライブラリを読みます。ベースモデルとデータセットは宣言された構成要素としてモデルに結びます。Hugging Faceキャッシュでは、スナップショットを指す `refs/main` などのrefを `cache-ref` として記録します。モデルカードの値は公開者の宣言です。
- ONNXファイルからIRバージョン、生成ツール、モデルバージョン、演算子セットを読みます。`ai.onnx`・`ai.onnx.ml` 以外の演算子ドメインはネイティブのカスタム演算子ライブラリが必要なため、`onnx:custom-operator-domain` として示します。
- PyTorchチェックポイント（`pytorch_model*.bin`、`.pt`、`.pth`、`.ckpt`、zip形式または旧形式）は、読み込み時にimportした関数を実行するpickleです。KODAは実行せずにpickleのopcodeだけを走査し、`pickle:safety` を `allowlisted-imports-only`、`unknown-imports`、`dangerous-imports` のいずれかで記録し、`os.system` などの危険なimportを `pickle:dangerous-import` として列挙します。最後まで走査できないファイルは `pickle:inspection=incomplete` とし、許可リストのみとは判定せず、それまでに見つけたimportは保持します。プロトコル0/1のpickleと旧形式 `torch.save` の5ストリームもすべて検査します。許可リストのみでないファイルにはsafetensorsを推奨します。Hugging Faceのモデルフォルダー内のpickle・ONNXファイル（`pytorch_model.bin`、`training_args.bin`、`optimizer.pt` など）はそのモデルに結び、最も危険な結果をモデルの `artifact-pickle-safety` として記録します。検査できないファイルがあれば、モデルを少なくとも `unknown-imports` とし、`artifact-inspection-status=incomplete` を記録します。
- 稼働中のホストで、vLLM・TGI・llama.cpp・SGLang・Triton・LMDeployのプロセスがモデルパスまたはリポジトリIDを指定して起動されていれば、一致するモデルに `runtime-state=referenced-by-running-process` と `serving-process` を記録し、OBOMのプロセスに `model-reference` を残します。起動引数に基づく判定で、リクエストごとにモデルを選ぶOllamaは対象外です。

### NVIDIA GPUを搭載したLinuxのQwen

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

`/srv/models/Qwen` を実際のパスに置き換えます。Hugging Faceの `snapshots/<revision>/` が `blobs/` を参照する場合、両方を含む `models--organization--model` を指定します。コンテナーのbind mountではホストから見える保存先を使います。

| 証拠 | 出力 |
|---|---|
| モデル構造、コンテキスト、精度、量子化、シャード、テンソル | `boms/aibom.cdx.json` の構成要素と依存関係。保存形式とフィールドによって取得内容が変わります |
| H100製品名、PCI識別子、ドライバー、ファームウェア | Linux PCI sysfsとNVIDIAドライバー情報を使う `boms/hbom.cdx.json` |
| PyTorch・Transformers・vLLM・CUDAのパッケージ版 | インストールメタデータを読めるホストまたはコンテナーのSBOM |
| サービングプロセスと待受ソケット | プロセスと実行ファイルを観測できた場合の `boms/obom.cdx.json` |

モデルカードにない学習・評価データと系譜には出所宣言が必要です。現在のGPU/VRAM使用量、MIG割当、実際のサービングコンテキストには別の実行時観測が必要です。

重みだけを指定すると、全体SHA-256とsafetensorsまたはGGUF v2/v3ヘッダー情報を `artifact-binding=sha256-calculated` として記録します。safetensorsではdtypeとデータ範囲、GGUFでは存在する `general.name`、`general.architecture`、`general.file_type` を読みます。テンソル内容とモデル計算は別途検証が必要です。[safetensors形式](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

識別子、リビジョン、ライセンス、出所、基盤モデル、データセットは `koda-model-1` で宣言します。例の `sha256` は実際の64桁ハッシュに置き換え、各宣言と `--model-artifact` を順番に対応させます。ハッシュが一致すれば他のモデル形式も結び付けられます。

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

モデルは `machine-learning-model`、データセットは `data` です。依存関係と `modelCard.modelParameters.datasets` の参照を保持します。基盤モデル・データセットは `name` が必須で、`version`、`sha256`、`source`、`license` は任意です。これらは供給者の宣言として記録し、指定した主成果物のハッシュを直接検証します。

## MBOM

### ソフトウェアのビルド証拠

`--provenance` はSLSA provenance v1を含むin-toto Statement v1です。実成果物を `--provenance-artifact` で指定し、`subject` のちょうど1件とSHA-256が一致する必要があります。ビルダー、ビルド種別、入力、実行ID、開始・終了時刻を `formulation.workflows` に記録します。外部・内部パラメーターの原文は省略します。[SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

必須項目は `_type=https://in-toto.io/Statement/v1`、`predicateType=https://slsa.dev/provenance/v1`、`subject[].name`、`subject[].digest.sha256`、`predicate.buildDefinition.buildType`、`predicate.runDetails.builder.id` です。`resolvedDependencies` と `runDetails.metadata` の `invocationId`、`startedOn`、`finishedOn` は存在すれば使います。DSSEは外部で検証・展開したStatement JSONを指定します。

### 物理製品の製造記録

`--provenance` に `koda-manufacturing-1` を指定します。製品・部品IDと部品番号で対象を識別します。

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

`observation` は計画工程が `declared`、実行報告が `reported` です。`observedAt` は記録取得時刻です。`assembly`、`inspection`、`test`、`packaging` に対応し、最大1,000工程を配列順に結びます。各工程に `startedOn`・`finishedOn` を追加できます。`inputIds` は `parts` のIDを参照し、製品・部品には `version` も指定できます。

## 実行可能なソース例

ソースの `internal/domainbom/testdata/` にサービス/OpenAPI、モデル、SLSA、製造工程の小さな合成テストデータがあります。

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

[収集範囲](support-matrix.ja.md) · [資産インベントリ](asset-inventory.ja.md)
