# SaaSBOM·AI-BOM·MBOM 보강 자료

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
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


`domain-bom`은 지정한 로컬 증적과 산출물을 읽어 `saasbom.cdx.json`, `aibom.cdx.json`, `mbom.cdx.json`을 생성합니다. `--cyclonedx-17`을 지정하면 각 문서의 1.7 파일도 만듭니다. 증적과 산출물의 SHA-256, 관측 범위, 선언 또는 보고된 정보라는 구분을 함께 기록합니다. `scan`에도 같은 증적 옵션을 전달할 수 있습니다.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

서명 진위는 `koda:domain:authenticity`와 관련 속성에서 미검증으로 표시합니다. 각 결과의 `compositions.aggregate`는 `incomplete`이며, 입력 자료가 제공한 범위를 표현합니다. 선언의 해시와 실제 산출물 해시가 일치하면 `artifact-binding=sha256-matched`를 기록합니다.

한 번에 세 종류 합계 12개 입력을 받습니다. JSON 증적 한 파일은 16 MiB, 개별 목록은 최대 10,000개로 제한하며 중복 JSON 키를 거부합니다. 모델과 빌드 산출물은 스트리밍으로 해시를 계산합니다. URL의 사용자정보·쿼리·fragment와 미해결 서버 템플릿은 거부합니다. 모델 가중치와 실행 파일을 실행하는 단계는 없습니다.

## SaaSBOM

`--saas-evidence`는 OpenAPI 3.x JSON·YAML 또는 `koda-services-1`을 받습니다. YAML은 문서 하나여야 하며 중복 키는 거부합니다. 숫자는 적힌 그대로 유지하므로 `version: 1.0`은 `1.0`으로 기록됩니다. OpenAPI에서는 제목·버전, 명시된 절대 서버 주소와 작업별 인증 선언을 읽습니다. 루트·경로·작업에 선언된 서버 주소를 모으며 기본 상대 주소의 배포 위치는 미확인으로 남깁니다. 익명 접근을 명시한 작업이 있으면 `authenticated=false`, 확인한 작업 전부에 인증 요구가 있으면 `true`를 기록합니다. 작업별 선언이 충분하지 않으면 이 필드를 생략합니다. 본문 예시, 보안 스킴 내용, 설명, 비밀 값은 출력 대상에 포함하지 않습니다. [OpenAPI 3.1 명세](https://spec.openapis.org/oas/v3.1.1.html)

호스트 수집에서는 리버스 프록시·로드밸런서 설정도 읽습니다. nginx `upstream`·`proxy_pass`·`grpc_pass`, Apache `ProxyPass`·`BalancerMember`, HAProxy `backend`의 `server`가 대상입니다. 각 백엔드는 `observation=declared-proxy-backend`와 선언된 파일·줄 번호를 가진 서비스로 기록됩니다. 스킴·호스트·포트만 남기고 경로·쿼리·인증 정보는 버리며, 변수를 쓴 대상은 미해결로 표시합니다. 실제 접속 여부는 이 선언이 아니라 OBOM의 외부 연결에서 확인합니다. Debian의 `*-available` 파일은 `*-enabled` 링크를 통해서만 반영하며, CBOM의 TLS 선언에도 같은 규칙을 적용합니다. 디렉터리 수집에서 그 링크를 따라갈 수 없으면 파일을 그대로 읽고, 활성화 여부를 확인하지 못했다는 이슈를 남깁니다.

서비스 제공자·신뢰 경계·데이터 분류·서비스 간 의존관계를 함께 입력하려면 다음 형식을 사용합니다.

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

`id`와 `name`은 필수입니다. `version`, `provider`, `endpoints`, `authenticated`, `trustBoundary`, `trustZone`, `data`, `dependsOn`은 선택 항목입니다. `dependsOn`의 ID는 같은 파일의 서비스여야 합니다. 데이터의 `flow`는 `inbound`, `outbound`, `bi-directional`, `unknown` 중 하나이며 서비스 기준의 방향입니다. 인증·신뢰 경계·실제 호출 관계는 공급한 선언에 근거합니다.

## AI-BOM

설치된 모델 하나를 확인하려면 모델 파일이 있는 로컬 디렉터리를 지정합니다. 전체 호스트 수집에서도 허용된 파일에 같은 검사를 적용합니다.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face 형식의 `config.json`에서 아키텍처, 텍스트 모델의 층·어텐션 헤드 수, 최대 컨텍스트, 양자화 설정을 읽습니다. 가중치 인덱스가 있으면 선언된 텐서 수와 샤드 목록을 확인합니다.
- safetensors·GGUF 헤더로 형식과 텐서 수를 확인하고 파일 크기와 함께 기록합니다. 모델과 확인한 가중치 파일은 의존 관계로 연결합니다. 큰 가중치도 지정된 범위의 헤더만 읽으며, 자동 탐색에서 기록하는 설정·인덱스·헤더 해시는 파일 전체의 해시와 구분됩니다.
- Ollama 저장소에서는 매니페스트의 모델 레이어와 읽을 수 있는 로컬 blob 헤더를 연결합니다. 파일로 확인 가능한 정보와 모델 서버의 현재 로딩 상태는 각각 다른 증거가 필요합니다.
- `config.json` 옆의 Hugging Face `README.md` 모델 카드에서 라이선스, `base_model`, `datasets`, `pipeline_tag`, 언어, 라이브러리를 읽습니다. 기반 모델과 데이터셋은 선언된 구성요소로 만들어 모델과 연결합니다. Hugging Face 캐시에서는 해당 스냅숏을 가리키는 `refs/main` 등의 ref를 `cache-ref`로 기록합니다. 모델 카드 값은 게시자의 선언입니다.
- ONNX 파일에서는 IR 버전, 생성 도구, 모델 버전, 연산자 집합을 읽습니다. `ai.onnx`·`ai.onnx.ml` 이외의 연산자 도메인은 네이티브 사용자 정의 연산자 라이브러리가 필요하므로 `onnx:custom-operator-domain`으로 표시합니다.
- PyTorch 체크포인트(`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt`, zip 또는 구형식)는 로드할 때 import한 함수를 실행하는 pickle입니다. KODA는 실행하지 않고 pickle opcode만 읽어 `pickle:safety`를 `allowlisted-imports-only`, `unknown-imports`, `dangerous-imports` 중 하나로 기록하고, `os.system` 같은 위험 import는 `pickle:dangerous-import`로 나열합니다. 끝까지 해석하지 못한 파일은 `pickle:inspection=incomplete`로 표시하고 허용 목록 전용으로 판정하지 않으며, 그 전까지 찾은 import는 유지합니다. 프로토콜 0/1 pickle과 구형 `torch.save` 파일의 스트림 5개를 모두 검사합니다. 허용 목록만 쓰는 파일이 아니면 safetensors 사용을 권장합니다. Hugging Face 모델 폴더 안의 pickle·ONNX 파일(`pytorch_model.bin`, `training_args.bin`, `optimizer.pt` 등)은 그 모델에 연결하고, 가장 위험한 결과를 모델의 `artifact-pickle-safety`로 기록합니다. 검사하지 못한 파일이 있으면 모델을 최소 `unknown-imports`로 표시하고 `artifact-inspection=incomplete`를 기록합니다.
- 실행 중인 호스트에서 vLLM·TGI·llama.cpp·SGLang·Triton·LMDeploy 프로세스가 모델 경로나 저장소 ID로 시작됐으면, 일치하는 모델에 `runtime-state=referenced-by-running-process`와 `serving-process`를 기록하고 OBOM 프로세스에는 `model-reference`를 남깁니다. 시작 인자 기준이며, 요청마다 모델을 고르는 Ollama는 연결하지 않습니다.
- 공급자, 모델 계보, 학습 데이터와 라이선스를 추가하려면 아래의 모델 명세 및 대응 산출물을 지정합니다.

### Linux에서 Qwen과 NVIDIA GPU를 함께 확인하는 방법

```sh
# 호스트의 모델, 설치 패키지, GPU, 운영 상태를 같은 수집 회차에 저장
sudo ./koda-bom --output-dir ./koda-results

# 특정 로컬 모델만 조사. 아래 경로는 해당 서버의 실제 모델 디렉터리로 교체
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Hugging Face 캐시를 쓰면서 `snapshots/<리비전>/`의 가중치가 `blobs/`를 가리키는 심볼릭 링크라면, 두 폴더를 포함하는 `models--조직--모델` 디렉터리를 지정합니다. 컨테이너에 바인드한 가중치는 호스트에서 보이는 실제 저장 경로를 사용합니다. 수집 범위는 읽을 수 있는 로컬 파일시스템입니다.

| 확인할 내용 | 결과에서 볼 곳 |
|---|---|
| 모델 아키텍처, 설정의 최대 컨텍스트, 정밀도·양자화, 샤드와 텐서 | `boms/aibom.cdx.json`의 모델·파일 구성요소와 `dependencies`. 저장 형식과 제공된 필드에 따라 값이 다릅니다. |
| H100 제품명, PCI 장치 식별자, 드라이버·펌웨어 | `boms/hbom.cdx.json`. Linux PCI sysfs와 NVIDIA 드라이버가 내보낸 GPU 정보를 읽습니다. |
| PyTorch·Transformers·vLLM·CUDA 관련 패키지 버전 | 설치 메타데이터를 읽을 수 있는 호스트나 해당 컨테이너의 SBOM |
| 서빙 프로세스와 수신 소켓 | 호스트의 `boms/obom.cdx.json`. 해당 프로세스·실행 파일을 관측한 경우에 표시합니다. |

학습·평가 데이터, 라이선스, 원본 모델 리비전과 계보는 모델 카드·출처 명세가 필요합니다. 조사 시점에 Qwen이 점유한 GPU·VRAM, MIG 할당, 실제 서빙 컨텍스트는 모델 설정이나 PCI 정보만으로 결정할 수 없습니다.

가중치 파일만 지정하면 safetensors 또는 GGUF v2/v3의 헤더에서 확인한 형식과 텐서 수, 전체 파일 SHA-256을 기록합니다. 이 경로의 `artifact-binding`은 `sha256-calculated`입니다. safetensors에서는 dtype와 데이터 범위, GGUF에서는 `general.name`, `general.architecture`, `general.file_type` 중 존재하는 메타데이터를 읽습니다. GGUF의 텐서 데이터·연산 결과 검증은 별도입니다. [safetensors 파일 형식](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

모델의 이름·리비전·라이선스·출처, 기반 모델, 학습·평가 데이터는 `koda-model-1`로 지정합니다. 이 경우 `sha256`은 함께 지정한 산출물의 실제 SHA-256과 일치해야 합니다. 선언을 함께 제공하면 다른 형식의 모델 파일도 해당 해시로 연결할 수 있습니다.

```json
{
  "schema": "koda-model-1",
  "name": "example-model",
  "version": "revision-2",
  "sha256": "실제_모델_파일의_SHA256_64자리",
  "license": "Apache-2.0",
  "source": "https://models.example.invalid/example-model",
  "task": "classification",
  "architecture": "transformer",
  "baseModels": [{"name": "base-model", "version": "revision-1"}],
  "datasets": [{"name": "training-data", "version": "v1", "source": "https://data.example.invalid/training"}]
}
```

모델은 `machine-learning-model`, 데이터셋은 `data` 구성요소로 출력합니다. 기반 모델·데이터셋과의 의존관계 및 `modelCard.modelParameters.datasets`의 참조를 유지합니다. 기반 모델과 데이터셋 항목은 `name`이 필수이며 `version`, `sha256`, `source`, `license`를 추가할 수 있습니다. 이들 항목은 공급자가 선언한 자료로 표시합니다. 별도로 지정한 주 모델 파일의 해시를 직접 검증합니다.

## MBOM

### 소프트웨어 빌드 기록

`--provenance`는 in-toto Statement v1의 SLSA provenance v1 JSON을 받습니다. `--provenance-artifact`로 실제 산출물을 지정해야 합니다. `subject` 중 정확히 한 항목의 SHA-256이 일치해야 하며, 선언된 빌더·빌드 유형·입력 리소스·실행 식별자·시작과 종료 시각을 CycloneDX `formulation.workflows`에 기록합니다. SLSA의 외부·내부 파라미터 원문은 출력하지 않습니다. [SLSA provenance v1 형식](https://slsa.dev/spec/v1.0/provenance)

필요한 필드는 `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`과 `subject[].digest.sha256`, `predicate.buildDefinition.buildType`, `predicate.runDetails.builder.id`입니다. `resolvedDependencies`와 `runDetails.metadata`의 `invocationId`, `startedOn`, `finishedOn`은 존재하면 사용합니다. DSSE 봉투는 외부에서 검증·추출한 Statement JSON으로 제공합니다.

### 물리 제품의 제조 기록

제조사 내보내기는 `koda-manufacturing-1`로 입력할 수 있습니다. `--provenance`만 지정합니다. 물리 제품은 제품·부품 ID와 부품번호로 식별합니다.

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

`observation`은 계획된 공정에 `declared`, 실행됐다고 보고된 공정에 `reported`를 사용합니다. 실제 제조사 기록의 캡처 시각을 `observedAt`에 기록합니다. `action`은 `assembly`, `inspection`, `test`, `packaging`을 지원합니다. 단계는 배열 순서로 연결되며 각 단계에 `startedOn`과 `finishedOn`을 추가할 수 있습니다. `inputIds`는 `parts`에 있는 ID여야 합니다. 제품·부품에는 `version`도 지정할 수 있습니다. 단계는 최대 1,000개입니다.

## 실행 가능한 예제

저장소의 `internal/domainbom/testdata/`에 서비스·OpenAPI, safetensors 모델과 모델 카드, 빌드 산출물과 SLSA Statement, 물리 제조 공정 예제를 동봉했습니다. 이 파일들은 작은 합성 시험 자료입니다.

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
