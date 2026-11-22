# Bằng chứng bổ sung cho SaaSBOM, AI-BOM và MBOM

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="additional-bom.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="additional-bom.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="additional-bom.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="additional-bom.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


`domain-bom` đọc bằng chứng và tệp sản phẩm cục bộ để tạo `saasbom.cdx.json`, `aibom.cdx.json` và `mbom.cdx.json`. Thêm `--cyclonedx-17` để xuất cả phiên bản 1.7. Lệnh `scan` cũng nhận các tùy chọn bằng chứng này. Khi quét máy chủ với thiết lập mặc định, bảy BOM riêng được lưu trong `boms/`, còn BOM hợp nhất được lưu ở `bom.cdx.json`.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

Bản ghi chứa SHA-256, phạm vi quan sát và phân biệt dữ liệu khai báo với dữ liệu đã báo cáo. Trạng thái xác thực chữ ký trong `koda:domain:authenticity` vẫn là chưa kiểm chứng. Khi nhập bằng chứng, `compositions.aggregate=incomplete`. Nếu khai báo khớp tệp sản phẩm thì `artifact-binding=sha256-matched`. Miền không có bằng chứng trong lần quét toàn máy được đánh dấu `no-evidence` và chưa rõ độ bao phủ.

Mỗi lệnh nhận tối đa 12 đầu vào cho cả ba miền. Mỗi tệp bằng chứng JSON tối đa 16 MiB, mỗi danh sách tối đa 10.000 mục. Công cụ từ chối khóa JSON trùng, thông tin người dùng trong URL, chuỗi truy vấn, phần sau dấu thăng và mẫu địa chỉ máy chủ chưa phân giải. Giá trị băm được tính theo luồng dữ liệu. Công cụ chỉ đọc trọng số mô hình và tệp thực thi.

## SaaSBOM

`--saas-evidence` nhận JSON OpenAPI 3.x hoặc `koda-services-1`. OpenAPI cung cấp tiêu đề, phiên bản, địa chỉ máy chủ tuyệt đối được khai báo ở cấp gốc, đường dẫn hoặc thao tác, cùng yêu cầu xác thực của từng thao tác. Địa chỉ tương đối mặc định không cho biết nơi triển khai. Thao tác cho phép truy cập ẩn danh đặt `authenticated=false`. Nếu mọi thao tác được kiểm tra đều yêu cầu xác thực, giá trị là `true`. Nếu khai báo chưa đủ, trường này được bỏ trống. Ví dụ về nội dung yêu cầu, nội dung lược đồ bảo mật, mô tả và bí mật không được lưu. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI cũng có thể ở dạng YAML. YAML chỉ được chứa một tài liệu, khóa trùng bị từ chối và số giữ nguyên văn bản gốc, nên `version: 1.0` vẫn là `1.0`.

Khi thu thập máy chủ, công cụ còn đọc cấu hình reverse proxy và bộ cân bằng tải: `upstream`, `proxy_pass`, `grpc_pass` của nginx, `ProxyPass`, `BalancerMember` của Apache và các `server` trong `backend` của HAProxy. Mỗi backend được ghi thành dịch vụ có `observation=declared-proxy-backend` cùng tệp và dòng khai báo. Chỉ giữ scheme, máy chủ và cổng; bỏ đường dẫn, chuỗi truy vấn và thông tin xác thực, còn đích dùng biến được báo là chưa phân giải. Việc backend có truy cập được hay không được xác nhận qua kết nối ra ngoài trong OBOM, không qua khai báo này. Tệp `*-available` của Debian chỉ có hiệu lực qua liên kết `*-enabled`, áp dụng cả cho khai báo TLS trong CBOM. Khi quét thư mục không theo được các liên kết đó, tệp vẫn được đọc và một vấn đề ghi rằng trạng thái bật chưa xác định.

Dùng lược đồ sau để ghi nhà cung cấp, ranh giới tin cậy, phân loại dữ liệu và quan hệ phụ thuộc giữa các dịch vụ.

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

`id` và `name` là bắt buộc. Các trường minh họa khác và `version` là tùy chọn. `dependsOn` tham chiếu đến ID dịch vụ trong cùng tệp. Hướng luồng dữ liệu `flow` được tính từ phía dịch vụ và nhận `inbound`, `outbound`, `bi-directional` hoặc `unknown`. Trạng thái xác thực, mức độ tin cậy và quan hệ gọi dịch vụ dựa trên khai báo được cung cấp.

## AI-BOM

Kiểm tra thư mục chứa mô hình trên máy chủ đích. Khi quét toàn máy, công cụ cũng thực hiện các bước kiểm tra này trên những đường dẫn nằm trong phạm vi thu thập.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- `config.json` của Hugging Face cung cấp kiến trúc, số tầng và số đầu chú ý của mô hình văn bản, độ dài ngữ cảnh tối đa và thông tin lượng tử hóa. Chỉ mục trọng số cho biết số tensor khai báo và danh sách các tệp phân mảnh.
- Phần đầu tệp safetensors hoặc GGUF cung cấp định dạng, số tensor và các siêu dữ liệu hiện có. Quan hệ phụ thuộc liên kết mô hình với tệp trọng số. Ngay cả khi trọng số lớn, bước dò tìm chỉ đọc một phần đầu tệp có giới hạn kích thước. Giá trị băm của cấu hình, chỉ mục, phần đầu tệp và toàn bộ tệp được ghi riêng.
- Bản kê Ollama nối các lớp của mô hình với phần đầu các blob cục bộ mà công cụ đọc được. Để xác nhận mô hình đang được nạp trên máy chủ, cần có bằng chứng lúc chạy.
- Thẻ mô hình `README.md` của Hugging Face nằm cạnh `config.json` cung cấp giấy phép, `base_model`, `datasets`, `pipeline_tag`, ngôn ngữ và thư viện. Mô hình nền và tập dữ liệu trở thành thành phần được khai báo, liên kết với mô hình. Trong bộ đệm Hugging Face, `refs/main` và các ref khác trỏ tới snapshot được ghi là `cache-ref`. Giá trị trong thẻ mô hình vẫn là khai báo của bên phát hành.
- Tệp ONNX cung cấp phiên bản IR, công cụ tạo, phiên bản mô hình và các bộ toán tử. Miền toán tử ngoài `ai.onnx` và `ai.onnx.ml` được liệt kê là `onnx:custom-operator-domain` vì cần thư viện toán tử tùy chỉnh dạng mã gốc.
- Checkpoint PyTorch (`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt`, dạng zip hoặc cũ) là pickle sẽ chạy các hàm được import khi nạp. KODA duyệt opcode pickle mà không thực thi và ghi `pickle:safety` là `allowlisted-imports-only`, `unknown-imports` hoặc `dangerous-imports`, kèm từng `pickle:dangerous-import` như `os.system`. Tệp không duyệt được tới cuối được ghi `pickle:inspection=incomplete`, không bao giờ được coi là chỉ dùng danh sách cho phép, và vẫn giữ các import tìm thấy trước khi lỗi. Pickle giao thức 0/1 và cả năm luồng của tệp `torch.save` dạng cũ đều được kiểm tra. Nên dùng safetensors cho tệp không thuộc loại chỉ dùng danh sách cho phép. Tệp pickle và ONNX trong thư mục mô hình Hugging Face, như `pytorch_model.bin`, `training_args.bin` hoặc `optimizer.pt`, được liên kết với mô hình đó, và mô hình ghi kết quả kém an toàn nhất trong `artifact-pickle-safety`. Nếu có tệp không kiểm tra được, mô hình được ghi ít nhất là `unknown-imports` kèm `artifact-inspection=incomplete`.
- Trên máy chủ đang chạy, tiến trình vLLM, TGI, llama.cpp, SGLang, Triton hoặc LMDeploy được khởi động với đường dẫn mô hình hoặc ID kho sẽ làm mô hình tương ứng được ghi `runtime-state=referenced-by-running-process` và `serving-process`, còn tiến trình trong OBOM có `model-reference`. Kết quả dựa trên tham số khởi động; Ollama chọn mô hình theo từng yêu cầu nên không được liên kết.

### Qwen trên máy chủ Linux có GPU NVIDIA

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

Thay `/srv/models/Qwen` bằng đường dẫn thực tế. Với liên kết tượng trưng của Hugging Face từ `snapshots/<revision>/` tới `blobs/`, chọn thư mục cha `models--organization--model`. Với bind mount của container, dùng đường dẫn lưu trữ nhìn thấy từ máy chủ.

| Bằng chứng | Kết quả |
|---|---|
| Kiến trúc, ngữ cảnh, độ chính xác, lượng tử hóa, các mảnh trọng số và tensor | Thành phần và quan hệ trong `boms/aibom.cdx.json`, tùy định dạng lưu trữ và các trường có sẵn |
| Mẫu H100, mã PCI, trình điều khiển và phần sụn | `boms/hbom.cdx.json`, dựa trên PCI sysfs của Linux và thông tin trình điều khiển NVIDIA |
| Phiên bản các gói PyTorch, Transformers, vLLM và CUDA | SBOM của máy chủ hoặc container khi đọc được siêu dữ liệu cài đặt |
| Tiến trình phục vụ mô hình và socket lắng nghe | `boms/obom.cdx.json` khi quan sát được tiến trình và tệp thực thi |

Dữ liệu huấn luyện hoặc đánh giá và phả hệ mô hình không có trong thẻ mô hình cần khai báo nguồn gốc. Mức sử dụng GPU/VRAM hiện tại, phân bổ MIG và ngữ cảnh phục vụ cần quan sát riêng lúc chạy.

Khi nhập riêng tệp trọng số, công cụ tính SHA-256 cho toàn tệp, đọc siêu dữ liệu hiện có trong phần đầu safetensors hoặc GGUF v2/v3 và ghi `artifact-binding=sha256-calculated`. safetensors cung cấp kiểu dữ liệu và các khoảng dữ liệu. GGUF có thể cung cấp `general.name`, `general.architecture`, `general.file_type`. Dữ liệu tensor và phép tính của mô hình cần được kiểm chứng riêng. [Định dạng safetensors](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

Dùng `koda-model-1` để khai báo danh tính, phiên bản, giấy phép, nguồn, mô hình cơ sở và bộ dữ liệu. Thay `sha256` trong ví dụ bằng giá trị băm 64 ký tự của tệp thực tế. Ghép từng khai báo với `--model-artifact` theo thứ tự. Khai báo khớp giá trị băm cũng có thể liên kết với tệp mô hình ở định dạng khác.

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

Mô hình dùng kiểu thành phần `machine-learning-model`, bộ dữ liệu dùng `data`. Quan hệ phụ thuộc và tham chiếu `modelCard.modelParameters.datasets` được giữ lại. Mỗi mô hình cơ sở hoặc bộ dữ liệu phải có `name` và có thể có `version`, `sha256`, `source`, `license`. Các siêu dữ liệu này do nhà cung cấp khai báo. Giá trị băm của tệp mô hình chính được cung cấp riêng sẽ được kiểm tra trực tiếp.

## MBOM

### Nguồn gốc bản dựng phần mềm

`--provenance` nhận in-toto Statement v1 chứa SLSA provenance v1. Cung cấp sản phẩm thực tế qua `--provenance-artifact`. Phải có đúng một `subject` khớp với SHA-256 của sản phẩm. Hệ thống dựng, loại bản dựng, đầu vào đã phân giải, ID lần chạy và thời điểm bắt đầu/kết thúc được ghi vào `formulation.workflows` của CycloneDX. Các tham số nội bộ và bên ngoài ở dạng thô được lược bỏ. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Các trường bắt buộc gồm `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType` và `predicate.runDetails.builder.id`. Công cụ dùng `resolvedDependencies` và các trường `invocationId`, `startedOn`, `finishedOn` trong `runDetails.metadata` nếu có. Hãy xác minh và trích xuất phong bì DSSE bằng công cụ riêng trước khi cung cấp Statement JSON.

### Sản xuất vật lý

Dùng `koda-manufacturing-1` với `--provenance`. Mã định danh sản phẩm, ID linh kiện và mã linh kiện giúp nhận diện các vật phẩm thực tế.

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

`observation` nhận `declared` cho bước theo kế hoạch hoặc `reported` cho bước được báo cáo là đã thực hiện. Đặt `observedAt` bằng thời điểm ghi nhận. Các hoạt động được hỗ trợ là `assembly`, `inspection`, `test`, `packaging`. Tối đa 1.000 bước được liên kết theo thứ tự trong mảng. `startedOn` và `finishedOn` của từng bước là tùy chọn. `inputIds` phải tham chiếu đến `parts`. Sản phẩm và linh kiện có thể có `version`.

## Ví dụ có thể chạy từ mã nguồn

Kho mã chứa các bộ dữ liệu thử nghiệm nhỏ cho dịch vụ/OpenAPI, mô hình, SLSA và sản xuất trong `internal/domainbom/testdata/`.

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

[Phạm vi thu thập](support-matrix.vi.md) · [Kiểm kê tài sản](asset-inventory.vi.md)
