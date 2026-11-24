# KODA BOM Kit — Lệnh thu thập và các tệp kết quả

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Chọn phạm vi

Chạy trên máy đang hoạt động để kiểm kê hệ điều hành, gói phần mềm, container và phần cứng có quyền đọc. Quét thư mục chỉ khảo sát cây thư mục đó. Quét ảnh đọc tệp Docker hoặc OCI đã xuất. Mỗi lần chạy chọn một loại đầu vào. Giới hạn mặc định là một triệu tệp thông thường và 30 phút. `--max-files 0 --timeout 0` bỏ hai giới hạn này. Quyền truy cập, ranh giới hệ thống tệp và giới hạn phân tích tệp nén vẫn áp dụng.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Quét một hoặc nhiều thư mục

Script nhận thư mục đích và có thể nhận thêm thư mục cha để lưu kết quả. Script dùng `--no-context` và từ chối mục tiêu `/`. Đặt đường dẫn có khoảng trắng trong dấu nháy. Dùng `--exclude-dir` để loại thư mục và `--exclude` để loại theo mẫu. Khi quét nhiều đích, các cây thư mục phải tách biệt và thư mục bị loại cần có đường dẫn tuyệt đối. Kết quả hợp nhất vẫn giữ `target-1`, `target-2` cùng vị trí phát hiện.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Đọc bằng chứng vá nóng

Khi quét máy, công cụ đọc trạng thái vá nóng của nhân từ sysfs. Script tùy chọn truy vấn các trình khách Canonical Livepatch, Ksplice hoặc Uptrack đã cài và lọc đầu ra. Báo cáo nhập vào chỉ được coi là hiện hành khi khớp lần khởi động và nhân đang chạy, đồng thời không quá 24 giờ. Thiếu bản ghi không cho biết một CVE đã được vá hay chưa.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Dựng lại đồ thị vận hành hoặc hợp nhất bộ kết quả

OBOM liên kết socket đang lắng nghe, tiến trình và gói đã cài. Địa chỉ gắn cục bộ chưa đủ để kết luận khả năng truy cập từ bên ngoài. Thêm quan sát đã xuất qua `--kubernetes-evidence` hoặc `--network-evidence`. Đặt `set_dir` thành thư mục chứa `bom-set.json` do lệnh tách tạo ra. Giữ nguyên các tệp quan hệ và giá trị kiểm tra. Bộ cũ dùng tên `mlbom.cdx.json` vẫn có thể hợp nhất.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Cung cấp bằng chứng cho các bảng kê khác

Trỏ công cụ thu thập AI đến thư mục chứa mô hình đã cài. Với SaaS hoặc sản xuất, cung cấp bản kê dịch vụ hoặc quy trình. Dùng `--asset-evidence` cho thiết bị Redfish, phần sụn hoặc bằng chứng mật mã đã xuất. Bảng kê lúc biên dịch chỉ liên kết với sản phẩm được quét khi SHA-256 khớp. Các hướng dẫn cuối trang mô tả định dạng đầu vào.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## Nhập hồ sơ IBM AIX và Oracle

Chạy script trên AIX, sau đó chạy lệnh nhập trên máy Linux dùng để phân tích. Cung cấp đầu ra OPatch do chủ sở hữu Oracle Home lưu lại và lịch sử bản vá SQL do DBA xuất nếu có. Hỗ trợ tối đa tám Home khác nhau. Phiên bản Listener cần bằng chứng cùng Home. Đối chiếu mã bản vá với thông báo tương ứng của nhà cung cấp.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Nhận diện các thành phần phụ thuộc đã triển khai

Với npm và pnpm, quan hệ dựa trên vị trí cài đặt, cách phân giải peer và phiên bản. Việc nhận diện JavaScript tĩnh hỗ trợ jQuery, jQuery UI và Fancytree. Go cần thông tin biên dịch nhúng và Rust ELF cần dữ liệu cargo-auditable. Với .NET, đối chiếu .deps.json cùng các DLL được quản lý đã triển khai. Ruby sử dụng gemspec đã cài. Java giữ đường dẫn bên trong WAR, EAR và Spring Boot. Tọa độ chưa xác định được giữ ở trạng thái chưa phân giải.

## So sánh bản triển khai với bảng kê của nhà cung cấp

Cung cấp một tệp WAR hoặc EAR và tài liệu CycloneDX 1.4–1.7 hoặc SPDX 2.3 chứa SHA-256 của chính tệp đó. Xem `common`, `observedOnly`, `supplierOnly` và `unresolved` trong `reconcile.json`. Gửi bảng kê quan sát được tới Tracker. Giới hạn là 512 MiB cho bản triển khai và 32 MiB cho bảng kê nhà cung cấp.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Kiểm tra độ bao phủ

Trên máy biên dịch hoặc kiểm thử, so sánh cùng một bản triển khai không thay đổi bằng KODA, Syft và Trivy. Script cần Python 3.11 trở lên. Dùng `--expected` cho các thành phần và quan hệ đã xác nhận hoặc `--baseline` để kiểm tra hồi quy. Phép thử Tracker tùy chọn sẽ tải dữ liệu lên dịch vụ thử nghiệm được chỉ định. Để kiểm tra đồ thị đã lưu, cung cấp `--normalized-bom-command`.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Đọc kết quả

Đặt `run_dir` thành đường dẫn công cụ vừa in ra. Mã thoát 0 là hoàn tất, 3 là kết quả một phần và 2 là thất bại. Đọc `collection.json` để xem giới hạn, phần thiếu và lỗi, `context.json` để xem quan hệ lúc chạy, `assets.json` để xem bằng chứng về thiết bị hoặc chứng thư. Mỗi thư mục container hoặc ảnh có bộ giá trị kiểm tra riêng. Chỉ dựa vào phiên bản và ngày tháng thì chưa thể kết luận về lỗ hổng.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Biên dịch trên máy riêng

Máy biên dịch cần Go và Python 3. Phiên bản này được biên dịch bằng Go 1.26.11. Nếu dùng tệp Go khác, hãy cung cấp đường dẫn và SHA-256 đã xác minh. Biên dịch ngoại tuyến yêu cầu bộ đệm mô-đun đã nạp sẵn. Gói phát hành dành cho Linux amd64, còn mã nguồn cũng biên dịch được cho Linux ARM64. Nguồn gốc bản dựng được ghi vào `release.json`.

```sh
VERSION=0.1.9 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Tài liệu

- [Cài đặt ngoại tuyến và kiểm tra kết quả](air-gapped.vi.md)
- [Bằng chứng phần cứng, mật mã và vận hành](asset-inventory.vi.md)
- [Bản kê dịch vụ, mô hình AI và quy trình sản xuất](additional-bom.vi.md)
- [Nền tảng hỗ trợ và giới hạn thu thập](support-matrix.vi.md)
- [Quy trình biên dịch và kiểm chứng](verification.vi.md)
- [Kết quả và phạm vi thử nghiệm](verification-results.vi.md)
