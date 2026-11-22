<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.vi.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Thu thập thông tin phần mềm, phần cứng và bằng chứng vận hành của máy Linux bằng một tệp thực thi ngoại tuyến. KODA BOM Kit tạo bảy bảng kê thành phần CycloneDX, một bảng kê hợp nhất và một danh mục phần mềm theo định dạng SPDX.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>Tải v0.1.8</b></a> ·
  Tác giả gốc <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Kho mã chính thức</a>
</p>

## Bắt đầu nhanh

Tải gói nén Linux amd64 cùng tệp SHA-256 tương ứng. Chép cả hai vào một thư mục trống trên máy chủ đích rồi chạy các lệnh sau tại đó. Máy chủ đích không cần cài Go, tải gói phần mềm hay cài cơ sở dữ liệu lỗ hổng.

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## Các tệp kết quả

Dòng cuối hiển thị đường dẫn đến thư mục vừa tạo trong `bom-output/`. Mở `bom.cdx.json` để xem bảng kê hợp nhất. Bảy bảng kê riêng nằm trong `boms/`.

| Tệp | Nội dung |
|---|---|
| `boms/sbom.cdx.json` | Gói phần mềm, thư viện và ứng dụng đã cài |
| `boms/hbom.cdx.json` | Thiết bị, phần sụn và trình điều khiển |
| `boms/cbom.cdx.json` | Tài sản mật mã như chứng thư và thuật toán |
| `boms/obom.cdx.json` | Quan hệ quan sát được giữa dịch vụ, tiến trình, socket và gói phần mềm |
| `boms/aibom.cdx.json` | Tệp mô hình cục bộ, trọng số và siêu dữ liệu được cung cấp |
| `boms/saasbom.cdx.json` | Dịch vụ được mô tả trong tài liệu OpenAPI hoặc bản kê dịch vụ |
| `boms/mbom.cdx.json` | Quy trình sản xuất và biên dịch có bằng chứng đi kèm |

Một bảng kê có thể trống nếu máy chủ không có bằng chứng tương ứng. Xem trạng thái bằng chứng và `collection.json` để biết lý do. Tracker nhận `sbom.cdx.json` hoặc `sbom.spdx.json` ở cấp cao nhất. Định dạng mặc định là CycloneDX 1.6 và SPDX 2.3. Thêm `--cyclonedx-17` để tạo cả CycloneDX 1.7.

Để hợp nhất lại, hãy sao chép toàn bộ thư mục `boms/`, gồm bản kê, dữ liệu quan hệ và các giá trị kiểm tra. Đặt `run_dir` thành đường dẫn mà công cụ vừa in ra.

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Tài liệu

- [Cài đặt ngoại tuyến và kiểm tra kết quả](air-gapped.vi.md)
- [Lệnh thu thập và các tệp kết quả](collector-guide.vi.md)
- [Bằng chứng phần cứng, mật mã và vận hành](asset-inventory.vi.md)
- [Bản kê dịch vụ, mô hình AI và quy trình sản xuất](additional-bom.vi.md)
- [Nền tảng hỗ trợ và giới hạn thu thập](support-matrix.vi.md)
- [Quy trình biên dịch và kiểm chứng](verification.vi.md)
- [Kết quả và phạm vi thử nghiệm](verification-results.vi.md)

### Hướng dẫn mã nguồn và kiểm thử

- [Nhập tài sản từ bên ngoài](internal/assetimport/README.vi.md)
- [Kiểm kê theo nền tảng](internal/platforminventory/README.vi.md)
- [Nhận diện sản phẩm](internal/products/README.vi.md)
- [Oracle Linux VM](tests/oracle-vm/README.vi.md)
- [Ubuntu VM](tests/ubuntu-vm/README.vi.md)

## Giấy phép và ghi công

KODA BOM Kit được phân phối theo giấy phép Apache-2.0. Các thông báo bên dưới ghi rõ tác giả gốc và giấy phép của những thành phần đi kèm. [Apache-2.0](../LICENSE) · [Thông báo tác giả](../NOTICE) · [Thông báo của bên thứ ba](THIRD_PARTY_NOTICES.vi.md)
