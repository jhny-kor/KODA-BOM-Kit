# Kiểm chứng VM kernel thực Ubuntu 24.04.1

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Đây là công cụ kiểm thử KODA BOM Kit, không phải phụ thuộc của tệp thực thi triển khai trên máy chủ cách ly. Nó khởi động trực tiếp Ubuntu Base **24.04.1 amd64** và kernel Ubuntu chính thức **6.8.0-47-generic / gói 6.8.0-47.47** bằng initramfs tùy chỉnh. QEMU user-mode hay fixture thư mục không chứng minh khởi động kernel thực.

Ubuntu Base được lấy từ mirror phân phối Ubuntu đã lưu trữ. SHA256SUMS.gpg được xác minh bằng Ubuntu CD Image Automatic Signing Key (2012), `843938DF228D22F7B3742BC0D94AA3F0EFE21092`. Keyring kho Ubuntu trong rootfs đã xác thực kiểm InRelease noble-updates ngày 2024-10-18 từ dịch vụ Snapshot chính thức. Chuỗi nối Release đã ký → Packages.xz → SHA-256 và kích thước hai DEB. Giữ mọi URL đầu vào, checksum, nhật ký chữ ký và ID ảnh Docker.

Máy dựng cần Go, Python 3 với `jsonschema`, Docker, GnuPG (`gpg`/`gpgv`). Tái sử dụng ảnh công cụ Oracle VM. Không cài các công cụ này trên máy chủ đích. Chạy từ gốc dự án và thay `<ID>` bằng ID lần chạy thực.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` tái sử dụng cơ chế xuất có giới hạn và baseline độc lập của bộ Oracle. Ubuntu tích hợp sẵn trình điều khiển loop nên thử nghiệm nạp `dummy.ko` thật để xác minh quan sát mô-đun. Ghi độc lập uname, proc release đang chạy, OS, SHA bộ thu thập và mô-đun đã nạp. Đối chiếu hai SBOM với schema chính thức cố định, checksum, phiên bản/source/PURL DEB gốc và kernel/mô-đun đã cài. Chạy lại prepare, run, validate mỗi khi cung cấp binary cuối mới.

Rootfs dùng `dpkg --unpack` để giải DEB gốc và tạo cơ sở dpkg thật. Cho phép ghi đè phụ thuộc và giữ gói ở trạng thái unpack. Điều đó không xác nhận hoàn tất cài đặt apt hay cấu hình thông thường. Khởi động systemd đầy đủ, GRUB, UEFI/Secure Boot, dịch vụ sản xuất và phần cứng vật lý cần thử riêng. QEMU không có NIC/đĩa. Docker dùng `--network none`, rootfs chỉ đọc và bỏ capabilities. Việc cài live patch thương mại hoặc thuê bao thực nằm ngoài thử nghiệm.

Kiểm chứng 0.1.3 truyền `--max-files 0 --timeout 0` để tắt hai giới hạn bộ thu thập. Watchdog riêng 11 phút của PID 1 và timeout QEMU phía host vẫn được giữ.

Giữ cùng nhau provenance, nhật ký chữ ký, dpkg, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, hai SBOM, `validation.json`. Giữ nguyên mã 3 của thu thập một phần, không đổi thành mã 0 của thu thập đầy đủ.
