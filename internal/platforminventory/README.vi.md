# Quan sát nền tảng gốc

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`Collect(ctx)` của KODA BOM Kit thu thập quan sát có giới hạn bằng công cụ đã cài trên máy đích. Công cụ dùng đối số cố định, thời hạn 60 giây mỗi lệnh và giới hạn đầu ra 32 MiB. Các trường được chọn trước khi ghi vào SBOM. Số sê-ri, UUID, tên người dùng và đường dẫn đầy đủ của ứng dụng bị loại bỏ. Đường dẫn cục bộ chỉ tham gia tính định danh thành phần đã băm.

Trên macOS, `/usr/sbin/system_profiler` cung cấp siêu dữ liệu phần cứng, phần mềm và ứng dụng. Bộ thu thập xuất firmware hệ thống, bộ nạp hệ điều hành, CPU và ứng dụng, đồng thời giữ số bản dựng trong chuỗi phiên bản hệ điều hành. Một số ứng dụng có thể thiếu phiên bản hoặc siêu dữ liệu.

Trên Windows, PowerShell hệ thống chạy không nạp profile và đọc các bản ghi CIM computer, BIOS, OS, QuickFixEngineering cùng mục gỡ cài đặt trong registry của máy và người dùng hiện tại. Số bản dựng và kiến trúc hệ điều hành được giữ lại. QuickFixEngineering chỉ bao gồm bản cập nhật do chính nó báo cáo. Kiểm kê registry không liệt kê mọi hồ sơ người dùng, ứng dụng Store hay phụ thuộc tích hợp. Bộ thu thập ghi nhận giới hạn phạm vi này.

Chạy xác minh macOS gốc bằng `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`. Fixture phân tích Windows và biên dịch chéo xác minh cấu trúc mã nguồn. Thực thi Windows thực tế cần máy đích Windows.
