# Bằng chứng thiết bị ngoại tuyến

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

`Load` của KODA BOM Kit đọc một tệp JSON thông thường, tối đa 8 MiB và 4096 bản ghi. Công cụ chấp nhận bản xuất fwupd `get-devices --json` (`Devices`), các đối tượng Redfish đã mở rộng `SoftwareInventory`, `Manager`, `ComputerSystem` và tập hợp các đối tượng này. Thành viên Redfish chỉ chứa URI tạo vấn đề thu thập chưa đầy đủ. Giá trị nhập là quan sát do quản trị viên xuất. `ImageState` của firmware được giữ khi có, nếu thiếu thì ở trạng thái chưa biết. Hàm băm xác định byte bằng chứng và không xác thực nguồn gốc.

Nhà cung cấp kiểm kê Windows, macOS, OT và các nền tảng khác có thể xuất định dạng tường minh sau.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id":"board", "kind":"device", "name":"Controller", "vendor":"Vendor", "model":"Model", "revision":"A"},
    {"id":"firmware", "parentId":"board", "kind":"firmware", "name":"Controller firmware", "version":"1.2", "properties":{"applicationState":"Active", "storedVersion":"1.3"}}
  ]
}
```

Các loại được hỗ trợ là `device`, `firmware`, `device-driver`. Thuộc tính được phép gồm `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem`, `updateState`. ID được giới hạn trong phạm vi bản băm bằng chứng để tránh gộp nhầm các lần nhập khác nhau. Thiếu phiên bản firmware tạo vấn đề thu thập chưa đầy đủ. Không suy luận CPE. Dấu thời gian quan sát mô tả bản xuất nguồn. Nếu bỏ qua, thời gian vẫn chưa biết.

Định dạng chung còn hỗ trợ `library`, `application`, `operating-system`, `container`. `purl` tùy chọn được phân tích và phiên bản bên trong phải khớp phiên bản khai báo tường minh. Các qualifier giới hạn ở `arch`, `distro`, `epoch`, `type`, `classifier`. `sha256` tùy chọn phải có 64 ký tự thập lục phân và xác định thành phần nhập. Bộ nhập tính riêng hàm băm tệp bằng chứng. Windows và macOS có thể dùng lệnh kiểm kê nền tảng gốc. Dùng định dạng này để bổ sung bằng chứng từ nhà cung cấp khác.

Bản xuất `devlink -j dev info` được chấp nhận qua đối tượng `info`. Tham chiếu bus xác định từng mục. Các nhóm phiên bản fixed, running, stored được giữ riêng. `fw` đang chạy được báo cáo sẽ thành phiên bản thành phần. Khóa phiên bản thay thế riêng của trình điều khiển được giữ trong thuộc tính. Thiếu `fw` tạo vấn đề chưa biết phiên bản. Số sê-ri bị loại bỏ.
