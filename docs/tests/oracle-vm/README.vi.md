# Bộ kiểm chứng khởi động trực tiếp kernel Oracle Linux 8.2

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

`init.go` là **PID 1 của VM kiểm chứng** KODA BOM Kit. Ràng buộc `//go:build ignore` loại tệp khỏi kiểm thử gói Go thông thường. Biên dịch tường minh bằng lệnh sau.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker và QEMU là công cụ kiểm chứng trên PC dựng. Chuyển tệp thực thi `koda-bom` tới máy chủ mạng cách ly. Bộ kiểm chứng và trình thông dịch Python không phải phụ thuộc của tệp triển khai.

## Tái hiện

Runner mô phỏng x86_64 bằng TCG trong container QEMU trên máy dựng ARM64. Máy khách có 4 GiB RAM, 2 vCPU, container giới hạn bộ nhớ 6 GiB. Chạy từ gốc dự án trên PC bên ngoài. Thay `<ID>` bằng ID thực do `run.py` in ra và giữ báo cáo cũ.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

Máy kiểm chứng cần `jsonschema` và kiểm tra ngoại tuyến với schema chính thức cố định trong `tests/schemas`. Tải xuống ở bước chuẩn bị cần mạng. VM kernel chạy không kết nối bên ngoài. Giữ ID ảnh dùng trong lần chạy vì tag có thể thay đổi.

`prepare.py` kiểm tra SHA-256 và kích thước bốn RPM cố định trong [kernels.json](../../../tests/oracle-vm/kernels.json), tổng 120,245,036 byte, cùng dấu vân tay khóa ký Oracle Linux 8. Nó nhập khóa công khai vào cơ sở RPM của container Oracle thử nghiệm mới, kiểm chữ ký bằng `rpm -Kv`, rồi cài kernel với `--nodeps --noscripts --notriggers`. Cách này tạo hệ thống tệp để kiểm ảnh kernel, mô-đun và siêu dữ liệu RPM. Script cài đặt thông thường, dracut và cấu hình GRUB nằm ngoài quy trình.

Chạy lại `prepare.py` với binary phát hành cuối trong thư mục làm việc hiện có để dựng lại bộ thu thập, PID 1 và initramfs từ hệ thống tệp kernel/RPM đã lưu đệm. Khởi động lại cả hai VM và đối chiếu **SHA-256 binary cuối** với baseline. Kết quả VM của bản dựng cũ không xác minh bản phát hành mới.

Giữ `input-provenance.json`, `rpm-signature-install.log` và từng lần chạy gồm `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, hai SBOM cùng checksum. Provenance ghi hash RPM, kernel, initramfs, PID 1, bộ thu thập và ID ảnh Oracle/QEMU. Báo cáo xác minh phát hành riêng liên kết bằng chứng với SHA-256 gói phân phối.

## Chuẩn bị máy khách

Initramfs kiểm chứng chứa hệ thống tệp Oracle Linux 8.2, cơ sở RPM của cả hai kernel đã cài, ảnh trong `/boot`, hai cây `/lib/modules`, `/koda-bom` cần kiểm và bộ kiểm chứng `/init`. RHCK và UEK phải khởi động trực tiếp bằng ảnh kernel riêng. Chỉ chạy container hoặc QEMU user-mode không tạo bằng chứng khởi động này. Có thể đặt mô-đun đúng phiên bản trích từ RPM kernel chính thức ở vị trí sau.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

Bộ kiểm chứng ghi SHA-256 mô-đun và thử nạp bằng `init_module`. Trạng thái và lỗi được ghi riêng khi thiếu mô-đun, đã nạp hoặc lỗi chữ ký/phụ thuộc. So sánh `loadedModulesAfter` với `loadedModules` của bộ thu thập để xác nhận việc nạp thật. Không quan sát thấy mô-đun không chứng minh thiếu tính năng.

QEMU không gắn giao diện mạng ngoài hay đĩa ảo. Runner dùng `-accel tcg,thread=single -cpu max -smp 2 -m 4096`. Máy khách thử dùng `random.trust_cpu=on` để tránh chờ `getrandom` khi khởi động sớm. Tham số thử nghiệm này không phải khuyến nghị cấu hình sản xuất. Giữ thiết lập CPU/tăng tốc thực và checksum kernel, RPM, initramfs, bộ thu thập trong hồ sơ máy chủ.

## Thực thi và thu thập

Bộ kiểm chứng gắn `/proc`, `/sys`, `/dev`, `/tmp`, `/results` và đặt hostname tổng hợp. Baseline độc lập ghi uname, `/proc/sys/kernel/osrelease`, OS release, danh sách mô-đun trước/sau, dòng lệnh kernel VM và checksum bộ thu thập. Hostname và dòng lệnh chỉ nằm trong bằng chứng VM tổng hợp này. Chính sách thu thập thông thường của sản phẩm vẫn áp dụng. Bộ thu thập chạy một lần bằng lệnh sau.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

Dùng live-host mặc định, không truyền `--target /payload`. Kiểm chứng 0.1.3 đặt giới hạn số tệp và thời gian bằng 0 để tắt giới hạn. Watchdog riêng 11 phút của PID 1 và timeout QEMU trên host vẫn được giữ để thu hồi tài nguyên. stdout, stderr mỗi luồng giới hạn 1 MiB, lưu riêng. Mã thoát, thời gian và lỗi ghi ở `/results/baseline.json`. Mã 3 là thu thập một phần và phải giữ nguyên.

Kết quả truyền qua đầu ra serial dưới dạng **base64(gzip(tar))** giữa các marker sau.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

Nếu tổng chưa nén vượt 256 MiB hoặc 10,000 tệp, chỉ xuất baseline giải thích lỗi. Sau khi xuất sẽ thử sync và poweroff. Nếu thất bại, PID 1 vẫn sống để tránh kernel panic. Runner trên host phải kết thúc QEMU nếu máy khách quá hạn.

## Các kiểm tra bắt buộc

- Uname của baseline khớp proc release và RHCK/UEK khởi động đúng phiên bản dự kiến.
- `context.json.mode=live-host` và `runningKernel` khớp chính xác baseline độc lập.
- UEK báo `kernelFlavor=UEK`, RHCK báo `RHCK-compatible` theo giao ước hiện tại.
- Kiểm kê gốc giữ cả hai kernel đã cài cùng epoch/version/release/arch/source package của mỗi RPM.
- Phân biệt kernel đã cài với kernel đang chạy do context xác định.
- `metadata.kernelVersion` và `versionMagic` khớp từng cây cài đặt. Danh sách mô-đun đã nạp khớp baseline kernel hoạt động.
- Schema và checksum của hai SBOM đều đạt. Báo cáo trung thực lỗi và trạng thái một phần.

## Giới hạn kiểm chứng

- Khởi động kernel khách Oracle RHCK/UEK thực. Kiểm chứng máy chủ x86_64 vật lý cần thực hiện riêng.
- Không gian người dùng Oracle Linux 8.2 và kernel chính thức chạy trong initramfs tùy chỉnh. Khởi động systemd đầy đủ, cài GRUB, UEFI/Secure Boot, SELinux enforcing và tích hợp dịch vụ sản xuất nằm ngoài kiểm thử.
- Thử `loop` kiểm tra nạp và quan sát một mô-đun thật. Không bao phủ mọi trình điều khiển hoặc phần cứng. Mô-đun đã cài của kernel không hoạt động không được coi là đã nạp.
- Chấp nhận mã `3` và `collection.status=partial` cùng lý do được giữ lại. Đạt kiểm nhận diện kernel, đầu ra chuẩn và toàn vẹn không chứng minh đã thu đủ mọi tệp.
