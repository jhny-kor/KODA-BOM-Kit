# Chạy trong mạng cô lập và xem kết quả

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 có gói Linux x86_64 (amd64), nhân 3.2 trở lên. Chuyển gói và `.tar.gz.sha256` tương ứng từ bản phát hành chính thức. Máy đích không cần cài Go, Python, Docker hoặc jq. NOTICE ghi jhny-kor và kho chính thức.

[Phát hành 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Xác minh và giải nén

Đặt đúng một gói khớp và checksum trong thư mục cục bộ cho phép chạy. Kiểm tra gói trước khi giải nén, rồi kiểm tra tệp bên trong. Checksum xác minh byte đã chuyển. Dùng nguồn phát hành chính thức đáng tin. USB noexec cần sao chép sang hệ thống tệp cho phép thực thi.

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## Kiểm tra máy chủ

Kiểm tra kiến trúc, nhân và `doctor`. `supported=true` cho biết đạt điều kiện chạy. `doctor.kernel` và `context.json.runningKernel` là nhân quan sát. `kernelFlavor=unknown/unconfirmed` vẫn có thể kèm phiên bản. root tăng khả năng đọc DMI, BMC, tiến trình và container.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Chọn phạm vi

Không tham số, `koda-bom` tạo thư mục trong `bom-output/` với `bom.cdx.json` hợp nhất và bảy tệp trong `boms/`. AI-BOM là `aibom.cdx.json`. Nội dung phụ thuộc bằng chứng cục bộ. Qwen dùng thư mục mô hình thật. H100 nằm trong HBOM. Cấu hình, tiêu đề và gói không xác định được phân bổ GPU hay cấu hình phục vụ đang có hiệu lực.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

Thu thư mục dùng `--no-context`. Đặt đầu ra ngoài đầu vào. Tập lệnh từ chối `/`, cho phép đường dẫn loại trừ tương đối khi chỉ một thư mục. Nhiều đích không được chồng lấn và loại trừ phải tuyệt đối. Chia sẻ giới hạn tệp/thời gian. Phụ thuộc bên ngoài có thể không được quan sát.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Thu livepatch

Tập lệnh tùy chọn truy vấn Ksplice, Uptrack hoặc Canonical đã có, làm sạch bằng chứng rồi chạy scan. Bằng chứng được lưu bên cạnh kết quả. Lấy `$?` ngay. Giới hạn truy vấn 30 giây và nhân hiệu lực 10 giây vẫn giữ khi bỏ timeout scan. Máy khách/daemon có hành vi mạng riêng.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Giới hạn và mã thoát

Mặc định 1,000,000 tệp thường và 30 phút. `--max-files 0 --timeout 0` bỏ hai giới hạn, Ctrl+C hủy. Quyền, loại trừ, liên kết, 2 GiB/tệp và giới hạn giải nén vẫn áp dụng. `--no-containers` bỏ container và image không dùng. `--no-images` bỏ container dừng và image không dùng. 0 là hoàn tất, 3 là một phần có kết quả, 2 là lỗi. Điều tra mã bất thường khác.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Tìm và kiểm tra kết quả

Dùng đúng đường dẫn được in. Tập lệnh in doctor/bằng chứng rồi dòng cuối là đường dẫn kết quả. Đặt `result` bằng đường dẫn đó. Tệp root có thể cần sudo. Kiểm tra manifest chính và từng container/image. Giữ lý do thu thập một phần.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## Đọc trạng thái và bản vá

`collection.json` có `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, định danh, nguồn, toàn vẹn và container. Số tệp là tệp được chọn khi duyệt. `file_limit_exceeded` có `limit` và `observed`. `context.json` có nhân, tiến trình, socket, dịch vụ, cấu hình và bản vá. `assets.json` có phần cứng, firmware và chứng chỉ.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` là quan sát nhân, `reported-applied` là báo cáo máy khách. `disabled`, `transitioning` giữ nghĩa trạng thái. `stale`, `identity_mismatch`, `unknown` cần thêm bằng chứng. Đọc trạng thái hiện tại và `patches[].state`, vì `reportedState` có thể cũ. Dữ liệu quá 24 giờ, khác lần khởi động/nhân hoặc thời gian tương lai quá mức không chứng minh áp dụng hiện tại. Canonical Last-Check/CheckState cũng được kiểm tra. Giải thích thiếu quan sát và `not-reported-patched` bằng bằng chứng nhân/nhà cung cấp.

`integrity.findings[].state=modified` hoặc `missing` là khác biệt hoặc thiếu. `bindScope=all-interfaces` mô tả địa chỉ gắn. Truy cập qua tường lửa cần chứng cứ khác. `unidentifiedExecutables` là chưa liên kết với gói. `reboot.recommended=not_observed` là chưa thấy tín hiệu. Đọc cùng ngữ cảnh và giới hạn.

## Đối chiếu nhà cung cấp và lưu giữ

SBOM nhà cung cấp WAR/EAR cần SHA-256 thực. Băm thiếu/khác trả mã 2. Xem `reconcile.json` và lý do một phần. Lưu toàn bộ thư mục cha cùng bằng chứng livepatch đã làm sạch và tính checksum gói xuất.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Tải lên và phân tích

Gửi `sbom.cdx.json` hoặc `sbom.spdx.json` tới Tracker tương thích. Container/image có SBOM riêng. Giữ collection, context và Syft làm bằng chứng kèm theo. Timeout tải lên độc lập. Kết quả là đầu vào cho phân tích thông báo. Hiệu lực bản vá và khắc phục CVE cần chứng cứ riêng. Xem lịch sử để biết phạm vi từng phiên bản và VM.

## Tài liệu

[Chạy trong mạng cô lập và xem kết quả](air-gapped.vi.md) · [Hướng dẫn biên dịch và kiểm chứng](verification.vi.md) · [Kết quả kiểm chứng](verification-results.vi.md)
