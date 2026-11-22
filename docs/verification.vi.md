# Hướng dẫn biên dịch và kiểm chứng

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 cung cấp gói ngoại tuyến Linux amd64 và SHA-256. Xác định tệp đã kiểm tra bằng hàm băm chính xác và môi trường chạy. Thu thập Linux hỗ trợ x86_64 và ARM64, lưu trữ Docker/OCI nhắm linux/amd64. Kiểm kê macOS/Windows dùng lệnh hệ thống chỉ đọc cố định. Chạy thực tế trên Windows chưa được kiểm chứng. Kết quả VM cũ thuộc từng bản dựng đã ghi.

[Phát hành 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Định dạng và tính toàn vẹn

Mặc định là CycloneDX 1.6 và SPDX 2.3. `--cyclonedx-17` thêm 1.7 từ cùng kiểm kê. Với `--format cyclonedx`, tạo hai tài liệu. Với `--format spdx`, tổ hợp bị từ chối trước khi xuất. `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` và hai tập lệnh hỗ trợ đều nhận tùy chọn này. Đối chiếu các tệp dự kiến với tùy chọn.

| Đầu ra | Định dạng |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` kiểm tra lược đồ cục bộ, định danh, bằng chứng, thuộc tính, ý nghĩa giấy phép, quan hệ, phạm vi và mục băm thiếu/trùng. Lược đồ 1.7 cố định ở bản chính thức 1.7.1, commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`, nguồn trong `tests/schemas/provenance.json`. Có 704 mã giấy phép ở 1.6 và 811 ở 1.7. 107 mã mới dùng `license.name` ở 1.6 và `license.id` ở 1.7. Cần đọc trạng thái một phần trong `collection.json`.

## Kiểm tra trên máy biên dịch

Chuẩn bị Go, Python, Docker, bộ nhớ đệm mô-đun và phụ thuộc lược đồ. `trusted_go_sha256` là hàm băm Go đã xác minh độc lập. `GOPROXY=off` dùng bộ nhớ đệm. QA phát hành từ chối `python3 -O` và `PYTHONOPTIMIZE`. Máy đích chạy tệp đóng gói. Trên macOS dùng `shasum -a 256 -c SHA256SUMS`.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Kiểm thử tích hợp

Chạy các lệnh trên bản phát hành cuối đã giải nén. Chuẩn bị dữ liệu trước khi tắt mạng. .NET/Ruby cần SDK .NET 10. Go/Rust cần mô-đun đệm và ELF ripgrep đã cố định, hoặc `--rust-binary`. Fancytree đối chiếu npm SHA-512 hoặc GitHub SHA-256. Các phép thử hỗ trợ `--tracker-root /path/to/tracker` để kiểm tra bộ phân tích Tracker thực.

`domain_bom_integration.py` chạy trực tiếp tệp đích. Hãy chạy phép thử này trên Linux amd64.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

Các phép thử bao gồm Java lồng nhau, pyz/pex, Go/Rust, nguồn cài đặt, ranh giới thư mục, băm nhà cung cấp, PURL và phụ thuộc. Mẫu Linux kiểm tra socket, container, firmware, dịch vụ, cấu hình, toàn vẹn và chứng chỉ. Mẫu AIX kiểm tra Oracle Home, Listener và OPatch. Thiết bị BMC/NIC/OT, lưu trữ Kubernetes thực và máy khách vá có thuê bao cần bằng chứng tại môi trường riêng.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## Nhân Linux và tái hiện VM

Chạy kiểm thử riêng Linux trên Linux. macOS có thể biên dịch chéo theo kiến trúc container. Dùng tệp phát hành cuối cho VM. RHCK `4.18.0-193.el8.x86_64` và UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` khởi động riêng bằng RPM có chữ ký trong `tests/oracle-vm/kernels.json`. Lưu nguồn, nhật ký chữ ký, ID image, log nối tiếp, đường cơ sở và xác minh.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle runner dùng QEMU system TCG, RAM 4 GiB, hai CPU và PID 1 tĩnh riêng, không có mạng/đĩa khách. Kiểm tra uname, proc, nạp loop thực, nhân cài đặt và đang chạy. Ubuntu khởi động `6.8.0-47-generic` bằng gói đã xác thực. GRUB, UEFI/Secure Boot, systemd đầy đủ, SELinux enforcing, driver vật lý và dịch vụ sản xuất cần thử riêng. Container Oracle chia sẻ nhân máy chủ.

[Oracle VM](../tests/oracle-vm/README.vi.md) · [Ubuntu VM](../tests/ubuntu-vm/README.vi.md)

## Lời gọi hệ thống, tài nguyên và phân tích sau đó

Theo dõi tệp cuối trong container cô lập. Nếu mô phỏng ARM64 không giải mã ptrace, `trace-network.sh` trả 77. Có thể dùng QEMU guest syscall với môi trường ghi rõ. Tuyên bố không có lần gọi cần dấu vết hoạt động đúng. Máy khách/daemon do tập lệnh livepatch gọi có hành vi mạng riêng.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

Mặc định là 1,000,000 tệp thường được chọn và 30 phút. Kiểm tra giới hạn, tùy chọn sai, hủy, quyền, dữ liệu hỏng và loại trừ. `--max-files 0 --timeout 0` bỏ hai giới hạn. Ghi thời gian và RSS cực đại của đầu vào thực. Hai tác vụ song song không đặt trần bộ nhớ. Tracker dùng cơ sở dữ liệu tạm cô lập và cả hai định dạng. Thông báo cục bộ phụ thuộc quy tắc và quan sát. Triển khai và khắc phục CVE cần bằng chứng riêng.

## Tài liệu

[Chạy trong mạng cô lập và xem kết quả](air-gapped.vi.md) · [Hướng dẫn biên dịch và kiểm chứng](verification.vi.md) · [Kết quả kiểm chứng](verification-results.vi.md)
