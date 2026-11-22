# Kiểm kê phần cứng và phần mềm

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Dùng tệp thực thi `koda-bom` được biên dịch cho đúng hệ điều hành và CPU của máy đích. Trên Linux, `scan` thu thập các gói và phần cứng của máy chủ. Trên Windows hoặc macOS, `platform-inventory` gọi các công cụ kiểm kê cục bộ do hệ điều hành cung cấp.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

Trong Windows PowerShell, dùng `.\koda-bom.exe platform-inventory --output-dir .\reports`. Trên Linux, khi quét thư mục hoặc ảnh, công cụ đọc hệ thống tệp đã chọn. Thông tin phần cứng đang hoạt động được lấy khi quét `/` trên máy chủ với chế độ ngữ cảnh bật. Với Docker/OCI, công cụ đọc ảnh Linux amd64 đã xuất. Gửi một tài liệu CycloneDX đã xác minh đến Tracker và lưu cả hai phiên bản định dạng cùng các giá trị kiểm tra.

## Bằng chứng thu thập được

| Hạng mục | Cách thu thập và diễn giải |
|---|---|
| Phần cứng | Các trường CPU, vi mã, biện pháp giảm thiểu, bo mạch, BIOS/UEFI, ESRT, PCI và trình điều khiển, NVMe/SCSI, USB, TPM. Nếu hệ thống cung cấp, công cụ đọc RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS và amdgpu `vbios_version`. Phần sụn NIC được đọc qua ioctl chỉ đọc, tương đương `ethtool -i`. megaraid_sas cần bằng chứng xuất riêng. Khi chạy bằng root, bảng SMBIOS gốc cung cấp nhà sản xuất, mã linh kiện, dung lượng và tốc độ của mô-đun bộ nhớ, model và công suất bộ nguồn, khe cắm cùng địa chỉ PCI; số sê-ri chỉ được ghi dưới dạng SHA-256. |
| BMC | Lệnh IPMI chỉ đọc `Get Device ID` qua `/dev/ipmi0` cần quyền root và mô-đun `ipmi_si`/`ipmi_devintf`. Công cụ ghi phiên bản phần sụn, mã nhà sản xuất IANA, mã sản phẩm và phiên bản phụ. Nếu thiếu thiết bị, kết quả ghi rõ lý do. Có thể đối chiếu nhãn bản dựng của nhà sản xuất bằng bản xuất Redfish. |
| Nhận diện CPU | x86 `cpuidSignature` và `familyModelStepping`, sơ đồ socket/lõi, tên nhà sản xuất và lõi ARM cùng phiên bản như `r3p1`. Lõi ARM chưa nhận diện được vẫn giữ mã gốc. USB `bcdDevice` là mã phiên bản thiết bị. |
| Tài sản bên ngoài | Đối tượng Redfish mở rộng, JSON fwupd, JSON devlink và lược đồ chung bên dưới. Phần sụn đang chạy và phần sụn đang lưu được ghi riêng. Trường dữ liệu tùy nhà sản xuất và mẫu thiết bị. |
| Trạng thái lúc chạy | Nhận diện tệp thực thi hoặc thư viện dùng chung đã bị thay thế, định danh tệp và gói sở hữu có thể xác định duy nhất. Trường hợp thay thế ghi `restart_review`. Riêng phiên bản gói đã cài chưa xác nhận được phiên bản còn trong bộ nhớ. |
| Nhận diện máy | SHA-256 của machine-id, DMI UUID và số sê-ri sản phẩm/bo mạch đã chuẩn hóa khi quét `/`, kể cả với `--no-context`. machine-id/UUID được chuyển thành chữ thường, số sê-ri được bỏ khoảng trắng ở hai đầu. Bỏ qua giá trị mẫu dùng chung và UUID toàn số 0. Băm là cách giả danh hóa, giá trị gốc của số sê-ri vẫn có thể đoán được. `--asset-tag` nhận nhãn một dòng tối đa 128 ký tự. Phạm vi trong container là `container-visible`. |
| Socket | TCP LISTEN và UDP chưa kết nối trong không gian tên mạng của công cụ, đối chiếu qua bộ mô tả tệp của tiến trình. `bindScope` nhận `all-interfaces`, `loopback` hoặc `address`. Đánh giá khả năng truy cập qua tường lửa hoặc định tuyến cần bằng chứng riêng. Socket chưa rõ chủ sở hữu được ghi vào `context.json.unattributedSockets`. Kết nối TCP ra ngoài đã thiết lập được ghi theo tiến trình và đích từ xa trong `outboundConnections`, kèm `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`). |
| Bảo mật và khởi động lại | Chế độ SELinux hiện tại và được cấu hình, trạng thái AppArmor cùng số hồ sơ, lockdown, FIPS và các tùy chọn khởi động trong danh sách cho phép. Bỏ qua thông tin xác thực và tham số khởi động ngoài phạm vi. `kernelConfig` ghi `y`/`m` từ `/proc/config.gz` hoặc `/boot/config-<running-kernel>`. Dấu hiệu cần khởi động lại gồm `/run/reboot-required`, thiếu mô-đun của nhân đang chạy hoặc đã cài nhân mới hơn cùng dòng phát hành. Có tín hiệu thì ghi `reboot.recommended=true`, còn lại ghi `not_observed`. Dòng phát hành được ước tính từ chuỗi phiên bản. |
| SSH | Khai báo toàn cục trong `sshd_config` và `sshd_config.d/*.conf`, gồm `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. Bỏ qua khối `Match`. Giá trị thực tế còn tùy thứ tự `Include`. |
| Mô-đun nhân và chương trình chưa rõ nguồn | `kernel.tainted` và `taintedModules` ghi tên, cờ `O`/`E`/`P`, phiên bản và srcversion. `unidentifiedExecutables` ghi đường dẫn/PID của chương trình cùng thư mục gốc chưa gắn được với gói, thành phần hoặc sản phẩm. Các đường dẫn usr-merge được đối chiếu. |
| Tính toàn vẹn | Đối chiếu giá trị băm của tệp thực thi và tệp `.so` với cơ sở dữ liệu RPM/dpkg/apk. Không xét tệp cấu hình và tệp ghost. Các mục `modified`/`missing` nằm trong `collection.json.integrity.findings` và thuộc tính thành phần. Hạn mức băm là 8 GiB mỗi máy chủ và 1 GiB mỗi container. Khi hết hạn mức, trạng thái là `partial`. prelink có thể làm giá trị băm khác nhau. |
| Nguồn gói | Danh sách `Packages` của apt (thô/gz/lz4) được đối chiếu theo tên. Lịch sử dnf và `from_repo` của yum cung cấp ID kho. Các giá trị gồm `repository`, `local-file`, `not-recorded`. Chưa hỗ trợ trường hợp thiếu lịch sử, dnf5 hoặc apk. Không lưu URL kho hay đường dẫn cục bộ. Cơ sở dữ liệu dnf được sao chép vào thư mục tạm và mở chỉ đọc. |
| Dịch vụ khởi động | Dùng `*.wants`/`*.requires` của systemd, khai báo unit/drop-in, `ExecStart` đầu tiên, kích hoạt bằng socket và PURL của gói. Bỏ qua unit bị mask. Trên máy chủ, trạng thái chạy/dừng dựa vào tiến trình trong `system.slice`. Dịch vụ dùng slice tùy chỉnh có thể được ghi là dừng. Timer đã bật ghi lịch `On*` và dịch vụ mà nó khởi động. |
| CPE phần cứng | Hỗ trợ các mẫu Intel Xeon/Core, AMD EPYC/Ryzen, thiết bị và BIOS Dell PowerEdge, thiết bị Lenovo ThinkSystem. Để trống CPE của mẫu chưa nhận diện, HPE hoặc BMC. |
| Chứng thư | Dấu vân tay, thời hạn hiệu lực, thuật toán, kích thước khóa và trạng thái của chứng thư công khai X.509. Dấu hiệu yếu gồm chữ ký SHA-1/MD5, RSA dưới 2048 bit và DSA. Thuật toán cổ điển có `nistQuantumSecurityLevel=0`. Bỏ qua tên chủ thể, tên tổ chức phát hành, khóa riêng, kho tin cậy của bản phân phối và gói chứa hơn 20 chứng thư. Khóa công khai máy chủ SSH (`etc/ssh/ssh_host_*_key.pub`) cũng được ghi cùng dấu vân tay SHA-256 của OpenSSH. |
| Ứng dụng | Phiên bản snap đang hoạt động và gói Debian nhúng, bản flatpak/AppStream đang dùng, siêu dữ liệu conda kèm tên kênh, siêu dữ liệu `.pyz`/`.pex`, JAR, JavaScript tĩnh và thông tin biên dịch Go/Rust. Giữ giá trị băm của tệp OCI/Docker và digest đã xác minh nếu có. |

## Container và đầu ra

Mỗi container đang chạy có bộ kết quả riêng tại `containers/<name>/`. Với Kubernetes, tên gồm namespace, pod và container, thêm 12 ký tự ID nếu trùng. Công cụ đọc siêu dữ liệu Docker, containerd, Podman và CRI-O từ đĩa. Nó dò hệ thống tệp gốc đang gắn qua thông tin thiết bị trong mountinfo và không kết nối tới socket API của runtime. Các lớp ảnh và lớp ghi được đưa vào, volume và bind mount được loại trừ. Socket chỉ được gán cho tiến trình trong container tương ứng. Ưu tiên gói sở hữu, với tệp Go thì dùng mô-đun chính. Nếu thiếu hệ thống tệp gốc hoặc hết thời gian, kết quả ghi `not_collected` cùng lý do. Dùng `--no-containers` để tắt tính năng này.

Đối với container đã dừng và ảnh cục bộ chưa dùng, hỗ trợ Docker overlay2, containerd overlayfs (gồm k3s/RKE2) và bộ nhớ Podman/CRI-O chạy với quyền root. Các lớp được dựng trong thư mục tạm, xử lý whiteout/opaque, kiểm tra xong rồi dọn bỏ. Bỏ qua tệp thiết bị và bit set-ID. Bỏ qua hệ thống gốc lớn hơn 16 GiB hoặc khi dung lượng trống nhỏ hơn kích thước hệ thống gốc cộng 1 GiB. Kết quả ghi `state: stopped` hoặc `state: image` và không có socket đang lắng nghe. Thay đổi đồng thời trong runtime có thể cản trở thu thập. Chưa hỗ trợ trình lưu trữ Docker khác và Podman không dùng quyền root. Dùng `--no-images` để tắt.

Theo mặc định, bảy BOM nằm trong `boms/`, bản hợp nhất nằm ở `bom.cdx.json`. AI-BOM có tên `aibom.cdx.json`. Các đầu ra tương thích gồm CycloneDX 1.6 `sbom.cdx.json` và SPDX 2.3 `sbom.spdx.json`. `--cyclonedx-17` xuất thêm các tệp 1.7. SPDX dùng `OTHER` và chú thích cho kiểu chưa có tương đương. Máy chủ dùng `koda:host:*`, container dùng `koda:container:*`, socket dùng `koda:runtime:listening`/`koda:runtime:bind-scope`. Xem `assets.json`, `context.json`, `collection.json`, `inventory.syft.json` và kiểm tra tệp bằng `SHA256SUMS`.

## Bằng chứng tài sản dạng chung

Cung cấp tối đa tám tệp, mỗi tệp tối đa 8 MiB. `parentId` tham chiếu tới `id` tài sản trong cùng tệp. Bỏ trường phiên bản khi chưa rõ. Redfish cần đối tượng tài sản hoặc phần sụn đã mở rộng ngoài danh sách URI. SHA-256 đầu vào xác định tệp đã nhập.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

## Tài sản mật mã và phiên TLS

Chứng thư X.509, khóa công khai và thuật toán được ghi thành `cryptographic-asset`. Các quan hệ với tổ chức phát hành được kiểm tra chữ ký. Những chỉ thị Nginx/Apache/sshd thuộc danh sách cho phép cung cấp bằng chứng cấu hình. Công cụ ghi chuỗi chứng thư công khai của JKS v1/v2 và SHA-256 của bí danh, bỏ qua khóa đã mã hóa. Khi không dùng mật khẩu, trạng thái toàn vẹn của kho là `not-verified`.

Dùng `--asset-evidence` để nhập siêu dữ liệu công khai của PKCS#12/HSM/KMS. Một mục `related-crypto-material` có thể chứa loại, kích thước, trạng thái khóa, `algorithmRef`, cùng `properties.storageType` và `keyAlias`. `dependsOn` của thành phần sử dụng khóa trỏ tới siêu dữ liệu khóa trong cùng tệp.

Ví dụ sau nhập kết quả thương lượng TLS đã đo độc lập. Thay dấu vân tay, điểm cuối và thời gian mẫu bằng quan sát thực tế. Nếu giá trị băm chứng thư khớp, dịch vụ sẽ liên kết với giao thức rồi đến chứng thư.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## Đối chiếu khuyến cáo ngoại tuyến

Dùng cùng tệp thực thi để đánh giá lại kết quả đã lưu với khuyến cáo mới.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--context` và `--kev` là tùy chọn. Khi dùng ngữ cảnh, cả SBOM và tệp ngữ cảnh được đối chiếu với `SHA256SUMS` của lần thu thập. KEV bổ sung thông tin ưu tiên. Hỗ trợ quy tắc tường minh bên dưới, OSV với phiên bản/PURL bị ảnh hưởng chính xác và CSAF 2.0 với ID sản phẩm chính xác cùng trạng thái vô điều kiện. Nếu gặp khoảng phiên bản hoặc biểu thức điều kiện/tổ hợp sản phẩm không hỗ trợ, việc đánh giá dừng và ghi lý do.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "Verify firmware activation according to the vendor advisory"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Dùng ID bản phân phối tương ứng với bản phát hành và phiên bản gói chính xác. Nếu phiên bản trong SBOM mâu thuẫn với PURL, kết quả là `review_required`. Có xét epoch của RPM. Mỗi lần chạy xử lý đến 1.000.000 mục phiên bản chính xác. Quy tắc tường minh hỗ trợ `supportEndsAt` và `affectedSemver` đối với hệ sinh thái phần mềm được hỗ trợ. Tệp bị thay thế hoặc phần sụn mới được lưu cần xem xét việc kích hoạt. Cần rà soát tài sản chưa rõ hoặc phiên bản ngoài khuyến cáo. Đối chiếu máy Linux/Windows vật lý với danh mục của nhà sản xuất. Kiểm kê gốc trên Windows/macOS tập trung vào hệ điều hành, phần cứng và ứng dụng đã cài.

## Quan sát khả năng kết nối TCP

`--network-evidence` đối chiếu kết quả TCP đã đo với socket OBOM hiện tại hoặc đã lưu của máy chủ. `hostField` nhận `machineIdSha256`, `productUuidSha256` hoặc `assetTag` được gán rõ ràng. `scope` là `host` hoặc ID container đầy đủ gồm 64 ký tự.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

Kết quả gồm `connected`, `refused` và `timed-out`. Nếu chưa rõ chủ sở hữu hoặc không tìm thấy socket, kết quả vẫn chưa ghép được. Mỗi vị trí và thời điểm đo cần bản ghi riêng. Công cụ không tự thăm dò kết nối. [Phạm vi hỗ trợ](support-matrix.vi.md) · [Bằng chứng cho các BOM khác](additional-bom.vi.md)
