# Phạm vi thu thập và giới hạn của bằng chứng

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Bảng này mô tả các bằng chứng có thể nhận diện. Kiểm tra trạng thái và lý do trong `collection.json` của từng lần chạy. Độ đầy đủ phụ thuộc vào siêu dữ liệu đọc được, cách cài đặt và quyền truy cập. Đánh giá lỗ hổng cần khuyến cáo phù hợp với những gì đã quan sát.

## Bảy loại BOM theo CycloneDX

Quét `/` với thiết lập mặc định tạo các tài liệu riêng trong `boms/` và bản hợp nhất `bom.cdx.json`. `--cyclonedx-17` xuất thêm phiên bản 1.7. Miền không hỗ trợ hoặc không có bằng chứng được ghi trạng thái rõ ràng, trong đó có `no-evidence` và độ bao phủ chưa rõ. [Các loại BOM theo CycloneDX](https://github.com/CycloneDX/specification#readme)

| BOM | Bằng chứng hiện có | Bằng chứng bổ sung |
|---|---|---|
| SBOM | Gói hệ điều hành và hệ sinh thái ngôn ngữ, phiên bản/PURL, giấy phép và quan hệ có sẵn, JAR, mô-đun nhúng, container | CycloneDX hoặc SPDX do nhà cung cấp/CI cấp, khớp SHA-256 sản phẩm, để bổ sung phụ thuộc tĩnh hoặc lúc biên dịch vào `build-sbom.cdx.json` |
| HBOM | CPU, bo mạch, thiết bị, trình điều khiển, phần sụn, DIMM EDAC và cảm biến nguồn/quạt, mô-đun bộ nhớ SMBIOS (nhà sản xuất, mã linh kiện, tốc độ), bộ nguồn và khe cắm | Dữ liệu Redfish hoặc sổ tài sản cho linh kiện không quan sát được, mã linh kiện, nhà cung cấp và vòng đời |
| CBOM | Chứng thư, khóa công khai, thuật toán, quan hệ phát hành đã kiểm chữ ký, cấu hình TLS/SSH và siêu dữ liệu JKS, khóa công khai máy chủ SSH, chính sách mật mã hệ thống và khai báo giao thức, bộ mã, nhóm khóa của OpenSSL | Kết quả đo thương lượng TLS và siêu dữ liệu công khai xuất từ HSM/KMS hoặc kho khóa được bảo vệ |
| OBOM | Quan hệ giữa máy chủ, container, tiến trình, tệp thực thi, gói và socket, trạng thái kích hoạt của systemd, đích kết nối TCP ra ngoài theo tiến trình, timer systemd, tác vụ cron và quy tắc tường lửa được khai báo | JSON Kubernetes cùng cụm cho Pod/workload/Service/Ingress, nhãn triển khai và `--network-evidence` khớp máy chủ |
| SaaSBOM | Đặc tả dịch vụ/OpenAPI tạo `saasbom.cdx.json`. Đồng thời đọc OpenAPI YAML và backend khai báo trong cấu hình nginx, Apache, HAProxy | Bằng chứng từ nhà cung cấp, danh mục hoặc API, quan hệ bên ngoài, xác thực, ranh giới tin cậy và phân loại luồng dữ liệu |
| AI-BOM | Cấu hình cục bộ, lượng tử hóa và ngữ cảnh, chỉ mục trọng số, phần đầu/kích thước GGUF và safetensors, lớp Ollama. Tệp chỉ định tường minh được tính SHA-256 toàn tệp. Kết quả là `aibom.cdx.json`. Ngoài ra còn phần đầu ONNX, mức an toàn import pickle của PyTorch, thẻ mô hình và ref bộ đệm Hugging Face, mô hình mà máy chủ mô hình chỉ định khi khởi động | Định danh, phiên bản, trọng số, phả hệ mô hình, thẻ mô hình, giấy phép, nguồn dữ liệu huấn luyện và đánh giá |
| MBOM | Nguồn gốc SLSA khớp sản phẩm hoặc lắp ráp/kiểm thử vật lý theo khai báo hay báo cáo, ghi vào `formulation` trong `mbom.cdx.json` | Các bước, công cụ, đầu vào, đầu ra và hồ sơ thực thi của CI hoặc lịch sử lắp ráp, sản xuất và kiểm tra của nhà sản xuất |

## Các lớp thu thập

| Lớp | Bằng chứng và giới hạn |
|---|---|
| Gói hệ điều hành | os-release hoặc tệp phiên bản của nhà cung cấp và cơ sở dữ liệu RPM/DEB/APK. Quyền truy cập, dữ liệu hỏng, thiếu gói nguồn hoặc luồng mô-đun có thể làm kết quả không đầy đủ. |
| Phần cứng/phần sụn | CPU, vi mã, CPUID, cấu trúc tô-pô, định danh ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB và TPM. Các trường RAID/HBA, RDMA, VBIOS GPU và ioctl của NIC tùy trình điều khiển. megaraid_sas cần dữ liệu xuất riêng. BMC IPMI cần quyền root, mô-đun và đối chiếu phiên bản của nhà sản xuất. Thiết bị thấy từ máy ảo/container có thể thuộc máy vật lý. |
| Tài sản bên ngoài | Đối tượng Redfish mở rộng, fwupd, devlink hoặc JSON dạng chung. Giữ phiên bản và trạng thái đã báo cáo, rà soát thiết bị chưa đối chiếu được. |
| Windows/macOS | Siêu dữ liệu gốc về hệ thống, hệ điều hành, phần sụn và ứng dụng đã cài. Bằng chứng Windows có kiểm tra biên dịch chéo. Phụ thuộc bên trong ứng dụng và bản cập nhật từ nhà sản xuất cần đầu vào bổ sung. |
| Phần mềm đang chạy | Định danh tệp thực thi, thư viện đang ánh xạ và gói sở hữu trong cùng phạm vi hệ thống tệp. Tệp đã thay thế là căn cứ để xem xét khởi động lại. |
| Định danh máy | SHA-256 của machine-id, DMI UUID/số sê-ri cùng nhãn tài sản chỉ định khi quét `/`. Quyền đọc sê-ri và giá trị mẫu dùng chung có thể làm thiếu dữ liệu. Băm là một hình thức giả danh hóa. |
| Socket lắng nghe | TCP LISTEN hoặc UDP đã bind trong không gian tên của công cụ, gán qua bộ mô tả tệp của tiến trình. Địa chỉ bind riêng lẻ chưa xác định khả năng truy cập qua tường lửa. Socket chưa rõ chủ nằm trong `unattributedSockets`. |
| Kết nối ra ngoài | TCP ESTABLISHED có cổng cục bộ không phải cổng lắng nghe, gộp theo tiến trình và đích từ xa, tối đa 16.384 socket. Kết nối từ cổng cục bộ cố định tới cổng tạm của đối phương được coi là kết nối đã chấp nhận. Chỉ thấy kết nối đang mở lúc thu thập. Chỉ áp dụng cho tiến trình của máy chủ. Kết nối tới cổng mà máy chủ này đang lắng nghe được liên kết với socket lắng nghe đó và tiến trình sở hữu. |
| Tác vụ định kỳ | `/etc/crontab`, `/etc/cron.d`, crontab người dùng và script trong `cron.{hourly,daily,weekly,monthly}`, cùng timer systemd đã bật với lịch `On*`. Chỉ giữ đường dẫn tuyệt đối của chương trình, bỏ các tham số. |
| Tường lửa | Tệp iptables-save (RHEL, Debian, ufw), vùng mặc định của firewalld cùng định nghĩa dịch vụ, chuỗi nftables có hook input và include dạng chuỗi cố định. Đây là khai báo trong tệp, không đọc bộ quy tắc đã nạp vào nhân. Base chain không có policy được coi là chấp nhận; ufw có `ENABLED=no` được ghi là `disabled`, còn framework có unit systemd đã cài nhưng không được bật cũng không chạy, hoặc bị mask, được ghi là `not-enabled`; cả hai đều không được coi là đang hoạt động. Quy tắc chỉ cho loopback, theo trạng thái đã thiết lập hoặc có phủ định không được coi là cổng mở; chấp nhận TCP/UDP cho cả giao thức nghĩa là mở mọi cổng của giao thức đó. Socket lắng nghe không thuộc loopback trong không gian tên mạng của máy chủ có `firewall-declared`: `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined` hoặc `none-observed` khi không đọc được khai báo nào đang hoạt động. Socket của container nằm trong không gian tên mạng riêng nên không có giá trị này. Cổng mà container công bố qua NAT đi qua quy tắc FORWARD, vốn không được đánh giá. |
| Cấu hình/khởi động lại | SELinux, AppArmor, lockdown, FIPS, tùy chọn khởi động được phép, cấu hình nhân `y`/`m`, tín hiệu reboot-required, cây mô-đun của nhân đang chạy và nhân mới hơn cùng dòng. Phải diễn giải các quan sát này. Thiếu tín hiệu không chứng minh máy không cần khởi động lại. |
| SSH | Khai báo toàn cục trong tệp cấu hình sshd. Bỏ qua `Match` và không tính thứ tự ưu tiên thực của `Include`. |
| Trạng thái taint và mô-đun | `kernel.tainted`, cờ trong `/proc/modules`, phiên bản và srcversion từ sysfs khi có. |
| Tệp thực thi không rõ nguồn | Tệp đang chạy trong cùng thư mục gốc nhưng chưa gắn được với gói, thành phần hoặc sản phẩm. Không xét không gian tên mount khác. Việc phân loại cần điều tra thêm. |
| Nguồn gói | apt Packages thô/gz/lz4, lịch sử dnf và yumdb. apt đối chiếu theo tên. Không hỗ trợ danh sách đã xóa, dnf5 và apk. Không lưu URL hay đường dẫn cục bộ. |
| Dịch vụ khởi động | Quan hệ wants/requires của systemd, unit/drop-in và cgroup v1/v2. Chỉ xét ExecStart đầu tiên. Đường dẫn tệp thực thi tương đối không được gắn với gói. Slice tùy chỉnh có thể hiển thị là dừng. Chưa hỗ trợ SysV. Timer đã bật ghi lịch `On*` và dịch vụ mà nó khởi động. |
| CPE phần cứng | Intel Xeon/Core, AMD EPYC/Ryzen, thiết bị và BIOS Dell PowerEdge, thiết bị Lenovo ThinkSystem nằm trong mẫu hỗ trợ. Thiếu mục từ điển hoặc mẫu có thể khiến việc đối chiếu thất bại. Bỏ trống CPE HPE/BMC. |
| Toàn vẹn gói | Giá trị băm của tệp thực thi và thư viện trong cơ sở dữ liệu RPM/dpkg/apk. Bỏ qua tệp cấu hình và tệp ghost. Hạn mức 8 GiB mỗi máy và 1 GiB mỗi container. prelink có thể gây sai lệch giả. |
| CBOM/chứng thư | X.509 dạng PEM/DER, khóa công khai, thuật toán, chuỗi công khai JKS v1/v2 và băm bí danh. Bỏ qua nội dung khóa được mã hóa, chưa xác minh toàn vẹn JKS. Không thu tên chủ thể/tổ chức phát hành, khóa riêng, nội dung PKCS#12, kho tin cậy của bản phân phối và gói hơn 20 chứng thư. Có ghi khóa công khai máy chủ SSH. `crypto-policies` và MinProtocol/CipherString/Ciphersuites/Groups trong `openssl.cnf` được ghi dưới dạng khai báo, không phân giải `.include` và việc kích hoạt section. |
| Nhân | uname, ảnh và mô-đun đã cài, vermagic, phiên bản RPM. Phân biệt nhân đang chạy với nhân đã cài. Tính năng tích hợp trong nhân có thể không để lại bằng chứng mô-đun riêng. |
| Vá nóng | Linux livepatch sysfs, stage của Oracle raw Ksplice và báo cáo tùy chọn từ Ksplice/Uptrack/Canonical. Bằng chứng áp dụng mất hiệu lực khi sai lần khởi động, nhân hoặc thời gian. Việc xác định CVE có áp dụng hay không cần phân tích riêng. |
| Java | Tệp release của JDK/JRE, manifest JAR/WAR/EAR và siêu dữ liệu Maven. Siêu dữ liệu của thư viện được đóng gói lại có thể đã bị sửa hoặc loại bỏ, làm hạn chế nhận diện. |
| PHP | Gói hoặc trình thông dịch, bằng chứng Composer và PEAR đã cài. Bỏ qua gói chỉ có trong tệp khóa. Khả năng bị khai thác tùy cấu hình. |
| snap/flatpak/conda | Phiên bản snap hiện hành, siêu dữ liệu và DEB nhúng, flatpak đang hoạt động/AppStream và conda-meta. Dùng PURL chung cho snap/flatpak, thiếu phiên bản nếu không có AppStream và chỉ ghi tên kênh conda. |
| Python | dist-info/egg-info, venv và siêu dữ liệu thật trong `.pyz`/`.pex`. Dữ liệu bị xóa hoặc không đọc được làm giới hạn kết quả. |
| Node.js/JavaScript tĩnh | node_modules, runtime, dấu hiệu jQuery/jQuery UI/Fancytree trong tệp và tài nguyên web EAR/WAR/ZIP/JAR. Chỉ tên tệp là chưa đủ. Áp dụng giới hạn quét và các cấu trúc được hỗ trợ. |
| Go/Rust | Thông tin bản dựng Go và phụ thuộc cargo-auditable của ELF. Thiếu dữ liệu thì phụ thuộc vẫn chưa rõ. Siêu dữ liệu hỏng hoặc vượt giới hạn sinh kết quả một phần. |
| .NET | `.deps.json` đã phát hành, DLL được quản lý và tài nguyên phiên bản của DLL độc lập. DLL độc lập không có PURL NuGet. Bản phát hành một tệp cần kiểm chứng thêm. |
| Ruby | Tệp gemspec/gem đã cài và gem mặc định. Chỉ có Gemfile.lock hoặc siêu dữ liệu cài đặt đã bị xóa thì chưa đủ căn cứ. |
| Phần mềm máy chủ gốc | Bằng chứng gói hoặc tệp thực thi của httpd, nginx, OpenSSL, OpenSSH, Redis, PostgreSQL, MySQL và MariaDB. Bản tùy chỉnh, bỏ ký hiệu hoặc liên kết tĩnh có thể chưa xác định được. |
| Máy chủ Java | Tomcat ServerInfo/manifest/catalina.jar và siêu dữ liệu sản phẩm, cài đặt, bản vá WebLogic/JBoss/WildFly. Riêng `.patch_storage` chưa xác nhận bản vá đang có hiệu lực. Các bản JEUS/thương mại thiếu mẫu thực tế vẫn chưa được xác minh. |
| Container đã dừng và ảnh | Docker overlay2, containerd overlayfs kể cả k3s/RKE2 và overlay Podman/CRI-O dùng quyền root. Dựng tạm tối đa 16 GiB mỗi hệ thống gốc và có kiểm tra dung lượng trống. Không hỗ trợ driver khác hay Podman không dùng quyền root. Không có socket lắng nghe. |
| Container đang chạy | Hệ thống gốc từ procfs, siêu dữ liệu runtime trên đĩa, SBOM riêng trong `containers/<name>/`. Bỏ qua volume, bind mount và sandbox Kubernetes. Có lý do khi không thấy hệ thống gốc. Không kết nối API/socket của runtime. Chỉ gán các socket thuộc tiến trình của container đó. |
| Kho ảnh đã xuất | Tệp tar Docker/OCI Linux amd64 được chọn, giá trị băm của tệp và digest manifest theo định dạng được hỗ trợ khi đã xác minh. Phạm vi là nội dung ảnh. Nhân và runtime của máy chủ cần quan sát riêng. |
| AIX/Oracle | `aix-import` ghi fileset, bản sửa tạm thời, OPatch theo Home và lịch sử bản vá SQL tùy chọn của tối đa tám Home trên cùng máy AIX. Trạng thái đang chạy cần bằng chứng riêng. |

Cài đặt thủ công giữ định danh thư mục và từng bản cài. Dù trùng tên và phiên bản, chúng có thể ở vị trí hoặc trạng thái bản vá khác nhau. Để trống CPE khi chưa xác định được. Dùng định danh đã xác nhận và bằng chứng đi kèm cho bước rà soát tiếp theo.

Định dạng mặc định là CycloneDX 1.6 và SPDX 2.3, tùy chọn thêm CycloneDX 1.7. Hướng dẫn kiểm kê giải thích `assess`, OSV/CSAF theo phiên bản chính xác và các lược đồ bằng chứng. Hướng dẫn BOM bổ sung mô tả dịch vụ, mô hình và sản xuất. [Kiểm kê và đánh giá tài sản](asset-inventory.vi.md) · [Bằng chứng BOM bổ sung](additional-bom.vi.md)

## Kịch bản kiểm thử hồi quy

Các ca thử phân biệt PHP runtime với Composer, Node runtime với node_modules, kiểm tra bản dựng JDK đầy đủ, danh tính bản cài/bản vá WebLogic, Tomcat cài tay và khai báo AJP/HTTP2, bản phân phối httpd/mod_http2, khai báo nguồn/alias/rewrite của nginx, các bản OpenSSL CLI/libssl/libcrypto độc lập, cùng nhân UEK/RHCK đang chạy và đã cài. Dữ liệu thử cung cấp bằng chứng nhận diện. Kết luận lỗ hổng cần khuyến cáo khớp với bằng chứng đó.
