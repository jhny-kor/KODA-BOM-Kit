# 採集支持範圍與證據限制

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


本表描述可識別的證據。每次運行請查看 `collection.json` 的狀態與原因。完整性取決於可讀元數據、安裝形式及權限。漏洞判斷需要匹配公告證據。

## 七種CycloneDX BOM

默認主機 `/` 掃描在 `boms/` 生成獨立文件並合併為 `bom.cdx.json`。`--cyclonedx-17` 增加1.7版。證據缺失會明確標記，包括 `no-evidence` 和未知覆蓋範圍。[CycloneDX分類](https://github.com/CycloneDX/specification#readme)

| BOM | 可用證據 | 補充資料 |
|---|---|---|
| SBOM | OS/語言包、版本/PURL、可得許可證/依賴、JAR、內置模塊、容器 | 將供應者/CI CycloneDX或SPDX綁定產物SHA-256，補充靜態/構建依賴，生成 `build-sbom.cdx.json` |
| HBOM | CPU/主板/設備/驅動/固件、EDAC DIMM和電源/風扇、SMBIOS內存模塊（製造商/零件號/速度）、電源和插槽 | 不可見零件、零件號、供應者、生命週期的Redfish或資產台賬 |
| CBOM | 公共證書/密鑰/算法、驗證的簽發關係、TLS/SSH配置、JKS、SSH主機公鑰、系統加密策略、OpenSSL協議/密碼套件/組聲明 | 實測TLS和HSM/KMS/保護密鑰庫的公開導出元數據 |
| OBOM | 主機/容器/進程/文件/包/套接字關係及systemd、每個進程的外部TCP連接目標、systemd定時器、cron任務、防火牆配置聲明 | 同集群Pod/workload/Service/Ingress JSON、部署標籤、主機身份匹配的 `--network-evidence` |
| SaaSBOM | 服務規範/OpenAPI生成 `saasbom.cdx.json`。也讀取OpenAPI YAML及nginx/Apache/HAProxy配置中聲明的後端 | 提供者/目錄/API、外部依賴、認證、信任邊界、分類數據流 |
| AI-BOM | 本地配置、量化/上下文、權重索引、GGUF/safetensors頭/大小、Ollama層。明確產物的完整SHA-256。`aibom.cdx.json`。另觀測ONNX頭、PyTorch pickle導入安全性、Hugging Face模型卡/緩存ref、模型服務器啓動時指定的模型 | 模型身份/修訂/權重、譜系、模型卡/許可證、訓練/評估來源 |
| MBOM | 匹配SLSA或物理組裝/測試聲明生成 `mbom.cdx.json` 的 `formulation` | CI步驟/工具/輸入輸出/執行記錄，製造工藝/檢驗歷史 |

## 各層採集

| 層 | 證據與限制 |
|---|---|
| OS包 | os-release/vendor release及RPM/DEB/APK數據庫。權限、損壞、source package/module stream缺失影響結果 |
| 硬件/固件 | CPU/微碼/CPUID/拓撲/ARM、DMI、BIOS/UEFI/ESRT、PCI、NVMe/SCSI、USB、TPM。RAID/HBA、RDMA、GPU VBIOS、NIC ioctl字段依驅動而變。megaraid_sas需導出，BMC需root/IPMI及廠商版本核對。VM/容器可能顯示物理主機信息 |
| 外部設備 | 展開Redfish、fwupd、devlink、通用JSON。保留報告的版本/狀態，復核未匹配項 |
| Windows/macOS | 系統/OS/固件/應用元數據。Windows驗證包括交叉構建。應用內部依賴和廠商更新需額外輸入 |
| 運行軟件 | 同文件系統範圍內的可執行文件/映射庫與包歸屬。替換提供重啓復核依據 |
| 主機身份 | 主機 `/` 的machine-id/DMI UUID/序列號SHA-256和顯式標籤。序列號權限及公共默認值影響可用性。哈希是化名化 |
| 監聽套接字 | 同命名空間TCP LISTEN/綁定UDP和進程FD。僅綁定無法確認防火牆可達性，無歸屬項為 `unattributedSockets` |
| 外部連接 | 按進程和遠程端點彙總本地端口不是監聽端口的ESTABLISHED TCP，最多16,384個套接字。從固定本地端口連向對方臨時端口的連接視為已接受的連接。只看到採集時打開的連接，僅限主機進程。連接到本主機監聽端口的連接會關聯到該監聽套接字及其所屬進程 |
| 計劃任務 | `/etc/crontab`、`/etc/cron.d`、用戶crontab、`cron.{hourly,daily,weekly,monthly}` 腳本，以及已啓用systemd定時器的 `On*` 計劃。只記錄程序絕對路徑，丟棄參數 |
| 防火牆 | iptables-save文件（RHEL/Debian/ufw）、firewalld默認區域及其服務定義、nftables input hook鏈和字面include。這些是文件聲明，不讀取內核已加載的規則。沒有policy的base chain視為接受，`ENABLED=no` 的ufw記為 `disabled`，systemd單元已安裝但既未啟用也未運行或已被屏蔽的框架記為 `not-enabled`，兩者都不視為生效。僅環回、已建立狀態和否定規則不視為開放端口，協議範圍的TCP/UDP接受視為開放該協議全部端口。主機網絡命名空間中的非環回監聽套接字帶有 `firewall-declared`：`accept-declared`、`accept-declared-restricted`、`policy-accept-declared`、`no-accept-declared`、`undetermined`，未讀取到有效聲明時為 `none-observed`。容器套接字位於各自的網絡命名空間，不帶此值。容器通過NAT發布的端口經過FORWARD規則，不予評估 |
| 設置/重啓 | SELinux、AppArmor、lockdown、FIPS、允許啓動參數、內核 `y`/`m`、重啓請求、運行模塊、較新同系列內核。需解釋觀察結果，無信號不足以證明無需重啓 |
| SSH | 全局配置聲明，排除 `Match`，不計算 `Include` 生效優先級 |
| taint/模塊 | `kernel.tainted`、`/proc/modules` 標誌和sysfs version/srcversion |
| 未知可執行文件 | 同root內無包/組件/產品歸屬的運行文件。排除其他掛載命名空間，分類需進一步調查 |
| 包來源 | apt平文/gz/lz4、dnf歷史、yumdb。apt按名稱。刪除清單、dnf5、apk不支持。省略URL/路徑 |
| 啓動服務 | systemd wants/requires、unit/drop-in、cgroup v1/v2。只取首個ExecStart，相對路徑不關聯包，自定義slice可能顯示停止。SysV不支持。已啓用的定時器記錄 `On*` 計劃和其啓動的服務 |
| 硬件CPE | Intel Xeon/Core、AMD EPYC/Ryzen、Dell PowerEdge設備/BIOS、Lenovo ThinkSystem設備。字典/型號缺失可導致不匹配。省略HPE/BMC |
| 包完整性 | RPM/dpkg/apk可執行文件/庫哈希，排除配置/ghost。主機8 GiB、容器1 GiB。prelink可能產生誤報 |
| CBOM/證書 | PEM/DER、公鑰/算法、JKS v1/v2公開鏈/別名哈希。跳過加密密鑰，JKS完整性未驗證。排除主體/簽發者名、私鑰、PKCS#12內容、發行版信任庫及超過20證書的文件。另記錄SSH主機公鑰。`crypto-policies` 和 `openssl.cnf` 的MinProtocol/CipherString/Ciphersuites/Groups作為聲明記錄，不解析 `.include` 和節的啓用 |
| 內核 | uname、安裝鏡像/模塊、vermagic、RPM版。區分運行與已安裝內核，未見模塊可能因為功能內置 |
| 熱補丁 | livepatch sysfs、Oracle raw Ksplice、可選Ksplice/Uptrack/Canonical helper。啓動/內核/時間不匹配的證據不能證明生效。CVE需單獨分析 |
| Java | JDK/JRE release、JAR/WAR/EAR manifest和Maven。shaded元數據被刪改時只能部分識別 |
| PHP | 包/解釋器、已安裝Composer/PEAR。排除僅lock中未安裝項，可利用性依賴配置 |
| snap/flatpak/conda | snap current及內置DEB、flatpak active/AppStream、conda-meta。snap/flatpak使用generic PURL，無AppStream時版本為空，conda只記渠道名 |
| Python | dist-info/egg-info、venv、`.pyz`/`.pex` 實際元數據。刪除或不可讀會限制採集 |
| Node.js/靜態JS | node_modules/runtime，文件和EAR/WAR/ZIP/JAR中jQuery/jQuery UI/Fancytree。文件名不足以定版本，依賴支持佈局和掃描上限 |
| Go/Rust | Go構建信息和cargo-auditable ELF。缺失信息則依賴未知，損壞/超限為部分採集 |
| .NET | `.deps.json`、托管DLL及獨立DLL版本。獨立DLL不發NuGet PURL，single-file需額外驗證 |
| Ruby | 已安裝specifications/gem及default gem。僅Gemfile.lock或元數據被刪時證據不足 |
| 原生服務器 | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB包/二進制。定制、strip、靜態副本可能未知 |
| Java服務器 | Tomcat ServerInfo/manifest/catalina.jar，WebLogic/JBoss/WildFly安裝/補丁。僅 `.patch_storage` 不能證明補丁生效。無真實fixture的JEUS等標為未驗證 |
| 停止容器/鏡像 | Docker overlay2、containerd overlayfs/k3s/RKE2、rootful Podman/CRI-O。臨時重建上限16 GiB/root並檢查空間。其他驅動/rootless不支持，無監聽套接字 |
| 運行容器 | procfs root及磁盤狀態，`containers/<name>/` 獨立SBOM。排除volume/bind mount及Kubernetes sandbox。不可見root記錄原因，不連接API，只歸屬本容器進程套接字 |
| 鏡像歸檔 | 明確Linux amd64 Docker/OCI tar、歸檔哈希、驗證manifest digest。範圍是鏡像內容，主機內核/運行狀態需另觀察 |
| AIX/Oracle | `aix-import` fileset、臨時修復、各Home OPatch及可選SQL歷史。單AIX最多8 Home，執行狀態需額外證據 |

手動安裝保留目錄/實例身份。同名同版本也可能有不同位置或補丁狀態。無法確定的CPE留空，後續審核使用確定的標識和證據。

默認格式是CycloneDX 1.6和SPDX 2.3，可增加CycloneDX 1.7。[資產清單與評估](asset-inventory.zh-hant.md) 說明 `assess`、精確版本OSV/CSAF及證據格式。[補充BOM證據](additional-bom.zh-hant.md) 涵蓋服務、模型和製造。

## 回歸驗證場景

覆蓋PHP與Composer、Node運行時與node_modules、完整JDK構建、WebLogic安裝/補丁、手工Tomcat與AJP/HTTP2、httpd/mod_http2發行包、nginx來源/alias/rewrite、OpenSSL CLI/libssl/libcrypto獨立副本、運行與安裝UEK/RHCK內核。回歸樣本檢驗識別證據，漏洞結論還需要公告匹配。
