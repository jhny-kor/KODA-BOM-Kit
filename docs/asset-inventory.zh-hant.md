# 硬件與軟件資產清單

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


使用為目標OS和CPU構建的 `koda-bom`。Linux的 `scan` 採集包和主機硬件。Windows/macOS的 `platform-inventory` 調用操作系統提供的本地清單工具。

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

Windows PowerShell使用 `.\koda-bom.exe platform-inventory --output-dir .\reports`。Linux目錄/鏡像掃描以指定文件系統為範圍。運行硬件在啓用上下文的主機 `/` 採集中觀察。Docker/OCI歸檔支持Linux amd64鏡像。將驗證後的CycloneDX文檔導入Tracker，並共同保存兩個版本及校驗和。

## 採集的證據

| 領域 | 內容及解釋 |
|---|---|
| 硬件 | CPU/微碼、緩解措施、主板、BIOS/UEFI、ESRT、PCI/驅動、NVMe/SCSI、USB和TPM。讀取公開的RAID/HBA `mpt3sas`、`qla2xxx`、`lpfc`、`hpsa`、`smartpqi`，RDMA `fw_ver`，NVIDIA Video BIOS，amdgpu `vbios_version`。NIC使用相當於 `ethtool -i` 的只讀ioctl。megaraid_sas需要導出證據。以root運行時，從SMBIOS原始表讀取內存模塊的製造商、零件號、容量和速度，電源型號和額定功率，以及系統插槽及其PCI地址；序列號僅記錄SHA-256 |
| BMC | 通過 `/dev/ipmi0` 的只讀IPMI `Get Device ID`，需要root及 `ipmi_si`/`ipmi_devintf`。記錄固件修訂、IANA製造商、產品ID和輔助修訂。缺失設備給出原因，需要時用Redfish核對廠商構建標籤 |
| CPU標識 | x86 `cpuidSignature`、`familyModelStepping`、插槽/核心拓撲，ARM廠商/核心名及 `r3p1` 類修訂。未知ARM保留原始標識。USB `bcdDevice` 保持設備發行標識含義 |
| 外部資產 | 展開的Redfish對象、fwupd、devlink JSON和下方通用格式。運行/存儲固件分別保留，字段取決於廠商型號 |
| 運行狀態 | 可執行文件/共享庫替換、文件標識和唯一識別的歸屬包。替換產生 `restart_review`，已安裝版本不足以確定內存版本 |
| 主機身份 | 主機 `/` 上machine-id和DMI UUID/產品/主板序列號的規範化SHA-256，`--no-context` 時也採集。machine-id/UUID轉小寫，序列號去首尾空格。公共默認值和全零UUID省略。哈希屬於可能被猜測的假名化。`--asset-tag` 原樣記錄最多128字符的單行標籤。容器範圍為 `container-visible` |
| 套接字 | 採集器網絡命名空間內TCP LISTEN和未連接UDP，通過進程FD歸屬。`bindScope` 為 `all-interfaces`、`loopback`、`address`。防火牆/路由可達性需另外證據。無歸屬項寫入 `context.json.unattributedSockets`。主機進程已建立的外部TCP連接按進程和遠程端點記錄在 `outboundConnections`，並帶 `remoteScope`（`loopback`、`private`、`link-local`、`public`） |
| 安全與重啓 | SELinux當前/配置模式、AppArmor啓用/配置數量、lockdown、FIPS、允許的啓動參數。排除憑據和無關參數。`kernelConfig` 讀取 `/proc/config.gz` 或 `/boot/config-<running-kernel>` 的 `y`/`m`。重啓請求、運行內核模塊缺失、同系列較新內核作為信號，有信號則 `reboot.recommended=true`，否則 `not_observed`。系列匹配基於發行字符串推斷 |
| SSH | `sshd_config` 與 `sshd_config.d/*.conf` 全局聲明，包括 `PermitRootLogin`、`PasswordAuthentication`、`PermitEmptyPasswords`、`KbdInteractiveAuthentication`、`LoginGraceTime`、`MaxStartups`、`X11Forwarding`、`AllowTcpForwarding`。排除 `Match`，生效值取決於 `Include` 順序 |
| 模塊與未知程序 | `kernel.tainted` 和 `taintedModules` 記錄名稱、`O`/`E`/`P`、version/srcversion。同一root且無包/組件/產品歸屬的程序寫入 `unidentifiedExecutables` 路徑/PID。考慮usr-merge路徑 |
| 完整性 | 比較RPM/dpkg/apk數據庫哈希與可執行文件/`.so`。排除配置和ghost。`modified`/`missing` 記錄於 `collection.json.integrity.findings` 和組件屬性。主機預算8 GiB、每容器1 GiB，用盡標記 `partial`。prelink可能造成差異 |
| 包來源 | apt Packages平文/gz/lz4按名稱匹配，dnf歷史和yum `from_repo` 提供倉庫ID。分類為 `repository`、`local-file`、`not-recorded`。缺少歷史、dnf5、apk不支持。省略倉庫URL/本地路徑，dnf DB複製到臨時目錄只讀打開 |
| 啓動服務 | systemd wants/requires、unit/drop-in、首個 `ExecStart`、socket激活、包PURL。排除被屏蔽unit，主機以 `system.slice` 進程判斷運行。自定義slice可能顯示停止。已啓用的定時器記錄 `On*` 計劃和其啓動的服務 |
| 硬件CPE | 支持Intel Xeon/Core、AMD EPYC/Ryzen、Dell PowerEdge設備/BIOS、Lenovo ThinkSystem設備模式。未知型號、HPE、BMC不猜測CPE |
| 證書 | 公共X.509指紋、有效期、算法、密鑰長度、狀態。弱項包括SHA-1/MD5、低於2048位RSA、DSA。經典算法 `nistQuantumSecurityLevel=0`。排除主體/簽發者名稱與私鑰，跳過發行版信任庫及超過20證書的文件。另記錄SSH主機公鑰（`etc/ssh/ssh_host_*_key.pub`）及其OpenSSH SHA-256指紋 |
| 應用 | 當前snap及內置DEB、active flatpak/AppStream、conda渠道名、`.pyz`/`.pex`、JAR、靜態JS、Go/Rust。保留Docker/OCI產物哈希和可驗證摘要 |

## 容器與輸出

運行容器分別寫入 `containers/<name>/`。Kubernetes使用namespace、pod、container，重名時增加ID前12位。讀取Docker/containerd/Podman/CRI-O磁盤元數據，不連接運行時API。通過mountinfo設備號定位root，包含鏡像/寫層，排除volume/bind mount。套接字歸屬本容器進程，包所有權優先，Go使用main module。不可見root/超時記錄帶原因的 `not_collected`。`--no-containers` 禁用該採集。

停止容器和未使用本地鏡像支持Docker overlay2、containerd overlayfs（含k3s/RKE2）、rootful Podman/CRI-O。複製到輸出臨時目錄，應用whiteout/opaque後採集並刪除副本。排除設備文件和set-ID位。root超過16 GiB或可用空間小於root大小+1 GiB則跳過。結果為 `state: stopped` 或 `state: image`，不包含監聽套接字。併發變化可能導致採集失敗。其他Docker驅動和rootless Podman不支持。`--no-images` 禁用該路徑。

默認在 `boms/` 生成7種BOM並合併為 `bom.cdx.json`。AI-BOM使用 `aibom.cdx.json`。兼容輸出為CycloneDX 1.6 `sbom.cdx.json` 和SPDX 2.3 `sbom.spdx.json`，`--cyclonedx-17` 增加1.7文件。SPDX缺少專用類型時使用 `OTHER` 和注釋。主機身份為 `koda:host:*`，容器為 `koda:container:*`，套接字為 `koda:runtime:listening`/`koda:runtime:bind-scope`。檢查 `assets.json`、`context.json`、`collection.json`、`inventory.syft.json`，使用 `SHA256SUMS` 驗證。

## 通用資產證據

最多8個文件，每個8 MiB。`parentId` 引用同文件 `id`，未知版本省略。Redfish需要展開URI列表後的設備/固件對象。輸入SHA-256標識導入文件。

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

## 密碼資產與TLS會話

X.509、公開密鑰、算法生成 `cryptographic-asset`。候選簽發者關係會驗證簽名。Nginx/Apache/sshd允許指令記錄配置證據。JKS v1/v2記錄公開證書鏈和別名SHA-256，跳過加密密鑰，無密碼完整性為 `not-verified`。

通過 `--asset-evidence` 導入PKCS#12/HSM/KMS公開元數據。`related-crypto-material` 可包含密鑰類型/大小/狀態、`algorithmRef`，以及 `properties.storageType` 和 `keyAlias`。使用方 `dependsOn` 指向同文件的密鑰元數據。

以下為獨立測量的TLS協商示例。以實測指紋、端點和時間替換示例值。證書哈希一致時建立服務→協議→證書關係。

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

## 離線安全公告評估

用同一程序及新公告重新評估存檔結果。

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--context`、`--kev` 可選。使用context時對照本次 `SHA256SUMS` 驗證SBOM和上下文。KEV提供優先級信息。支持下方顯式規則、精確受影響版本/PURL的OSV、精確產品ID/無條件狀態的CSAF 2.0。未支持的範圍、條件或產品組合會停止並說明原因。

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

使用包含發行版本的distro ID和精確包版本。SBOM/PURL版本衝突為 `review_required`，考慮RPM epoch。每次最多1,000,000條精確版本。顯式規則支持 `supportEndsAt` 和受支持生態的 `affectedSemver`。替換文件/存儲固件需要激活復核，未知設備/公告外版本需人工審查。物理Linux和Windows設備須核對廠商清單。Windows/macOS原生採集主要覆蓋OS、硬件、已安裝應用。

## TCP可達性觀察

`--network-evidence` 將已有TCP測量與主機或存檔OBOM套接字匹配。`hostField` 為 `machineIdSha256`、`productUuidSha256` 或明確分配的 `assetTag`。`scope` 為 `host` 或完整64位容器ID。

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

結果支持 `connected`、`refused`、`timed-out`。歸屬不明確或套接字不存在時保留為未匹配。每個測量位置和時間需要獨立觀察。採集器不主動探測連接。[支持矩陣](support-matrix.zh-hant.md) · [補充BOM證據](additional-bom.zh-hant.md)
