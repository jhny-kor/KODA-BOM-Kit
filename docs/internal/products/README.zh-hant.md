# 產品證據收集器

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 的 `Collect(context.Context, root string, paths []string)` 接收通過預先檢查的一般檔案相對路徑清單。它不會探索檔案、執行已安裝程式、解壓縮封存檔、連線伺服器或讀取環境與設定中的機密。`os.OpenRoot` 限制路徑解析，絕對路徑及含父目錄跳轉的輸入會被拒絕。檔案內容和封存中繼資料的讀取皆有上限。路徑清單為空時不進行檔案探索。

## 認可的靜態證據

- JDK/JRE `release` 檔案中允許的版本、執行階段、組建、廠商和架構欄位。
- Tomcat `catalina.jar` 中 `ServerInfo.properties` 與 `MANIFEST` 的版本交叉核對。
- WebLogic `weblogic.jar` 產品資訊清單與目前安裝目錄 `inventory/ContentsXML/comps.xml` 的元件識別資訊。修補程式 ID 僅作為觀測值保留。通用 XML 或 `.patch_storage` 項目無法證明 CPU/PSU 修補程式已套用，`patchState` 維持 `unknown`。
- 已安裝產品模組下的 JBoss EAP/WildFly 產品發行資訊清單。
- 包含產品專屬內嵌版本簽章的 OpenSSH、OpenSSL、PHP、Node.js ELF 檔案。此分類補充 Syft，尚未證實能辨識所有 stripped 或自訂二進位檔。原生掃描輸入上限為 32 MiB，過大的候選項會明確標記為不完整。

Tomcat、JDK 或相同安裝目錄中的 WebLogic 中繼資料互相矛盾時，標記衝突且不宣告確定版本。不同安裝目錄不會合併。原生程式庫、用戶端、伺服器產物維持獨立 ID，即使同目錄同版本亦然。不產生 CPE 推斷或 CVE 判定。

JEUS 產品與修補程式中繼資料 **不受支援**。獨立的通用 Java 編目器可能收集 JAR 程式庫，但它們無法證明已識別 JEUS 產品或已套用的修補等級。

測試建立具代表性的中繼資料結構，不使用授權產品映像。商業安裝驗證需要目標廠商 fixture。
