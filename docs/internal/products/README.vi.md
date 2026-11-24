# Bộ thu thập bằng chứng sản phẩm

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`Collect(context.Context, root string, paths []string)` của KODA BOM Kit nhận danh sách tệp thông thường có đường dẫn tương đối đã kiểm tra trước. Công cụ không khám phá tệp, chạy chương trình đã cài, giải nén kho lưu trữ, liên hệ máy chủ hay đọc bí mật trong môi trường hoặc cấu hình. `os.OpenRoot` giới hạn phân giải đường dẫn. Đường dẫn tuyệt đối hoặc chứa bước lên thư mục cha bị từ chối. Đọc nội dung và siêu dữ liệu kho lưu trữ có giới hạn. Danh sách rỗng không kích hoạt khám phá tệp.

## Bằng chứng tĩnh được chấp nhận

- Các trường phiên bản, runtime, bản dựng, nhà cung cấp và kiến trúc được phép trong tệp JDK/JRE `release`.
- Đối chiếu phiên bản `ServerInfo.properties` và `MANIFEST` trong Tomcat `catalina.jar`.
- Manifest sản phẩm WebLogic `weblogic.jar` và định danh thành phần trong `inventory/ContentsXML/comps.xml` của thư mục cài đặt hiện tại. ID bản vá chỉ được giữ làm quan sát. XML chung hay mục `.patch_storage` không chứng minh bản vá CPU/PSU đã áp dụng. `patchState` vẫn là `unknown`.
- Manifest phát hành JBoss EAP/WildFly trong mô-đun sản phẩm đã cài.
- Tệp ELF OpenSSH, OpenSSL, PHP và Node.js có chữ ký phiên bản nhúng đặc trưng sản phẩm. Cách phân loại này bổ sung Syft. Chưa xác lập khả năng nhận diện toàn bộ binary stripped hay tùy chỉnh. Đầu vào quét gốc giới hạn 32 MiB, ứng viên quá lớn được đánh dấu chưa đầy đủ.

Siêu dữ liệu Tomcat, JDK hoặc WebLogic cùng thư mục cài đặt mâu thuẫn được đánh dấu xung đột và không khẳng định phiên bản. Các thư mục cài đặt khác nhau không bị gộp. Thư viện, máy khách và máy chủ gốc giữ ID riêng kể cả khi cùng phiên bản và thư mục. Không sinh suy luận CPE hay đánh giá CVE.

Siêu dữ liệu sản phẩm và bản vá JEUS **chưa được hỗ trợ**. Bộ lập danh mục Java chung có thể thu thập thư viện JAR, nhưng không chứng minh định danh sản phẩm JEUS hay mức bản vá đã áp dụng.

Các bài kiểm thử dựng cấu trúc siêu dữ liệu đại diện, không dùng ảnh sản phẩm có bản quyền. Xác minh cài đặt thương mại cần fixture của nhà cung cấp đích.
