# Thông báo bên thứ ba

<!-- koda-doc-nav -->
<p align="center">
  <a href="THIRD_PARTY_NOTICES.md"><img src="badges/en.svg" alt="English"></a>
  <a href="THIRD_PARTY_NOTICES.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="THIRD_PARTY_NOTICES.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="THIRD_PARTY_NOTICES.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="THIRD_PARTY_NOTICES.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="THIRD_PARTY_NOTICES.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="THIRD_PARTY_NOTICES.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <strong>Tiếng Việt</strong>
  <a href="THIRD_PARTY_NOTICES.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="THIRD_PARTY_NOTICES.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="THIRD_PARTY_NOTICES.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Mã nguồn KODA BOM Kit được cung cấp theo Apache-2.0. Xem [LICENSE](../LICENSE) và [thông báo tiếng Anh](THIRD_PARTY_NOTICES.md).

Tệp thực thi này nhúng Anchore Syft v1.57.1 cùng các phụ thuộc Go bắc cầu. Các thành phần giữ nguyên giấy phép tương ứng. Bản phát hành chứa `licenses/inventory.json`, liệt kê mô-đun thực sự liên kết cho Linux amd64 và bản sao nguyên văn giấy phép, thông báo của chúng. Giấy phép thiếu được báo cáo và dừng bước đóng gói phát hành nghiêm ngặt. Giấy phép thư viện chuẩn Go nằm trong `licenses/GO-LICENSE`. Tệp này không cấp phép lại các thành phần đó hoặc khẳng định mọi phụ thuộc đều dùng Apache-2.0.

Fixture schema chỉ dùng trong kiểm thử trên máy dựng được sao chép từ đặc tả CycloneDX 1.6, 1.7 và SPDX 2.3. Nguyên văn giấy phép thượng nguồn, URL nguồn và giá trị SHA-256 được giữ trong `tests/schemas/`. Máy chủ đích không cần các fixture này.

- [Anchore Syft v1.57.1](https://github.com/anchore/syft/tree/v1.57.1)
- [CycloneDX 1.6](https://github.com/CycloneDX/specification/tree/1.6)
- [CycloneDX 1.7](https://github.com/CycloneDX/specification/tree/1.7.1)
- [SPDX 2.3](https://github.com/spdx/spdx-spec/tree/v2.3)
