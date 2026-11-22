# Ürün kanıtı toplayıcısı

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit içindeki `Collect(context.Context, root string, paths []string)`, önceden denetlenmiş göreli normal dosya yollarının listesini alır. Dosya keşfetmez, kurulu programları çalıştırmaz, arşiv açmaz, sunucuya bağlanmaz veya ortam ve yapılandırma sırlarını okumaz. `os.OpenRoot` yol çözümlemesini sınırlar. Mutlak yollar veya üst dizine geçiş içeren girdiler reddedilir. Dosya içeriği ve arşiv üst verisi okumaları sınırlıdır. Boş yol listesi dosya keşfi başlatmaz.

## Kabul edilen statik kanıtlar

- JDK/JRE `release` dosyalarında izin verilen sürüm, çalışma zamanı, derleme, sağlayıcı ve mimari alanları.
- Tomcat `catalina.jar` içinde `ServerInfo.properties` ile `MANIFEST` sürümlerinin çapraz kontrolü.
- WebLogic `weblogic.jar` ürün bildirimi ve mevcut kurulum kökündeki `inventory/ContentsXML/comps.xml` bileşen kimliği. Yama kimlikleri gözlem olarak korunur. Genel XML veya `.patch_storage` girdileri CPU/PSU yamasının uygulandığını kanıtlamaz. `patchState`, `unknown` olarak kalır.
- Kurulu ürün modülündeki JBoss EAP/WildFly ürün sürüm bildirimleri.
- Ürüne özel gömülü sürüm imzaları olan OpenSSH, OpenSSL, PHP ve Node.js ELF dosyaları. Bu sınıflandırma Syft’i tamamlar. Tüm stripped veya özelleştirilmiş ikililerin kapsandığı doğrulanmamıştır. Yerel tarama girdisi 32 MiB ile sınırlıdır ve büyük adaylar açıkça eksik olarak işaretlenir.

Tomcat, JDK veya aynı kurulum kökündeki WebLogic üst verisi çelişkiliyse çakışma işaretlenir ve sürüm ileri sürülmez. Farklı kurulum kökleri birleştirilmez. Yerel kitaplık, istemci ve sunucu çıktıları aynı dizin ve sürümde olsalar bile ayrı kimliklerini korur. CPE çıkarımı veya CVE değerlendirmesi üretilmez.

JEUS ürün ve yama üst verisi **desteklenmez**. Ayrı genel Java kataloglayıcısı JAR kitaplıklarını toplayabilir, ancak bunlar JEUS ürün kimliğini veya uygulanmış yama düzeyini kanıtlamaz.

Testler lisanslı ürün görüntüleri yerine temsili üst veri yapıları oluşturur. Ticari kurulumların doğrulanması hedef sağlayıcı fixture’larını gerektirir.
