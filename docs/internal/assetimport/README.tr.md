# Çevrimdışı aygıt kanıtı

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit içindeki `Load`, en fazla 8 MiB ve 4096 kayıt içeren tek bir normal JSON dosyasını okur. fwupd `get-devices --json` dışa aktarımlarını (`Devices`), genişletilmiş Redfish `SoftwareInventory`, `Manager`, `ComputerSystem` nesnelerini ve bunların koleksiyonlarını kabul eder. Yalnızca URI içeren Redfish üyeleri eksik toplama sorunları oluşturur. İçe aktarılan değerler yöneticinin dışa aktardığı gözlemlerdir. Ürün yazılımının `ImageState` değeri varsa korunur, yoksa bilinmiyor olarak kalır. Dışa aktarım özetleri kanıt baytlarını tanımlar ve kaynağın kimliğini doğrulamaz.

Windows, macOS, OT ve diğer envanter sağlayıcıları aşağıdaki açık biçimi dışa aktarabilir.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id":"board", "kind":"device", "name":"Controller", "vendor":"Vendor", "model":"Model", "revision":"A"},
    {"id":"firmware", "parentId":"board", "kind":"firmware", "name":"Controller firmware", "version":"1.2", "properties":{"applicationState":"Active", "storedVersion":"1.3"}}
  ]
}
```

Desteklenen türler `device`, `firmware` ve `device-driver` şeklindedir. İzin verilen özellikler `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` ve `updateState` alanlarıdır. Kimlikler, farklı içe aktarımların yanlışlıkla birleşmesini engellemek için kanıt özeti kapsamında tutulur. Eksik ürün yazılımı sürümleri eksik toplama sorunu oluşturur. CPE değerleri çıkarımla üretilmez. Gözlem zamanları kaynak dışa aktarımı tanımlar. Atlanan zaman damgası bilinmiyor olarak kalır.

Genel biçim `library`, `application`, `operating-system` ve `container` türlerini de kabul eder. İsteğe bağlı `purl` ayrıştırılır ve içindeki sürüm açıkça belirtilen sürümle eşleşmelidir. Niteleyiciler `arch`, `distro`, `epoch`, `type` ve `classifier` ile sınırlıdır. İsteğe bağlı `sha256`, 64 onaltılık karakterden oluşmalı ve içe aktarılan bileşeni tanımlamalıdır. İçe aktarıcı kanıt dosyasının özetini ayrıca hesaplar. Windows ve macOS, yerel platform envanter komutunu kullanabilir. Diğer sağlayıcılardan alınan ek kanıtlar için bu biçimi kullanın.

`devlink -j dev info` dışa aktarımları `info` nesnesi üzerinden kabul edilir. Veri yolu başvuruları girdileri tanımlar. Fixed, running ve stored sürüm grupları ayrı korunur. Bildirilen çalışan `fw`, bileşen sürümü olur. Sürücüye özel alternatif sürüm anahtarları özelliklerde tutulur. Eksik `fw`, bilinmeyen sürüm sorunu oluşturur. Seri numaraları çıkarılır.
