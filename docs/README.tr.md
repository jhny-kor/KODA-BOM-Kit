<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.tr.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>Tek bir çevrimdışı çalıştırılabilir dosyayla bir Linux makinesindeki yazılım, donanım ve çalışma zamanı verilerini toplayın. KODA BOM Kit yedi CycloneDX malzeme listesi, bunların birleşik sürümünü ve SPDX biçiminde bir yazılım envanteri üretir.</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><b>v0.1.9 sürümünü indir</b></a> ·
  İlk yazar <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">Resmî depo</a>
</p>

## Hızlı başlangıç

Linux amd64 arşivini ve ona karşılık gelen SHA-256 dosyasını indirin. Her ikisini hedef sunucuda boş bir dizine kopyalayıp aşağıdaki komutları orada çalıştırın. Hedef sunucuda Go kurmanız, paket indirmeniz veya güvenlik açığı veritabanı bulundurmanız gerekmez.

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## Çıktı dosyaları

Son satırda `bom-output/` altında oluşturulan dizin gösterilir. Birleşik envanteri görmek için `bom.cdx.json` dosyasını açın. Yedi ayrı liste `boms/` dizinindedir.

| Dosya | İçerik |
|---|---|
| `boms/sbom.cdx.json` | Kurulu paketler, kütüphaneler ve uygulamalar |
| `boms/hbom.cdx.json` | Aygıtlar, sistem yazılımları ve sürücüler |
| `boms/cbom.cdx.json` | Sertifikalar ve algoritmalar gibi kriptografik varlıklar |
| `boms/obom.cdx.json` | Hizmetler, süreçler, soketler ve paketler arasında gözlenen ilişkiler |
| `boms/aibom.cdx.json` | Yerel model dosyaları, ağırlıklar ve sağlanan model üst verileri |
| `boms/saasbom.cdx.json` | OpenAPI belgesinde veya hizmet bildiriminde tanımlanan hizmetler ile vekil yapılandırmasında beyan edilen arka uçlar |
| `boms/mbom.cdx.json` | Sağlanan kanıtların tanımladığı üretim ve derleme süreçleri |

İlgili kanıt bulunmadığında bir liste boş kalabilir. Nedeni için listenin kanıt durumuna ve `collection.json` dosyasına bakın. Tracker, üst dizindeki `sbom.cdx.json` veya `sbom.spdx.json` dosyasını kabul eder. Varsayılan biçimler CycloneDX 1.6 ve SPDX 2.3’tür. CycloneDX 1.7 çıktısını da almak için `--cyclonedx-17` ekleyin.

Listeleri yeniden birleştirmek için bildirim, ilişki ve sağlama toplamı dosyalarıyla birlikte `boms/` dizininin tamamını kopyalayın. `run_dir` değerini toplayıcının gösterdiği dizin yoluna ayarlayın.

```sh
(
  cd koda-bom-linux-amd64-0.1.9-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## Belgeler

- [Çevrimdışı kurulum ve sonuçları denetleme](air-gapped.tr.md)
- [Toplama komutları ve çıktı dosyaları](collector-guide.tr.md)
- [Donanım, kriptografi ve çalışma zamanı kanıtları](asset-inventory.tr.md)
- [Hizmet, yapay zekâ modeli ve üretim bildirimleri](additional-bom.tr.md)
- [Desteklenen platformlar ve toplama sınırları](support-matrix.tr.md)
- [Derleme ve doğrulama adımları](verification.tr.md)
- [Test sonuçları ve kapsamı](verification-results.tr.md)

### Kaynak kod ve test kılavuzları

- [Dış varlıkları içe aktarma](internal/assetimport/README.tr.md)
- [Platform envanteri](internal/platforminventory/README.tr.md)
- [Ürün tanımlama](internal/products/README.tr.md)
- [Oracle Linux VM](tests/oracle-vm/README.tr.md)
- [Ubuntu VM](tests/ubuntu-vm/README.tr.md)

## Lisans ve atıf

KODA BOM Kit, Apache-2.0 lisansıyla dağıtılır. İlk yazar ve pakete dahil edilen bağımlılıkların lisansları aşağıdaki bildirimlerde belirtilmiştir. [Apache-2.0](../LICENSE) · [Yazar bildirimi](../NOTICE) · [Üçüncü taraf bildirimleri](THIRD_PARTY_NOTICES.tr.md)
