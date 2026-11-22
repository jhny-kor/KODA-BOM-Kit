# Yerel platform gözlemleri

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit içindeki `Collect(ctx)`, hedefte kurulu araçlarla sınırlı gözlemler toplar. Sabit komut argümanları, komut başına 60 saniyelik süre ve 32 MiB çıktı sınırı kullanır. Alanları SBOM’a yazmadan önce seçer. Seri numaraları, UUID’ler, kullanıcı adları ve tam uygulama yolları çıkarılır. Yerel yollar yalnızca bileşen kimliğinin özet hesabına katılır.

macOS üzerinde `/usr/sbin/system_profiler`, donanım, yazılım ve uygulama üst verilerini sağlar. Toplayıcı sistem ürün yazılımını, işletim sistemi yükleyicisini, CPU’yu ve uygulamaları üretir. İşletim sistemi derleme numarası sürüm metninde korunur. Bazı uygulamalarda sürüm veya üst veri bulunmayabilir.

Windows üzerinde sistem PowerShell’i profil yüklemeden çalışır. CIM computer, BIOS, OS ve QuickFixEngineering kayıtlarını, makine ve mevcut kullanıcı kaldırma kayıt defteri girdilerini okur. İşletim sistemi derlemesi ve mimarisi korunur. QuickFixEngineering yalnızca bildirdiği güncellemeleri kapsar. Kayıt defteri envanteri bütün kullanıcı profillerini, Store uygulamalarını veya gömülü bağımlılıkları listelemez. Toplayıcı bu sınırlar için kapsam sorunu kaydeder.

Yerel macOS doğrulamasını `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory` ile çalıştırın. Windows ayrıştırma fixture’ları ve çapraz derleme kaynak yapısını doğrular. Gerçek Windows çalıştırması için Windows hedefi gerekir.
