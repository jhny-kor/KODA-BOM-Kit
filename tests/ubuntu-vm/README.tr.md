# Ubuntu 24.04.1 gerçek çekirdek VM doğrulaması

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

Bu bir KODA BOM Kit test aracıdır. Kapalı ağ sunucusuna dağıtılan yürütülebilir dosyanın bağımlılığı değildir. Ubuntu Base **24.04.1 amd64** ve resmî Ubuntu çekirdeği **6.8.0-47-generic / paket 6.8.0-47.47** özel initramfs ile doğrudan başlatılır. QEMU user-mode veya dizin fixture’ları gerçek çekirdek önyüklemesini kanıtlamaz.

Ubuntu Base kaynağı arşivlenmiş Ubuntu dağıtım aynasından alınır. SHA256SUMS.gpg, Ubuntu CD Image Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092` ile doğrulanır. Doğrulanmış rootfs içindeki Ubuntu arşiv anahtarlığı, resmî Snapshot hizmetinin 2024-10-18 noble-updates InRelease dosyasını denetler. Zincir imzalı Release → Packages.xz → iki DEB’in SHA-256 ve boyutunu bağlar. Tüm giriş URL’lerini, sağlama toplamlarını, imza günlüklerini ve Docker görüntü kimliklerini koruyun.

Derleme makinesi Go, Python 3 ve `jsonschema`, Docker, GnuPG (`gpg`/`gpgv`) gerektirir. Oracle VM araç görüntüsü yeniden kullanılır. Bu araçlar hedef sunucuya kurulmaz. Proje kökünden çalıştırın ve `<ID>` yerine gerçek çalıştırma kimliğini koyun.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go`, Oracle düzeneğinin sınırlı dışa aktarım ve bağımsız baseline tasarımını yeniden kullanır. Ubuntu’nun loop sürücüsü gömülü olduğundan test, modül gözlemini doğrulamak için gerçek `dummy.ko` yükler. Çalışan uname, proc release, işletim sistemi, toplayıcı SHA ve yüklü modülleri bağımsız kaydeder. İki SBOM’u sabit resmî şemalar, sağlama toplamları, özgün DEB sürümleri/source/PURL ve kurulu çekirdek/modüllerle karşılaştırır. Yeni son ikili sağlandığında prepare, run ve validate adımlarını yeniden çalıştırın.

Test rootfs’i özgün DEB’leri açıp gerçek dpkg veritabanı oluşturmak için `dpkg --unpack` kullanır. Bağımlılık geçersiz kılmaları kabul edilir ve paketler unpack durumunda kalır. Bu, normal apt kurulumunun veya yapılandırmanın tamamlandığını kanıtlamaz. Tam systemd açılışı, GRUB, UEFI/Secure Boot, üretim hizmetleri ve fiziksel donanım ayrı testler gerektirir. QEMU’da NIC veya disk yoktur. Docker `--network none`, salt okunur rootfs ve kaldırılmış capabilities kullanır. Gerçek ticari veya abonelik canlı yamalarının kurulumu kapsam dışıdır.

0.1.3 doğrulaması toplayıcının iki sınırını kaldırmak için `--max-files 0 --timeout 0` geçirir. Test PID 1’in ayrı 11 dakikalık watchdog’u ve ana makine QEMU zaman aşımı korunur.

Provenance, imza ve dpkg günlükleri, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, iki SBOM ve `validation.json` birlikte korunmalıdır. Kısmi toplama çıkış kodu 3’ü koruyun. Tam toplama çıkış kodu 0’a dönüştürmeyin.
