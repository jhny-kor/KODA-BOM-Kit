# Doğrulama sonuçları

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit ve önceki sürümlerin kayıtları tarih, özet, ortam, kısmi sonuçlar ve doğrulanmayan alanları içerir. Resmi 0.1.9 yayını arşivi, sağlama toplamını ve kapsamı tanımlar. Her yeni dosya kendi testini gerektirir.

[Yayın 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 2026-11-21 — ayırma ve birleştirme

`f0610ca-worktree-00ed83f2acd8`, iki 0.1.6 arşivinde `scan --separate-boms`, `bom-split`, `bom-merge` ve `domain-bom` test etti. Tüm bileşen/ilişkiler karşılaştırıldı, her birleşime kökler arası bir ilişki eklendi. Ubuntu sertifika kimliklerinin on çifti farklı konumlardaki 20 kayıt olarak korundu. Yinelenen kimlik sıfırdı. Linux ARM64, dört gözlenen BOM'u sentetik OpenAPI, model, SLSA ve üretim girdileriyle birleştirdi. Gerçek TCP 18443, Perl ve paketine bağlandı. Şema ve özetler geçti. İmza ve saha kanıtı ayrıca doğrulanmalıdır.

| Arşiv | Bileşen önce / sonra | İlişki önce / sonra |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — çalışma ilişkileri

`f0610ca-worktree-06f22395e26f` iki kısmi arşivden OBOM üretti. Soketler namespace/süreç bazında sayılır. Debian ARM64, `127.0.0.1:18443/tcp` ile `/usr/bin/perl` ve `perl-base` bağlantısını, üç Redfish parça numarasını, TLS örneklerini, iki derleme ilişkisini ve 11 toplamı denetledi. Yeniden üretilen OBOM'lar aynıydı. Beş sentetik Kubernetes kaynağı tam konteyner kimlikleriyle eşleşti. Üretim kümeleri, fiziksel envanter ve gerçek TLS oturumları kapsam dışındaydı.

| Arşiv | Konteyner | Soket host + konteyner | Paket host + konteyner | Karşılaştırılan ilişki |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — 12 Daybreak düzeltmesi

Eski KODA-SBOM-Maker `cc86c1b` bulguları giderildi. Go ayar yalıtımı, açılan akışın özeti, 256 katman sınırı ve özet kullanımı, sınırlı ZIP/ZIP64 indeksleri, whiteout doğrulaması, özel çıktı dizinleri, indeksli/sınırlı bildirim eşleştirme, optimize Python reddi, doğrulanmış köklerde okuma, kısa kimlik güvenliği, RPM epoch çakışmaları ve 256 girdilik iptal edilebilir tarama ele alındı.

Go, vet ve yayın kontrolleri macOS ARM64'te geçti. Go 1.26.11 / Syft 1.57.1 ile statik Linux amd64 çevrimdışı derlendi. 306 toplam ve ağsız Debian CLI/dizin testleri geçti. Önce/sonra 88 paket, bir OS, 20 cihaz ve 15 sürücü aynıydı. İki toplama da gerekçeli kısmi durumdaydı. Diğer platformlar çapraz derlendi. Çalıştırma ve yeni VM testleri yapılmadı.

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Docker Desktop `7.0.14-linuxkit` ortamında Linux, Go ve vet geçti. CPU lscpu ile eşleşti, 1,736 çekirdek seçeneği okundu. Debian 147 pakette tek kayıtsız yerel paket buldu. Rocky 167 depo paketi ve yerel/kayıtsız kurulumları ayırdı. Dokuz çalışan, 14 durmuş konteyner ve 11 kullanılmayan imaj yaklaşık 3 dk 30 sn içinde 35 SBOM üretti. 796, 71, 51 paket sayıları eşleşti. Overlay2 curl'ü korudu, kullanılmayan busybox toplandı. Silinen konteyner `not_collected` oldu. Gerçek x86, systemd, Kubernetes/k3s/Podman/CRI-O ve yeni VM'ler doğrulanmadı.

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` üzerinde kimlik, gerçek soketler, 16 konteyner ve beş harici modül doğrulandı. Yaklaşık 89 MB'lık 735 dosyada bir değiştirilmiş ve bir taşınmış/eksik dosya bulundu. RSA-1024 ve ECDSA P-384 ile süre ve zayıf anahtarlar, özel anahtar çıkarmadan sınandı. Donanım, snap/flatpak/conda ve bazı ayarlar sentetikti. Fiziksel RAID/NIC/BMC, üretim SELinux, diğer motorlar ve yeni VM'ler doğrulanmadı.

## 2026-11-18 — 0.1.6-dev

Go, vet, yardımcı ve shell kontrolleri geçti. Linux amd64/ARM64 ve gerçek macOS ARM64 temel envanteri şema ve toplamları geçti. Windows yalnız derlendi. Silinmiş/değişmiş dosyalar, imaj özetleri ve yerel kurallar test edildi. Yerel Tracker iki CycloneDX sürümünü okudu. Üretim ve tarayıcı doğrulanmadı. 704/811 lisans ve ek 107 kimliğin anlamı korundu. Toplam dosya sayısı kapsama bağlıdır.

## 0.1.2–0.1.5 geçmişi

0.1.5 pnpm/Maven POM ilişkilerini, 0.1.4 dizin yardımcısını, 0.1.3 dosya/süre sınırlarını ekledi. Sağlanan `release.json`, `VERIFICATION.json`, `dist/evidence/v0.1.x/final-verification.json` ile özetleri eşleştirin. 0.1.2 son dosyasıyla Ubuntu ve iki Oracle çekirdeğini yeniden çalıştırdı. Abonelikli istemci kurulumu ve gerçek yama uygulaması sentetik testlerin dışındaydı.

## 2026-10-29 — uygulama ve Oracle VM

68 Linux kontrolü ve vet geçti. uid 65534, salt okunur girdi/rootfs, yeteneksiz/ağsız örnekler şema, PURL, canary ve hataları doğruladı. Oracle konteyneri RPM 182, Python 5, binary 2 içeriyordu. guest syscall ağ ve ek execve girişimi sıfır gösterdi. Yalıtılmış SQLite Tracker iki biçime HTTP 202 verdi. Küçük 0.1.0 örneği 0.78 sn ve 219,644 KiB en yüksek RSS kullandı.

Oracle Linux 8.2 VM'leri imzalı RHCK/UEK başlattı. uname/proc ve loop eşleşti. Her biri RPM 186, çekirdek 2, modül 5,321, Python 5, binary 2 olmak üzere 5,516 bileşen içerdi. Ağaçlar RHCK 2,478 ve UEK 2,843 modüldü. Şemalar ve beşer toplam geçti. Çıkış 3, kısmi toplama, tamamlanmış bağlam kaydedildi. Korumalı dosyalar, kapsam dışı linkler, OpenSSH çakışması ve Syft uyarıları korundu.

| Kernel | Toplama / toplam saniye |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## Kanıt sınırları

İlk VM'ler aşağıdaki 0.1.0 özetini kullandı. Sonraki sürümlerin kendi raporları vardır. Fiziksel x86, tam OS/servis bütünleşmesi ve gerçek üretici yamaları kapsam dışındaydı. QEMU guest trace ile yerel ptrace ortamları farklıdır. Canlı toplama farklı anları birleştirebilir. Sakin zaman aralığı veya salt okunur snapshot kullanın. Paket sürümü ve gözlem yokluğu CVE etkisi/giderimini tek başına belirlemez.

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## Belgeler

[Kapalı ağda çalıştırma ve sonuç inceleme](air-gapped.tr.md) · [Derleme ve doğrulama kılavuzu](verification.tr.md) · [Doğrulama sonuçları](verification-results.tr.md)
