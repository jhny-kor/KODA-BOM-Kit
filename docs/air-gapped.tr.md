# Kapalı ağda çalıştırma ve sonuç inceleme

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8, Linux x86_64 (amd64), çekirdek 3.2 ve sonrası içindir. Resmi yayından arşiv ve eşleşen `.tar.gz.sha256` dosyasını taşıyın. Sunucuya Go, Python, Docker veya jq kurmak gerekmez. NOTICE, jhny-kor ve resmi depoyu belirtir.

[Yayın 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Doğrulama ve açma

Tek bir eşleşen arşiv ve toplam dosyasını çalıştırılabilir yerel dizine koyun. Açmadan önce arşivi, sonra iç dosyaları denetleyin. Toplamlar taşınan baytları doğrular. Güvenilir resmi kaynağı kullanın. noexec USB'den çalıştırılabilir dosya sistemine kopyalayın.

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## Sunucuyu inceleme

Mimari, çalışan çekirdek ve `doctor` çıktısını denetleyin. `supported=true` çalışma önkoşullarının geçtiğini gösterir. `doctor.kernel` ve `context.json.runningKernel` gözlenen çekirdektir. `kernelFlavor=unknown/unconfirmed` olsa da sürüm kaydedilebilir. root, DMI/BMC/süreç/konteyner görünürlüğünü artırır.

```bash
uname -m
uname -r
./koda-bom doctor
```

## Toplama kapsamı

Parametresiz `koda-bom`, `bom-output/` altında yeni dizin, birleşik `bom.cdx.json` ve `boms/` içinde yedi belge üretir. AI-BOM dosyası `aibom.cdx.json` olur. İçerik yerel kanıtlara bağlıdır. Qwen için gerçek model dizinini kullanın. H100, HBOM içindedir. Ayar, başlık ve paketler güncel GPU atamasını ya da etkin servis ayarını belirleyemez.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

Dizin toplama `--no-context` kullanır. Çıktıyı girdi kapsamının dışına koyun. Yardımcı `/` hedefini reddeder, tek dizinde göreli dışlama kabul eder. Çoklu hedefler örtüşmemeli, dışlamalar mutlak olmalıdır. Süre/dosya limitleri paylaşılır. Dış bağımlılıklar gözlenemeyebilir.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Livepatch toplama

İsteğe bağlı yardımcı mevcut Ksplice, Uptrack veya Canonical istemcilerini sorgular, kanıtı temizler ve scan çalıştırır. Temiz kanıtı sonuç yanında saklar. `$?` değerini hemen alın. Sorgu 30 sn, etkin çekirdek sorgusu 10 sn ile sınırlıdır. scan sınırını kaldırmak bunları kaldırmaz. İstemci ve daemon ağ davranışı kendilerine aittir.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## Sınırlar ve çıkış kodları

Varsayılan 1,000,000 normal dosya ve 30 dakikadır. `--max-files 0 --timeout 0` ikisini kaldırır, Ctrl+C iptal eder. İzin, dışlama, link, dosya başına 2 GiB ve imaj açma sınırları sürer. `--no-containers` konteyner ve kullanılmayan imajları, `--no-images` durmuş konteyner ve kullanılmayan imajları atlar. 0 tamamlandı, 3 sonuçlu kısmi, 2 başarısızdır. Diğer anormal kodları da araştırın.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## Sonuçları bulma ve doğrulama

Komutun yazdığı tam dizini kullanın. Yardımcı doctor ve kanıtlardan sonra son satırda sonuç yolunu verir. `result` değişkenini bu yola ayarlayın. root dosyaları sudo gerektirebilir. Ana manifesto ve her konteyner/imaj manifestosunu doğrulayın. Kısmi toplama gerekçelerini saklayın.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## Toplama ve yama durumları

`collection.json`, `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, kimlik, kaynak, bütünlük ve konteynerleri içerir. Dosya sayısı taramada seçilen dosyalardır. `file_limit_exceeded`, `limit` ve `observed` içerir. `context.json` çekirdek, süreç, soket, servis, ayar ve yamaları, `assets.json` donanım/firmware/sertifikaları içerir.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` doğrudan çekirdek, `reported-applied` istemci bildirimidir. `disabled` ve `transitioning` durumlarını korur. `stale`, `identity_mismatch`, `unknown` ek kanıt ister. `reportedState` eski olabilir, mevcut durum ve `patches[].state` birlikte okunmalıdır. 24 saatten eski, başka boot/çekirdek veya aşırı gelecek zamanlı rapor güncel uygulamayı kanıtlamaz. Canonical Last-Check/CheckState de denetlenir. Eksik gözlem ve `not-reported-patched` üretici/çekirdek kanıtıyla yorumlanır.

`integrity.findings[].state=modified` veya `missing`, fark veya eksikliği belirtir. `bindScope=all-interfaces` bağlanılan adreslerdir. Güvenlik duvarı üzerinden erişim ayrı kanıt ister. `unidentifiedExecutables` paket eşlemesi bulunamadığını, `reboot.recommended=not_observed` sinyal yokluğunu belirtir. Bağlam ve sınırlarla birlikte değerlendirin.

## Tedarikçi karşılaştırması ve saklama

WAR/EAR tedarikçi SBOM'u gerçek SHA-256 içermelidir. Eksik/uyuşmayan özet çıkış 2 verir. `reconcile.json` ve kısmi gerekçeleri inceleyin. Temiz livepatch kanıtıyla tüm üst dizini arşivleyin ve aktarım toplamını hesaplayın.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## Yükleme ve sonraki analiz

Uyumlu Tracker'a `sbom.cdx.json` veya `sbom.spdx.json` gönderin. Konteyner/imajların kendi SBOM'ları vardır. collection, context ve Syft'i ek kanıt olarak saklayın. Yükleme süresi bağımsız ayarlanır. Toplama sonraki bildirim analizini besler. Güncel yama etkisi ve CVE giderimi kendi kanıtını ister. Sürüm/VM kapsamları için doğrulama kayıtlarına bakın.

## Belgeler

[Kapalı ağda çalıştırma ve sonuç inceleme](air-gapped.tr.md) · [Derleme ve doğrulama kılavuzu](verification.tr.md) · [Doğrulama sonuçları](verification-results.tr.md)
