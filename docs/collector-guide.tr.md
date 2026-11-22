# KODA BOM Kit — Toplama komutları ve çıktı dosyaları

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## Kapsamı seçme

Çalışan makinede işletim sistemini, paketleri, konteynerleri ve okunabilen donanımı envantere ekleyebilirsiniz. Dizin taraması o dizin ağacını kapsar. İmaj taraması dışa aktarılmış bir Docker veya OCI arşivini okur. Her çalıştırmada bir girdi türü seçin. Varsayılan sınırlar bir milyon normal dosya ve 30 dakikadır. `--max-files 0 --timeout 0` bu iki sınırı kaldırır. İzinler, dosya sistemi sınırları ve arşiv çözümleme sınırları geçerliliğini korur.

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## Bir veya daha fazla dizini tarama

Betik hedef dizini ve isteğe bağlı olarak sonuçların üst dizinini alır. `--no-context` kullanır ve `/` hedefini reddeder. Boşluk içeren yolları tırnak içine alın. Bir dizini dışlamak için `--exclude-dir`, bir deseni dışlamak için `--exclude` kullanın. Birden fazla hedefte çakışmayan dizinler seçin ve dışlanan dizinlerin mutlak yollarını verin. Birleştirmeden sonra bulguların konumları `target-1` ve `target-2` ile korunur.

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## Canlı yama kanıtlarını okuma

Makine taraması çekirdeğin canlı yama durumunu sysfs üzerinden okur. İsteğe bağlı betik kurulu Canonical Livepatch, Ksplice veya Uptrack istemcilerini sorgular ve çıktıyı süzer. Bir raporun güncel sayılması için aynı açılış ve çekirdekle eşleşmesi ve en fazla 24 saatlik olması gerekir. Bir kaydın bulunmaması belirli bir CVE’nin giderilip giderilmediğini göstermez.

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## Çalışma grafiğini yeniden oluşturma veya kümeyi birleştirme

Makinenin OBOM’u dinleyen soketleri, süreçleri ve kurulu paketleri ilişkilendirir. Yerel dinleme adresi tek başına dışarıdan erişimi göstermez. Dışa aktarılan gözlemleri `--kubernetes-evidence` veya `--network-evidence` ile ekleyin. `set_dir` değerini ayırma işleminin oluşturduğu `bom-set.json` dosyasını içeren dizine ayarlayın. İlişki ve sağlama toplamı dosyalarını birlikte saklayın. Eski `mlbom.cdx.json` adını kullanan kümeler de birleştirilebilir.

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## Diğer listeler için kanıt sağlama

Yapay zekâ toplayıcısına kurulu modelin dizinini verin. SaaS ve üretim kayıtları için hizmet veya süreç bildirimi sağlayın. Redfish aygıtları, sistem yazılımı veya kriptografik gözlemler için `--asset-evidence` kullanın. Derleme listesi taranan ürünle SHA-256 eşleştiğinde ilişkilendirilir. Girdi biçimleri sayfa sonundaki kılavuzlardadır.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## IBM AIX ve Oracle kayıtlarını içe aktarma

Betiği AIX’te, içe aktarma komutunu Linux analiz makinesinde çalıştırın. Oracle Home sahibinin kaydettiği OPatch çıktısını ve gerekiyorsa DBA tarafından dışa aktarılan SQL yama geçmişini verin. En fazla sekiz ayrı Home desteklenir. Listener sürümü için aynı Home’dan gelen kanıt gerekir. Yama kimliklerini ilgili üretici duyurusuyla karşılaştırın.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## Dağıtılmış bağımlılıkları belirleme

npm ve pnpm ilişkileri kurulu konumlara, eş bağımlılık çözümlemesine ve sürümlere dayanır. Statik JavaScript tanıma jQuery, jQuery UI ve Fancytree’yi kapsar. Go gömülü derleme bilgilerini, Rust ELF cargo-auditable verilerini kullanır. .NET için .deps.json dağıtılmış yönetilen DLL’lerle karşılaştırılır, Ruby için kurulu gemspec dosyaları kullanılır. Java taraması WAR, EAR ve Spring Boot içindeki arşiv yollarını korur. Bilinmeyen koordinatlar çözümlenmeden kalır.

## Dağıtımı tedarikçi listesiyle karşılaştırma

Bir WAR veya EAR dosyasıyla bu arşivin SHA-256 değerini içeren bir CycloneDX 1.4–1.7 veya SPDX 2.3 belgesi verin. `reconcile.json` içindeki `common`, `observedOnly`, `supplierOnly` ve `unresolved` alanlarını inceleyin. Tracker’a gözlenen listeyi gönderin. Üst sınır dağıtım için 512 MiB, tedarikçi belgesi için 32 MiB’dir.

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## Kapsamı doğrulama

Derleme veya test makinesinde değişmeyen aynı dağıtımı KODA, Syft ve Trivy ile karşılaştırın. Betik Python 3.11 veya daha yeni bir sürüm gerektirir. Doğrulanmış bileşen ve ilişkiler için `--expected`, gerileme denetimi için `--baseline` kullanın. İsteğe bağlı Tracker testleri verileri belirtilen test hizmetine yükler. Saklanan grafiği denetlemek için `--normalized-bom-command` sağlayın.

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## Toplama sonuçlarını yorumlama

`run_dir` değerini toplayıcının yazdırdığı yola ayarlayın. Çıkış kodu 0 tamamlandı, 3 kısmi sonuç, 2 hata anlamına gelir. Sınırlar, eksikler ve hatalar için `collection.json`, çalışma zamanı ilişkileri için `context.json`, aygıt veya sertifika kanıtları için `assets.json` dosyasını inceleyin. Her konteyner veya imaj dizininin kendi sağlama toplamları vardır. Yalnızca sürüm ve tarihe bakarak güvenlik açığı durumu belirlenemez.

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## Ayrı makinede derleme

Derleme makinesinde Go ve Python 3 kullanılır. Bu sürüm Go 1.26.11 ile derlenmiştir. Farklı bir Go kullanıyorsanız doğrulanmış çalıştırılabilir dosyanın yolunu ve SHA-256 değerini verin. Çevrimdışı derleme için önceden doldurulmuş bir modül önbelleği gerekir. Yayımlanan arşiv Linux amd64 içindir, kaynak kod Linux ARM64 için de derlenebilir. Derleme kökeni `release.json` dosyasına yazılır.

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## Belgeler

- [Çevrimdışı kurulum ve sonuçları denetleme](air-gapped.tr.md)
- [Donanım, kriptografi ve çalışma zamanı kanıtları](asset-inventory.tr.md)
- [Hizmet, yapay zekâ modeli ve üretim bildirimleri](additional-bom.tr.md)
- [Desteklenen platformlar ve toplama sınırları](support-matrix.tr.md)
- [Derleme ve doğrulama adımları](verification.tr.md)
- [Test sonuçları ve kapsamı](verification-results.tr.md)
