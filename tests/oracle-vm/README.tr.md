# Oracle Linux 8.2 doğrudan çekirdek önyükleme doğrulama düzeneği

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

`init.go`, KODA BOM Kit için **doğrulama VM’sinin PID 1 sürecidir**. `//go:build ignore` kısıtı onu normal Go paket testlerinden çıkarır. Aşağıdaki komutla açıkça derleyin.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker ve QEMU derleme PC’sindeki doğrulama araçlarıdır. Kapalı ağdaki hedef sunucuya `koda-bom` yürütülebilir dosyasını aktarın. Bu düzenek ve Python yorumlayıcısı dağıtılan yürütülebilir dosyanın bağımlılığı değildir.

## Yeniden üretme

Çalıştırıcı, ARM64 derleme makinesindeki QEMU konteynerinde TCG ile x86_64 öykünmesi yapar. Konukta 4 GiB RAM ve 2 vCPU bulunur. Konteyner bellek sınırı 6 GiB’dir. Harici PC’de proje kökünden çalıştırın. `<ID>` yerine `run.py` tarafından verilen gerçek kimliği koyun ve önceki raporları koruyun.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

Doğrulama makinesi `jsonschema` gerektirir ve `tests/schemas` altında sabitlenen resmî şemaları çevrimdışı denetler. Hazırlık indirmeleri ağ ister. Çekirdek VM’si dış bağlantısız çalışır. Etiket değişebileceğinden kullanılan görüntü kimliğini koruyun.

`prepare.py`, [kernels.json](kernels.json) içinde sabitlenen dört RPM’in SHA-256 ve boyutlarını, toplam 120,245,036 baytı ve Oracle Linux 8 imza anahtarı parmak izini doğrular. Açık anahtarı yeni Oracle test konteynerinin RPM veritabanına alır, imzaları `rpm -Kv` ile denetler ve çekirdekleri `--nodeps --noscripts --notriggers` ile kurar. Bu, çekirdek görüntüsü, modül ve RPM üst verisi doğrulaması için dosya sistemi oluşturur. Normal kurulum betikleri, dracut ve GRUB yapılandırması kapsam dışıdır.

Mevcut çalışma dizininde son sürüm ikilisiyle `prepare.py` komutunu yeniden çalıştırarak önbellekli çekirdek/RPM dosya sisteminden toplayıcıyı, PID 1’i ve initramfs’i yeniden oluşturun. İki çekirdek VM’sini de yeniden başlatın ve **son ikilinin SHA-256 değerini** baseline ile karşılaştırın. Eski derlemenin VM sonuçları yeni sürümü doğrulamaz.

`input-provenance.json`, `rpm-signature-install.log` ve her çalıştırmanın `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json` dosyalarını, iki SBOM’u ve sağlama toplamlarını koruyun. Provenance, RPM, çekirdek, initramfs, PID 1 ve toplayıcı özetleri ile Oracle/QEMU görüntü kimliklerini kaydeder. Ayrı sürüm doğrulama raporu bu kanıtları dağıtım arşivinin SHA-256 değerine bağlar.

## Konuk hazırlığı

Doğrulama initramfs’i Oracle Linux 8.2 dosya sistemini, iki kurulu çekirdeğin RPM veritabanını, `/boot` görüntülerini, iki `/lib/modules` ağacını, test edilen `/koda-bom` dosyasını ve `/init` düzeneğini içerir. RHCK ve UEK kendi görüntülerinden ayrı ayrı doğrudan başlamalıdır. Yalnızca konteyner veya QEMU user-mode çalıştırmak bu önyükleme kanıtını oluşturmaz. İsteğe bağlı olarak resmî çekirdek RPM’inden çıkarılan eşleşen sürümlü modülü aşağıdaki konuma koyun.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

Düzenek modülün SHA-256 değerini kaydeder ve `init_module` ile yüklemeyi dener. Modül eksikse, zaten yüklüyse veya imza/bağımlılık nedeniyle başarısızsa durum ve hatayı ayrı kaydeder. Gerçek yüklemeyi doğrulamak için `loadedModulesAfter` ile toplayıcının `loadedModules` alanını karşılaştırın. Modülün gözlenmemesi özelliğin bulunmadığını kanıtlamaz.

QEMU’ya dış ağ arayüzü veya sanal disk verilmez. Çalıştırıcı `-accel tcg,thread=single -cpu max -smp 2 -m 4096` kullanır. Test konuğunda erken açılıştaki `getrandom` beklemesini önlemek için `random.trust_cpu=on` kullanılır. Bu test argümanı üretim yapılandırması önerisi değildir. Gerçek CPU/hızlandırma ayarlarını ve çekirdek, RPM, initramfs, toplayıcı sağlama toplamlarını ana makine kayıtlarında tutun.

## Çalıştırma ve toplama

Düzenek `/proc`, `/sys`, `/dev`, `/tmp`, `/results` yollarını bağlar ve sentetik makine adı ayarlar. Bağımsız baseline uname, `/proc/sys/kernel/osrelease`, OS release, modül öncesi/sonrası listeleri, VM çekirdek komut satırı ve toplayıcı sağlama toplamını kaydeder. Makine adı ve komut satırı yalnızca bu sentetik VM kanıtına dahildir. Ürünün normal toplama politikası geçerliliğini korur. Toplayıcı aşağıdaki komutla bir kez çalışır.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

`--target /payload` olmadan varsayılan live-host modunu kullanın. 0.1.3 doğrulaması dosya sayısı ve süre sınırlarını 0 yaparak kaldırır. Kaynak temizliği için PID 1’in ayrı 11 dakikalık watchdog’u ve ana makine QEMU zaman aşımı korunur. stdout ve stderr ayrı dosyalarda, her biri 1 MiB ile sınırlanır. Çıkış kodu, süre ve hatalar `/results/baseline.json` içine yazılır. Çıkış 3 kısmi toplama demektir ve 3 olarak kalmalıdır.

Sonuçlar seri çıkışta şu işaretçiler arasında **base64(gzip(tar))** olarak aktarılır.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

Açılmış toplam 256 MiB veya 10,000 dosyayı aşarsa yalnızca hatayı açıklayan baseline dışa aktarılır. Ardından sync ve poweroff denenir. Başarısız olursa PID 1 çekirdek paniğini önlemek için yaşamaya devam eder. Konuk süreyi aşarsa ana makine çalıştırıcısı QEMU’yu sonlandırmalıdır.

## Zorunlu denetimler

- Baseline uname ile proc release eşleşir ve RHCK/UEK amaçlanan sürümlerde açılır.
- `context.json.mode=live-host` ve `runningKernel` bağımsız baseline ile tam eşleşir.
- UEK `kernelFlavor=UEK`, RHCK ise mevcut sözleşme olan `RHCK-compatible` bildirir.
- Yerel envanter iki kurulu çekirdeği ve her RPM’in epoch/version/release/arch/source package alanlarını korur.
- Kurulu çekirdekler context tarafından tanımlanan çalışan çekirdekten ayrılır.
- `metadata.kernelVersion` ve `versionMagic` her kurulum ağacıyla eşleşir. Yüklenen modül listesi etkin çekirdek baseline değeriyle uyuşur.
- İki SBOM şeması ve sağlama toplamı geçer. Toplama hataları ve kısmi durumlar doğru bildirilir.

## Doğrulama sınırları

- Gerçek Oracle RHCK/UEK konuk çekirdekleri açılır. Fiziksel x86_64 sunucu doğrulaması ayrı yürütülür.
- Oracle Linux 8.2 kullanıcı alanı ve resmî çekirdekler özel initramfs içinde çalışır. Tam systemd açılışı, GRUB kurulumu, UEFI/Secure Boot, SELinux enforcing ve üretim hizmeti entegrasyonu test dışıdır.
- `loop` testi bir gerçek modülün yüklenmesini ve gözlenmesini denetler. Tüm sürücüleri veya donanımı kapsamaz. Etkin olmayan çekirdeğin kurulu modülleri yüklü kabul edilmemelidir.
- Çıkış `3` ve `collection.status=partial` nedenleriyle birlikte kabul edilir. Çekirdek kimliği, standart çıktı ve bütünlük denetimlerinin geçmesi bütün dosyaların eksiksiz toplandığını göstermez.
