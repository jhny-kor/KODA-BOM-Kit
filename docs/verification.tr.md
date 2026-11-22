# Derleme ve doğrulama kılavuzu

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8, çevrimdışı Linux amd64 arşivi ve SHA-256 dosyası sağlar. Test edilen çalıştırılabilir dosyayı tam özeti ve ortamıyla tanımlayın. Linux toplama x86_64 ve ARM64, Docker/OCI arşivleri linux/amd64 içindir. macOS ve Windows envanteri sabit salt okunur sistem komutları kullanır. Windows üzerinde çalıştırma henüz doğrulanmamıştır. Eski VM sonuçları ilgili derlemelere aittir.

[Yayın 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## Çıktı biçimleri ve bütünlük

Varsayılanlar CycloneDX 1.6 ve SPDX 2.3'tür. `--cyclonedx-17` aynı envanterden 1.7 ekler. `--format cyclonedx` ile iki belge üretir. `--format spdx` ile birlikte çıktıdan önce reddedilir. Seçeneği `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` ve iki yardımcı betik destekler. Beklenen dosyaları seçeneklerle karşılaştırın.

| Çıktı | Biçim |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` yerel şemaları, kimlikleri, kanıtları, özellikleri, lisans anlamlarını, ilişkileri, kapsamı ve eksik/yinelenen sağlama toplamlarını denetler. 1.7 şemaları resmi 1.7.1, `b29bae660048e0ad2fbc5f2972927b442ce951c4` commit'ine sabitlenmiştir. Kaynak `tests/schemas/provenance.json` içindedir. 1.6'da 704, 1.7'de 811 lisans kimliği vardır. Ek 107 kimlik 1.6'da `license.name`, 1.7'de `license.id` olarak korunur. `collection.json` kısmi durumunu da inceleyin.

## Derleme bilgisayarı denetimleri

Go, Python, Docker, modül önbelleği ve şema bağımlılıklarını hazırlayın. `trusted_go_sha256` bağımsız doğrulanmış Go özetidir. `GOPROXY=off` önbelleği kullanır. Yayın QA'sı `python3 -O` ve `PYTHONOPTIMIZE` kullanımını reddeder. Hedef sunucu paketlenmiş programı çalıştırır. macOS üzerinde `shasum -a 256 -c SHA256SUMS` kullanın.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Entegrasyon testleri

Komutları son dağıtımın açılmış haliyle çalıştırın. Ağı kesmeden önce gerekli önbellekleri hazırlayın. .NET/Ruby için .NET 10 SDK gerekir. Go/Rust modül önbelleği ve sabit ripgrep ELF veya `--rust-binary` kullanır. Fancytree npm SHA-512 veya GitHub SHA-256 karşılaştırır. Desteklenen testlerde `--tracker-root /path/to/tracker` gerçek yerel ayrıştırıcıyı denetler.

`domain_bom_integration.py` hedef dosyayı doğrudan çalıştırır. Bu testi Linux amd64 üzerinde çalıştırın.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

Testler iç içe Java, pyz/pex, Go/Rust, kurulum kaynağı, dizin sınırları, tedarikçi özeti, PURL ve bağımlılıkları kapsar. Linux örnekleri soket, konteyner, firmware, servis, ayar, bütünlük ve sertifikaları sınar. AIX örnekleri Oracle Home, Listener ve OPatch'i doğrular. Fiziksel BMC/NIC/OT, gerçek Kubernetes depolaması ve abonelikli yama istemcileri kendi ortam kanıtlarını gerektirir.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## Linux çekirdekleri ve VM tekrarları

Linux'a özel testleri Linux'ta çalıştırın. macOS, konteyner mimarisi için çapraz derleyebilir. VM'lerde son dağıtım dosyasını kullanın. RHCK `4.18.0-193.el8.x86_64` ve UEK R6 `5.4.17-2011.1.2.el8uek.x86_64`, `tests/oracle-vm/kernels.json` içindeki imzalı RPM'lerle ayrı başlatılır. Kaynak, imza, imaj kimliği, seri günlükler, referans ve doğrulamaları saklayın.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle çalıştırıcısı QEMU system TCG, 4 GiB, iki CPU ve özel statik PID 1 kullanır. Konuk ağ/disk içermez. uname, proc, gerçek loop yüklemesi ve kurulu/çalışan çekirdekleri denetler. Ubuntu doğrulanmış paketlerle `6.8.0-47-generic` başlatır. GRUB, UEFI/Secure Boot, tam systemd, SELinux enforcing, fiziksel sürücüler ve üretim servisleri ek test ister. Oracle konteyneri ana makine çekirdeğini paylaşır.

[Oracle VM](tests/oracle-vm/README.tr.md) · [Ubuntu VM](tests/ubuntu-vm/README.tr.md)

## Sistem çağrıları, kaynaklar ve sonraki analiz

Son dosyayı yalıtılmış konteynerde izleyin. ARM64 öykünmesi ptrace kayıtlarını okuyamazsa `trace-network.sh` 77 döndürür. Ortamı kaydederek QEMU guest syscall kullanılabilir. Sıfır girişim iddiası çalışan izleme gerektirir. Livepatch yardımcısının çağırdığı istemci ve daemon'ların ağ davranışı ayrıca değerlendirilir.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

Varsayılan sınırlar seçilen 1,000,000 normal dosya ve 30 dakikadır. Sınır, yanlış seçenek, iptal, izin, bozulma ve dışlamaları sınayın. `--max-files 0 --timeout 0` bu sınırları kaldırır. Gerçek girdi için süre ve en yüksek RSS kaydedilmelidir. İki paralel iş bellek üst sınırı sağlamaz. Tracker iki biçim için yalıtılmış geçici veritabanıyla doğrulanır. Yerel bildirim analizi kurallara ve gözlemlere bağlıdır. Üretim dağıtımı ve CVE giderimi kendi kanıtını gerektirir.

## Belgeler

[Kapalı ağda çalıştırma ve sonuç inceleme](air-gapped.tr.md) · [Derleme ve doğrulama kılavuzu](verification.tr.md) · [Doğrulama sonuçları](verification-results.tr.md)
