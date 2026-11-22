# SaaSBOM, AI-BOM ve MBOM için ek kanıtlar

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="additional-bom.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="additional-bom.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="additional-bom.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="additional-bom.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


`domain-bom`, yerel kanıtları ve çıktıları okuyarak `saasbom.cdx.json`, `aibom.cdx.json`, `mbom.cdx.json` oluşturur. `--cyclonedx-17`, 1.7 dosyalarını ekler. `scan` aynı kanıt seçeneklerini kabul eder. Varsayılan ana makine toplaması yedi ayrı BOM'u `boms/` altına, birleşik belgeyi `bom.cdx.json` dosyasına yazar.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

SHA-256, gözlem kapsamı ve bilginin beyan mı rapor mu olduğu kaydedilir. İmza doğruluğu `koda:domain:authenticity` içinde doğrulanmamış olarak kalır. Sağlanan kanıtlarda `compositions.aggregate=incomplete` kullanılır. Beyan ve çıktı hash'i eşleştiğinde `artifact-binding=sha256-matched` yazılır. Tam ana makine taramasında kanıtı olmayan alan `no-evidence` ve bilinmeyen kapsamla işaretlenir.

Üç alan toplam 12 girdi kabul eder. Her JSON en fazla 16 MiB, her liste 10.000 öğedir. Yinelenen JSON anahtarları, URL kullanıcı bilgileri/sorguları/parçaları ve çözümlenmemiş sunucu şablonları reddedilir. Çıktıların hash'i akış halinde hesaplanır. Model ağırlıkları ve çalıştırılabilir dosyalar çalıştırılmaz.

## SaaSBOM

`--saas-evidence`, OpenAPI 3.x JSON veya `koda-services-1` kabul eder. OpenAPI başlık, sürüm, kök/yol/işlem düzeyindeki açık mutlak sunucu adreslerini ve kimlik doğrulama beyanlarını sağlar. Göreli sunucuların dağıtım konumu bilinmez. Açık anonim işlem varsa `authenticated=false`, incelenen tüm işlemler kimlik doğrulama gerektiriyorsa `true` kaydedilir. Yetersiz beyanda alan atlanır. Gövde örnekleri, güvenlik şeması içerikleri, açıklamalar ve sırlar dışarıda bırakılır. [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

Sağlayıcı, güven sınırı, veri sınıflandırması ve hizmet bağımlılıkları için bu biçimi kullanın.

```json
{
  "schema": "koda-services-1",
  "services": [
    {
      "id": "app",
      "name": "Application",
      "provider": "Example",
      "endpoints": ["https://app.example.invalid/api"],
      "authenticated": true,
      "trustBoundary": true,
      "trustZone": "production",
      "data": [{"flow": "outbound", "classification": "personal-data", "name": "customer-record"}],
      "dependsOn": ["database"]
    },
    {
      "id": "database",
      "name": "Database service",
      "endpoints": ["https://database.example.invalid"],
      "authenticated": true
    }
  ]
}
```

`id` ve `name` zorunludur. Diğer örnek alanlar ve `version` isteğe bağlıdır. `dependsOn` aynı dosyadaki hizmet kimliğine başvurur. `flow`, hizmet açısından `inbound`, `outbound`, `bi-directional` veya `unknown` olur. Kimlik doğrulama, güven ve çağrı ilişkileri verilen beyanlara dayanır.

## AI-BOM

Hedef sunucudaki model dizinini belirtin. Ana makine toplaması izin verilen yollara aynı incelemeyi uygular.

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` mimari, katman sayısı, dikkat başlıkları, en büyük bağlam ve nicemleme ayarlarını sağlar. Ağırlık indeksleri beyan edilen tensör sayısını ve parça listesini verir.
- safetensors/GGUF başlıkları biçim, tensör ve kullanılabilir metaveriyi sağlar. Model ve dosyalar bağımlılıklarla bağlanır. Büyük ağırlıklarda da sınırlı başlık alanı okunur. Yapılandırma/indeks/başlık hash'leri tüm dosya hash'inden ayrı tanımlanır.
- Ollama manifestleri model katmanlarını okunabilen yerel blob başlıklarına bağlar. Sunucunun güncel yükleme durumu çalışma zamanı kanıtı gerektirir.

### NVIDIA GPU bulunan Linux sunucusunda Qwen

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

`/srv/models/Qwen` yerine gerçek yolu kullanın. `snapshots/<revision>/`, `blobs/` dizinine bağlanıyorsa ikisini kapsayan `models--organization--model` dizinini seçin. Konteyner bind mount için ana makineden görünen depolama yolunu kullanın.

| Kanıt | Çıktı |
|---|---|
| Mimari, bağlam, hassasiyet, nicemleme, parçalar, tensörler | Biçim ve mevcut alanlara göre `boms/aibom.cdx.json` bileşenleri ve bağımlılıkları |
| H100 modeli, PCI kimlikleri, sürücü, donanım yazılımı | Linux PCI sysfs ve NVIDIA sürücü bilgilerinden `boms/hbom.cdx.json` |
| PyTorch, Transformers, vLLM, CUDA sürümleri | Kurulum metaverisi okunabiliyorsa ana makine/konteyner SBOM'u |
| Sunum süreci ve dinleme soketleri | Süreç ve çalıştırılabilir dosya gözlemlenirse `boms/obom.cdx.json` |

Eğitim/değerlendirme verisi, lisans, kaynak revizyonu ve soy bilgisi model kartı veya kaynak beyanı gerektirir. Güncel GPU/VRAM kullanımı, MIG ataması ve sunulan gerçek bağlam için çalışma zamanı gözlemleri gerekir.

Tek başına ağırlık çıktısı, tam SHA-256 ve safetensors veya GGUF v2/v3 başlıklarını `artifact-binding=sha256-calculated` ile kaydeder. safetensors dtype ve veri aralıklarını, GGUF mevcutsa `general.name`, `general.architecture`, `general.file_type` alanlarını sağlar. Tensör verisi ve model hesaplamaları ayrıca doğrulanmalıdır. [safetensors biçimi](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

Kimlik, revizyon, lisans, kaynak, temel modeller ve veri kümelerini `koda-model-1` ile bildirin. Örnek `sha256` yerine gerçek 64 karakterlik hash'i yazın. Her beyanı sırasıyla bir `--model-artifact` ile eşleştirin. Eşleşen beyan başka model biçimlerini de bağlayabilir.

```json
{
  "schema": "koda-model-1",
  "name": "example-model",
  "version": "revision-2",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "license": "Apache-2.0",
  "source": "https://models.example.invalid/example-model",
  "task": "classification",
  "architecture": "transformer",
  "baseModels": [{"name": "base-model", "version": "revision-1"}],
  "datasets": [{"name": "training-data", "version": "v1", "source": "https://data.example.invalid/training"}]
}
```

Modeller `machine-learning-model`, veri kümeleri `data` türündedir. Bağımlılıklar ve `modelCard.modelParameters.datasets` başvuruları korunur. Her temel model/veri kümesi `name` gerektirir, `version`, `sha256`, `source`, `license` kabul eder. Bu metaveri sağlayıcı beyanıdır. Ayrıca sağlanan ana çıktının hash'i doğrudan doğrulanır.

## MBOM

### Yazılım derleme kaynağı

`--provenance`, SLSA provenance v1 içeren in-toto Statement v1 kabul eder. Gerçek ürünü `--provenance-artifact` ile verin. Tam olarak bir `subject` SHA-256 ile eşleşmelidir. Derleyici, derleme türü, girdiler, çalıştırma kimliği ve zamanlar `formulation.workflows` alanına yazılır. Ham iç/dış parametreler atlanır. [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

Zorunlu alanlar `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType`, `predicate.runDetails.builder.id` şeklindedir. `resolvedDependencies` ve `runDetails.metadata` içindeki `invocationId`, `startedOn`, `finishedOn` varsa kullanılır. DSSE zarflarını dışarıda doğrulayıp Statement JSON olarak çıkarın.

### Fiziksel üretim

`--provenance` ile `koda-manufacturing-1` kullanın. Ürün/parça kimlikleri ve parça numaraları fiziksel öğeleri tanımlar.

```sh
./koda-bom domain-bom --output-dir ./results \
  --provenance ./manufacturing.json
```

```json
{
  "schema": "koda-manufacturing-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "observation": "reported",
  "product": {"id": "server", "name": "Server", "model": "R1", "partNumber": "SRV-R1", "manufacturer": "Example"},
  "parts": [{"id": "board", "name": "Mainboard", "partNumber": "MB-1"}],
  "steps": [
    {"name": "Install board", "action": "assembly", "inputIds": ["board"]},
    {"name": "Acceptance test", "action": "test", "inputIds": ["board"]}
  ]
}
```

Planlanan aşamalar için `observation=declared`, gerçekleştiği raporlananlar için `reported` kullanılır. `observedAt` kayıt alınma zamanıdır. İşlemler `assembly`, `inspection`, `test`, `packaging` olabilir. En fazla 1.000 aşama dizi sırasıyla bağlanır. `startedOn`/`finishedOn` isteğe bağlıdır. `inputIds`, `parts` kimliklerine başvurur. Ürün/parça `version` içerebilir.

## Çalıştırılabilir kaynak örnekleri

`internal/domainbom/testdata/` küçük sentetik hizmet/OpenAPI, model, SLSA ve üretim örnekleri içerir.

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./internal/domainbom/testdata/services.json \
  --saas-evidence ./internal/domainbom/testdata/openapi.json \
  --model-evidence ./internal/domainbom/testdata/model.json \
  --model-artifact ./internal/domainbom/testdata/model.safetensors \
  --provenance ./internal/domainbom/testdata/provenance.json \
  --provenance-artifact ./internal/domainbom/testdata/product.bin

./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --provenance ./internal/domainbom/testdata/manufacturing.json
```

[Toplama kapsamı](support-matrix.tr.md) · [Varlık envanteri](asset-inventory.tr.md)
