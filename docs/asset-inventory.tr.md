# Donanım ve yazılım envanteri

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Hedef işletim sistemi ve CPU için derlenmiş `koda-bom` kullanın. Linux `scan` paketleri ve donanımı toplar. Windows/macOS `platform-inventory`, sistemin yerel envanter araçlarını çağırır.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

PowerShell'de `.\koda-bom.exe platform-inventory --output-dir .\reports` kullanın. Dizin/imaj taraması seçilen dosya sistemini kapsar. Çalışan donanım, bağlam etkin ana makine `/` toplamasında gözlemlenir. Docker/OCI arşivleri Linux amd64 destekler. Doğrulanmış CycloneDX'i Tracker'a aktarın ve sürümleri/sağlama toplamlarını birlikte saklayın.

## Toplanan kanıtlar

| Alan | İçerik ve yorum |
|---|---|
| Donanım | CPU/mikrokod, azaltımlar, kart, BIOS/UEFI, ESRT, PCI/sürücü, NVMe/SCSI, USB, TPM. RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS, amdgpu `vbios_version`. NIC için `ethtool -i` eşdeğeri salt okunur ioctl. megaraid_sas dışa aktarma gerektirir. Root olarak ham SMBIOS tablosu bellek modüllerinin üretici, parça numarası, kapasite ve hızını, güç kaynaklarının model ve gücünü, yuvaları ve PCI adreslerini verir; seri numaraları SHA-256 olarak kaydedilir |
| BMC | `/dev/ipmi0` üzerinden salt okunur IPMI `Get Device ID`, root ve `ipmi_si`/`ipmi_devintf` gerekir. Revizyon, IANA üretici, ürün ve yardımcı revizyon kaydedilir. Eksikler açıklanır. Üretici sürüm etiketini Redfish ile karşılaştırın |
| CPU | x86 `cpuidSignature`/`familyModelStepping`, topoloji, ARM üretici/çekirdek, `r3p1` gibi revizyon. Bilinmeyen çekirdekte ham kodlar korunur. USB `bcdDevice` aygıt sürüm kimliğidir |
| Dış varlıklar | Açılmış Redfish nesneleri, fwupd/devlink JSON ve ortak şema. Çalışan/saklanan donanım yazılımı ayrı, alanlar modele bağlıdır |
| Çalışma | Çalıştırılabilir/kütüphane değişimi, dosya kimliği, tekil sahip paket. Değişim `restart_review` üretir. Bellekteki sürümü belirlemek için kurulu sürüme ek kanıt gerekir |
| Kimlik | Ana makine `/` için normalize machine-id ve DMI UUID/seri SHA-256, `--no-context` ile de alınır. machine-id/UUID küçük harf, seri kenar boşlukları temizlenmiş. Genel varsayılanlar/sıfır UUID atlanır. Hash'ler tahmin edilebilir takma kimliklerdir. `--asset-tag` tek satır 128 karakter. Konteyner kapsamı `container-visible` |
| Soketler | Toplayıcının ağ alanında TCP LISTEN/bağlanmamış UDP, süreç tanıtıcılarıyla sahiplenilir. `bindScope`, `all-interfaces`, `loopback`, `address` olur. Güvenlik duvarı/yönlendirme erişimi ayrı kanıt ister. Sahipsizler `context.json.unattributedSockets`. Kurulmuş giden TCP bağlantıları süreç ve uzak hedef başına `outboundConnections` içinde `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`) ile kaydedilir |
| Güvenlik/yeniden başlatma | SELinux mevcut/yapılandırılan, AppArmor/profiller, lockdown, FIPS, izinli açılış seçenekleri. Kimlik bilgileri dışlanır. `kernelConfig`, `/proc/config.gz` veya `/boot/config-<running-kernel>` içindeki `y`/`m` değerlerini okur. Reboot-required, çalışan modüllerin yokluğu ve aynı ailede yeni çekirdek sinyaldir. Varsa `reboot.recommended=true`, yoksa `not_observed`. Aile sürüm metninden çıkarılır |
| SSH | `sshd_config`/`sshd_config.d/*.conf` genel beyanları, `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. `Match` dışlanır. Etkin değerler `Include` sırasına bağlıdır |
| Modüller/programlar | `kernel.tainted`, `taintedModules`, adlar, `O`/`E`/`P`, version/srcversion. Aynı root'ta paket/bileşen/ürün sahibi bulunmayan programlar `unidentifiedExecutables` yol/PID kaydıdır. usr-merge dikkate alınır |
| Bütünlük | RPM/dpkg/apk hash'leri ile çalıştırılabilir/`.so` karşılaştırılır. Yapılandırma/ghost dışlanır. `modified`/`missing`, `collection.json.integrity.findings` ve özelliklerde bulunur. 8 GiB/host, 1 GiB/konteyner, sonra `partial`. prelink fark oluşturabilir |
| Kaynak | apt Packages düz/gz/lz4 ad eşleştirmesi, dnf geçmişi, yum `from_repo`. `repository`, `local-file`, `not-recorded`. Geçmiş yokluğu, dnf5/apk sınıflandırılmaz. URL/yollar atlanır. dnf DB geçici kopyada salt okunur açılır |
| Açılış | systemd wants/requires, unit/drop-in, ilk `ExecStart`, soket etkinleştirme, PURL. Maskeli unit dışlanır. `system.slice` süreçleri durum belirler, özel slice durmuş görünebilir. Etkin zamanlayıcılar `On*` takvimini ve başlattıkları hizmeti kaydeder |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge aygıt/BIOS, Lenovo ThinkSystem aygıt. Bilinmeyen modeller, HPE/BMC için CPE tahmin edilmez |
| Sertifikalar | Açık X.509 parmak izi, geçerlilik, algoritma, anahtar boyutu/durum. SHA-1/MD5, RSA <2048, DSA göstergeleri. Klasik algoritma `nistQuantumSecurityLevel=0`. Konu/veren adları ve özel anahtarlar dışlanır. Sistem güven depoları ve >20 sertifikalı dosyalar atlanır. SSH host açık anahtarları (`etc/ssh/ssh_host_*_key.pub`) da OpenSSH SHA-256 parmak iziyle kaydedilir |
| Uygulamalar | Etkin snap/gömülü DEB, etkin flatpak/AppStream, conda kanal adı, `.pyz`/`.pex`, JAR, statik JS, Go/Rust. Docker/OCI hash'leri ve doğrulanan özetler |

## Konteynerler ve çıktılar

Her çalışan konteyner `containers/<name>/` alır. Kubernetes namespace/pod/konteyner kullanır, çakışmada ID'nin ilk 12 karakterini ekler. Docker/containerd/Podman/CRI-O disk metaverisi okunur, API'ye bağlanılmaz. Root mountinfo aygıtlarıyla bulunur. İmaj/yazılabilir katmanlar dahil, volume/bind mount hariçtir. Soketler konteyner süreçlerine atanır, paket sahipliği öncelikli, Go için main module kullanılır. Görünmeyen root/zaman aşımı gerekçeli `not_collected` üretir. `--no-containers` kapatır.

Duran konteyner ve kullanılmayan imajlar Docker overlay2, containerd overlayfs/k3s/RKE2, rootful Podman/CRI-O destekler. Katmanlar whiteout/opaque uygulanarak geçici kopyada birleştirilir, taramadan sonra kopya silinir. Aygıt dosyaları ve set-ID bitleri atlanır. Root >16 GiB veya boş alan boyut+1 GiB altında ise atlanır. `state: stopped` veya `state: image`, soketsiz çıktı üretir. Eşzamanlı değişiklik toplamayı engelleyebilir. Diğer sürücüler/rootless Podman desteklenmez. `--no-images` bu yolu kapatır.

`boms/` altında yedi profil oluşturulur ve `bom.cdx.json` içinde birleştirilir. AI-BOM adı `aibom.cdx.json` olur. Uyumluluk çıktıları CycloneDX 1.6 `sbom.cdx.json`, SPDX 2.3 `sbom.spdx.json`, isteğe bağlı `--cyclonedx-17` ile 1.7'dir. SPDX eşdeğer tür yoksa `OTHER` ve açıklama kullanır. Host `koda:host:*`, konteyner `koda:container:*`, soketler `koda:runtime:listening`/`koda:runtime:bind-scope`. `assets.json`, `context.json`, `collection.json`, `inventory.syft.json` dosyalarını inceleyin, `SHA256SUMS` ile doğrulayın.

## Ortak varlık kanıtı

En fazla sekiz dosya, her biri 8 MiB. `parentId` aynı dosyadaki `id` alanına başvurur. Bilinmeyen sürümü atlayın. Redfish için URI listesinin ötesinde açılmış nesneler gerekir. SHA-256 içe aktarılan dosyayı tanımlar.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

## Kriptografik varlıklar ve TLS

Sertifikalar, açık anahtarlar ve algoritmalar `cryptographic-asset` olur. Olası verenler imzayla kontrol edilir. İzinli Nginx/Apache/sshd yönergeleri yapılandırma kanıtıdır. JKS v1/v2 açık zincirleri ve takma ad SHA-256 değerlerini kaydeder, şifreli anahtarları atlar, parolasız bütünlüğü `not-verified` olarak işaretler.

PKCS#12/HSM/KMS açık metaverisini `--asset-evidence` ile alın. `related-crypto-material`, anahtar türü/boyutu/durumu, `algorithmRef`, `properties.storageType`, `keyAlias` içerebilir. Tüketici `dependsOn` aynı dosyadaki anahtara başvurur.

Örnek ayrı ölçülmüş TLS anlaşmasını gösterir. Parmak izi, uç nokta ve zamanı gerçek değerlerle değiştirin. Eşleşen hash hizmet → protokol → sertifika bağlantısını oluşturur.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## Çevrimdışı güvenlik duyurusu değerlendirmesi

Yeni duyurularla arşivlenmiş sonuçları yeniden değerlendirin.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`/`--context`/`--kev` isteğe bağlıdır. Bağlam kullanımı SBOM ve bağlamı `SHA256SUMS` ile doğrular. KEV öncelik bilgisi ekler. Açık kurallar, tam sürüm/PURL içeren OSV, tam ürün ID/koşulsuz durum içeren CSAF 2.0 desteklenir. Desteklenmeyen aralık, koşul veya birleşimler gerekçeyle durdurulur.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "Verify firmware activation according to the vendor advisory"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Dağıtım sürümlü distro kimliği ve tam paket sürümü kullanın. SBOM/PURL çelişkisi `review_required` üretir. RPM epoch dikkate alınır. Çalıştırma başına en fazla 1.000.000 tam sürüm girdisi. Kurallar `supportEndsAt` ve desteklenen ekosistemlerde `affectedSemver` kabul eder. Değiştirilen dosya/saklanan firmware etkinleştirme incelemesi, bilinmeyen varlık/duyuruda olmayan sürüm ek inceleme gerektirir. Fiziksel Linux ve Windows aygıtlarını üretici envanteriyle karşılaştırın. Yerel Windows/macOS envanteri OS, donanım ve kurulu uygulamalara odaklanır.

Raporun `risks` dizisi, toplayıcının BOM'a kaydettiği riskleri `KODA collection evidence` kaynağıyla listeler; bunlar için duyuru dosyası gerekmez ve duyuru `findings` kayıtlarından ayrı tutulur. `sbom.cdx.json` ve `sbom.spdx.json` kriptografik riskleri taşır; birleştirilmiş `bom.cdx.json` ayrıca AI-BOM ve OBOM risklerini ekler. `bom.cdx.json` içinde duyurular, ana makine paketini tekrarlayan OBOM düğümlerini atlar; çalışan konteynerlerin paketleri kendi OBOM düğümleri üzerinden eşleştirilir; bu düğümler yalnızca süreçlerin kullandığı paketleri kapsar. Bir konteynerin tam envanteri için `containers/<name>/sbom.cdx.json` dosyasını değerlendirin. `risk_observed`, kayıtlı kanıtın durumu gösterdiği; `review_required`, durumun dışlanamadığı anlamına gelir.

| Bulgu ID | Durum | Kayıtlı kanıt |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | 2048 bitten kısa RSA veya DSA kullanan sertifika ya da SSH ana makine anahtarı |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | MD5 veya SHA-1 ile imzalanmış sertifika (toplayıcının kendinden imzalı olarak doğruladıkları hariç) |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | TLS 1.2'den eski protokollere izin veren yapılandırma veya LEGACY sistem şifreleme politikası |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | Model dosyasındaki veya bir model dizininin checkpoint'indeki pickle, kod çalıştırabilen çağrılabilirleri içe aktarır |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | Pickle izin listesi dışındaki modülleri içe aktarır veya inceleme tamamlanmamıştır |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | Bildirilen güvenlik duvarı kurallarının kabul ettiği, loopback dışındaki ana makine dinleyicisi; kısıtlı kaynaklar, değerlendirilemeyen kurallar veya etkin güvenlik duvarı bildiriminin olmaması (`none-observed`) inceleme gerektirir |

## NIS-SBOM tablosu

`nis-sbom`, toplanan bir CycloneDX SBOM'u NIS-SBOM 1.0'ın 20 temel alanına dönüştürür (Kore kılavuzu "SW 공급망 보안 가이드라인 1.0", Tablo 35). Kılavuz alanları ve tablo biçimini tanımlar, dosya şeması tanımlamaz; bu nedenle sonuç, yazılım bileşeni başına bir satır içeren UTF-8 CSV dosyasıdır. Yalnızca yazılım bileşenleri listelenir. Donanım, dosyalar ve kriptografik varlıklar dahil edilmez.

```sh
./koda-bom nis-sbom \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --organization EXAMPLE \
  --output ./nis-sbom.csv
```

`--organization` ve `--sequence` (varsayılan 1), SBOM kimliğini `EXAMPLE-YYYYMMDD-000001` biçiminde oluşturur. `--product`, `--product-version` ve `--author`, taranan hedefin adının ve toplayıcı adının yerine geçer. Tedarikçi, SBOM'da kayıtlı değerdir; yoksa PURL ad alanı kullanılır. Yalnızca SHA-256 veya daha güçlü özetler listelenir. `SBOM Type`, SBOM'da kayıtlı yaşam döngüsü aşamasını izler; kayıt yoksa `Deployed` olur. `SPDX Doc. ID` ve `Component Alias` boş kalır. Toplayıcı zafiyet eşleştirmesi yapmadığı için `Vul. DB` ve `Vul. Info` da boş kalır. Bir elektronik tablonun formül olarak çalıştırabileceği değerin başına `'` eklenir.

## TCP gözlemleri

`--network-evidence`, önceki ölçümleri host/arşiv OBOM soketleriyle eşleştirir. `hostField`, `machineIdSha256`, `productUuidSha256` veya açıkça atanmış `assetTag` olur. `scope`, `host` veya tam 64 karakterli konteyner ID'sidir.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

Sonuçlar `connected`, `refused`, `timed-out`. Belirsiz sahipler veya eksik soketler eşleşmeden kalır. Her gözlem noktası/zamanı ayrı kayıt gerektirir. Toplayıcı bağlantı testi yapmaz. [Destek matrisi](support-matrix.tr.md) · [Ek kanıtlar](additional-bom.tr.md)
