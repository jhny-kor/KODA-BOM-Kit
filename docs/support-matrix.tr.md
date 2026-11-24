# Toplama kapsamı ve kanıt sınırları

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <strong>Türkçe</strong>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Matris tanımlanabilen kanıtları gösterir. Her çalıştırmada `collection.json` durum ve gerekçelerini inceleyin. Tamlık okunabilir metaveri, biçim ve izinlere bağlıdır. Güvenlik açığı değerlendirmesi eşleşen duyurular gerektirir.

## Yedi CycloneDX BOM

Host `/` ayrı belgeleri `boms/`, birleşik belgeyi `bom.cdx.json` içine yazar. `--cyclonedx-17`, 1.7 ekler. Kanıt yokluğu `no-evidence` ve bilinmeyen kapsamla belirtilir. [CycloneDX kategorileri](https://github.com/CycloneDX/specification#readme)

| BOM | Mevcut kanıtlar | Ek girdiler |
|---|---|---|
| SBOM | OS/dil paketleri, sürüm/PURL, lisans/bağımlılık, JAR, modül, konteyner | Statik/derleme bağımlılıkları için çıktı SHA-256'ya bağlı sağlayıcı/CI CycloneDX/SPDX, `build-sbom.cdx.json` |
| HBOM | CPU/kart/aygıt/sürücü/firmware, EDAC DIMM, güç/fan sensörü, SMBIOS bellek modülleri (üretici, parça numarası, hız), güç kaynakları ve yuvalar | Görünmeyen parça, numara, tedarikçi ve yaşam döngüsü için Redfish/varlık kaydı |
| CBOM | Açık sertifika/anahtar/algoritma, doğrulanmış verenler, TLS/SSH, JKS, SSH host açık anahtarları, sistem şifreleme politikası, OpenSSL protokol/şifre/grup beyanları | Ölçülmüş TLS, HSM/KMS/korumalı depoların açık metaveri çıktısı |
| OBOM | Host/konteyner/süreç/dosya/paket/soket ve systemd, süreç başına giden TCP hedefleri, systemd zamanlayıcıları, cron işleri ve beyan edilmiş güvenlik duvarı kuralları | Aynı küme Kubernetes Pod/workload/Service/Ingress, etiketler, host eşleşen `--network-evidence` |
| SaaSBOM | Hizmet/OpenAPI tanımlarından `saasbom.cdx.json`. Ayrıca OpenAPI YAML ile nginx, Apache ve HAProxy yapılandırmasında beyan edilen arka uçlar | Sağlayıcı/katalog/API, dış bağımlılık, kimlik doğrulama, güven, sınıflandırılmış akış |
| AI-BOM | Yapılandırma, nicemleme/bağlam, indeks, GGUF/safetensors başlık/boyut, Ollama. Açık çıktının tam SHA-256 değeri. `aibom.cdx.json`. Ayrıca ONNX başlıkları, PyTorch pickle içe aktarma güvenliği, Hugging Face model kartları ve önbellek ref'leri, model sunucusunun başlatılırken belirttiği model | Kimlik/revizyon/ağırlık, soy, kart/lisans, eğitim/değerlendirme kaynağı |
| MBOM | Eşleşen SLSA veya beyan edilmiş montaj/test, `mbom.cdx.json` `formulation` | CI aşama/araç/girdi/çıktı/çalıştırma veya üretim/denetim geçmişi |

## Katmanlar

| Katman | Kanıt ve sınırlar |
|---|---|
| OS | os-release/vendor release ve RPM/DEB/APK DB. İzin, bozukluk, eksik source package/module stream sınırlayabilir |
| Donanım/firmware | CPU/mikrokod/CPUID/topoloji/ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM. RAID/HBA, RDMA, GPU VBIOS, NIC sürücüye bağlıdır. megaraid_sas dışa aktarma, BMC root/IPMI ve revizyon karşılaştırması gerektirir. VM/konteyner fiziksel host'u gösterebilir |
| Dış aygıtlar | Açılmış Redfish, fwupd/devlink/ortak JSON. Raporlanan sürüm/durum korunur, eşleşmeyen varlık incelenir |
| Windows/macOS | Sistem/OS/firmware/uygulama. Windows çapraz derleme doğrulaması içerir. İç bağımlılıklar/güncellemeler ek girdi ister |
| Çalışan yazılım | Aynı kapsamda çalıştırılabilir/kütüphane ve sahip paket. Değişim yeniden başlatma incelemesi sağlar |
| Kimlik | Host `/` için machine-id/UUID/seri SHA-256 ve açık etiket. İzin/genel varsayılanlara bağlıdır. Takma kimliklendirmedir |
| Soketler | Aynı ağ alanı TCP LISTEN/UDP ve süreç FD'leri. Bind tek başına güvenlik duvarını belirlemez. Sahipsiz `unattributedSockets` |
| Giden bağlantılar | Yerel portu dinleme portu olmayan ESTABLISHED TCP, süreç ve uzak hedef başına, en çok 16.384 soket. Sabit yerel porttan karşı tarafın geçici portuna giden bağlantı kabul edilmiş sayılır. Yalnızca toplama anında açık olan bağlantılar görülür. Yalnızca host süreçleri. Bu host'un dinlediği bir porta giden bağlantı, istemci süreci o dinleyen sokete ve sahibi olan sürece bağlar |
| Zamanlanmış işler | `/etc/crontab`, `/etc/cron.d`, kullanıcı crontab'ları ve `cron.{hourly,daily,weekly,monthly}` betikleri ile etkin systemd zamanlayıcılarının `On*` takvimi. Yalnızca programın mutlak yolu tutulur; argümanlar atılır |
| Güvenlik duvarı | iptables-save dosyaları (RHEL/Debian/ufw), firewalld varsayılan bölgesi ve hizmetleri, input hook'lu nftables zincirleri ve sabit include'lar. Bunlar dosya beyanlarıdır; çekirdeğe yüklü kural kümesi okunmaz. Politikasız base chain kabul eder; `ENABLED=no` olan ufw `disabled`, systemd birimi kurulu olup ne etkin ne de çalışır durumda olan ya da maskelenmiş bir çerçeve `not-enabled` olarak kaydedilir; ikisi de etkin sayılmaz. Yalnızca loopback, kurulmuş durum ve olumsuzlanmış kurallar açık port sayılmaz; protokol genelinde TCP/UDP kabulü o protokolün tüm portlarını açar. Ana makine ağ ad alanında loopback dışındaki dinleyen soketlere `firewall-declared` eklenir: `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined` veya hiçbir etkin bildirim okunmadığında `none-observed`. Konteyner soketleri kendi ağ ad alanlarında olduğundan değer almaz. Konteynerlerin NAT ile yayımladığı portlar FORWARD kurallarından geçer ve değerlendirilmez |
| Ayar/yeniden başlatma | SELinux, AppArmor, lockdown, FIPS, izinli açılış, çekirdek `y`/`m`, reboot-required, modül/yeni aynı aile çekirdek. Sinyal yokluğu yeniden başlatmanın gereksizliğini kanıtlamaz |
| SSH | Genel beyanlar, `Match` hariç, etkin `Include` önceliği hesaplanmaz |
| Taint/modül | `kernel.tainted`, `/proc/modules`, varsa sysfs version/srcversion |
| Bilinmeyen dosya | Aynı root'ta paket/bileşen/ürün sahibi yok. Diğer mount alanları hariç. Sınıflandırma ek araştırma ister |
| Kaynak | apt düz/gz/lz4 ad eşleştirmesi, dnf/yumdb. Silinen listeler, dnf5/apk desteklenmez. URL/yol atlanır |
| Hizmet | systemd wants/requires, unit/drop-in, cgroup v1/v2. İlk ExecStart, göreli dosya pakete bağlanmaz. Özel slice durmuş görünebilir. SysV yok. Etkin zamanlayıcılar `On*` takvimini ve başlattıkları hizmeti kaydeder |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge aygıt/BIOS, Lenovo ThinkSystem. Sözlük/model eksikleri eşleşmeyi engeller. HPE/BMC yok |
| Bütünlük | RPM/dpkg/apk çalıştırılabilir/kütüphane hash'leri. Config/ghost hariç. 8 GiB host, 1 GiB konteyner. prelink yanlış fark verebilir |
| CBOM | PEM/DER, açık anahtar/algoritma, JKS v1/v2 açık zincir/takma ad hash'i. Şifreli anahtar atlanır, JKS bütünlüğü doğrulanmaz. Adlar, özel anahtar, PKCS#12, OS depoları, >20 sertifika hariç. SSH host açık anahtarları da dahil. `crypto-policies` ve `openssl.cnf` içindeki MinProtocol/CipherString/Ciphersuites/Groups beyan olarak kaydedilir; `.include` ve bölüm etkinleştirme çözümlenmez |
| Çekirdek | uname, kurulu imaj/modül, vermagic, RPM. Çalışan/kurulu ayrılır. Modül yokluğu gömülü işlev olabilir |
| Livepatch | sysfs, Oracle raw Ksplice, isteğe bağlı Ksplice/Uptrack/Canonical helper. Boot/çekirdek/zaman farkı uygulama kanıtını geçersiz kılar. CVE ayrı analiz ister |
| Java | JDK/JRE release, JAR/WAR/EAR manifest, Maven. Değiştirilmiş/silinmiş shaded metaveri sınırlıdır |
| PHP | Paket/yorumlayıcı, kurulu Composer, PEAR. Yalnız lock hariç. Kullanılabilir saldırı koşulu yapılandırmaya bağlıdır |
| snap/flatpak/conda | snap current/DEB, flatpak active/AppStream, conda-meta. snap/flatpak generic PURL, AppStream yoksa sürüm yok, conda yalnız kanal adı |
| Python | dist-info/egg-info, venv, gerçek `.pyz`/`.pex` metaverisi. Eksiklik/izin sınırlaması |
| Node/JS | node_modules/runtime, dosya ve EAR/WAR/ZIP/JAR içinde jQuery/jQuery UI/Fancytree. Dosya adı tek başına yetmez. Desteklenen düzen ve inceleme sınırları |
| Go/Rust | Go build info, cargo-auditable ELF. Veri yoksa bağımlılık bilinmez, bozuk/aşırı veri kısmi toplama |
| .NET | `.deps.json`, yönetilen DLL, sürüm kaynakları. Tek DLL'ye NuGet PURL verilmez, single-file ek doğrulama ister |
| Ruby | Kurulu specifications/gem ve default. Yalnız Gemfile.lock veya silinmiş metaveri yetersiz |
| Yerel sunucular | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB. Özel/strip/statik kopya bilinmeyebilir |
| Java sunucuları | Tomcat ServerInfo/manifest/catalina.jar, WebLogic/JBoss/WildFly kurulum/yama. `.patch_storage` tek başına etkinliği kanıtlamaz. Gerçek fixture olmayan JEUS doğrulanmamıştır |
| Duran/imaj | Docker overlay2, containerd overlayfs/k3s/RKE2, rootful Podman/CRI-O. 16 GiB/root sınırı ve boş alan kontrolüyle geçici birleştirme. Diğer sürücü/rootless yok, soket yok |
| Çalışan konteyner | procfs root, disk metaverisi, `containers/<name>/`. Volume/bind mount, Kubernetes sandbox hariç. Görünmeyen root açıklanır. API yok, yalnız konteyner süreçlerinin soketleri |
| İmaj arşivi | Açık Linux amd64 Docker/OCI tar, hash/doğrulanmış digest. İmaj içeriği kapsamı, host çekirdeği/çalışma ayrı gözlenir |
| AIX/Oracle | `aix-import` fileset, geçici düzeltme, Home başına OPatch ve isteğe bağlı SQL. Tek sunucuda en fazla sekiz Home. Çalışma durumu ayrı kanıt ister |

Elle kurulum konum/örnek kimliğini korur. Aynı ad ve sürüm farklı yama durumuna sahip olabilir. Bilinmeyen CPE boş bırakılır. Sonraki incelemede doğrulanmış kimlik ve kanıt kullanın.

Varsayılan CycloneDX 1.6/SPDX 2.3, isteğe bağlı 1.7. [Envanter ve değerlendirme](asset-inventory.tr.md), `assess`, tam sürümlü OSV/CSAF ve şemaları açıklar. [Ek kanıtlar](additional-bom.tr.md) hizmet/model/üretimi kapsar.

## Regresyon senaryoları

PHP/Composer, Node runtime/node_modules, tam JDK derlemesi, WebLogic kurulum/yama, elle Tomcat/AJP/HTTP2, httpd/mod_http2 sürümü, nginx kaynak/alias/rewrite, OpenSSL CLI/libssl/libcrypto ayrı kopyaları, çalışan/kurulu UEK/RHCK test edilir. Senaryolar kimlik kanıtını sınar. Güvenlik açığı sonucu duyuru eşleştirmesi gerektirir.
