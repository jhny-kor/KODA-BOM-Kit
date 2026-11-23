# ขอบเขตการเก็บข้อมูลและข้อจำกัดของหลักฐาน

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
  <strong>ไทย</strong>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


ตารางนี้อธิบายหลักฐานที่สามารถระบุได้ ตรวจสถานะและเหตุผลใน `collection.json` ของแต่ละรอบ ความครบถ้วนขึ้นกับเมทาดาทาที่อ่านได้ รูปแบบการติดตั้ง และสิทธิ์ การประเมินช่องโหว่ต้องมีหลักฐานประกาศที่ตรงกัน

## BOM CycloneDX เจ็ดประเภท

การสแกนโฮสต์ `/` แบบเริ่มต้นสร้างเอกสารแยกใน `boms/` และเอกสารรวม `bom.cdx.json` ตัวเลือก `--cyclonedx-17` เพิ่มรุ่น 1.7 หลักฐานโดเมนที่ไม่รองรับหรือไม่มีจะระบุชัดเจน รวม `no-evidence` และความครอบคลุมที่ไม่ทราบ [ประเภท CycloneDX](https://github.com/CycloneDX/specification#readme)

| BOM | หลักฐานที่มี | หลักฐานเพิ่มเติม |
|---|---|---|
| SBOM | แพ็กเกจ OS/ภาษา รุ่น/PURL ใบอนุญาต/dependencies ที่มี JAR โมดูลฝัง และคอนเทนเนอร์ | CycloneDX หรือ SPDX จากผู้จัดหา/CI ที่ผูกกับ SHA-256 อาร์ติแฟกต์สำหรับส่วนพึ่งพา static/build ออกเป็น `build-sbom.cdx.json` |
| HBOM | CPU/บอร์ด/อุปกรณ์/ไดรเวอร์/เฟิร์มแวร์ EDAC DIMM และเซนเซอร์ไฟฟ้า/พัดลม โมดูลหน่วยความจำจาก SMBIOS (ผู้ผลิต หมายเลขชิ้นส่วน ความเร็ว) แหล่งจ่ายไฟ และสล็อต | Redfish หรือทะเบียนทรัพย์สินสำหรับชิ้นส่วนที่มองไม่เห็น หมายเลขชิ้นส่วน ผู้จัดหา และวงจรชีวิต |
| CBOM | ใบรับรอง/กุญแจ/อัลกอริทึมสาธารณะ ความสัมพันธ์ issuer ที่ตรวจแล้ว การตั้งค่า TLS/SSH และเมทาดาทา JKS กุญแจสาธารณะของโฮสต์ SSH นโยบายการเข้ารหัสของระบบ และข้อประกาศโปรโตคอล/ชุดรหัส/กลุ่มของ OpenSSL | การเจรจา TLS ที่วัดจริง และเมทาดาทาสาธารณะที่ส่งออกจาก HSM/KMS/keystore ที่ป้องกัน |
| OBOM | ความสัมพันธ์โฮสต์/คอนเทนเนอร์/โปรเซส/ไฟล์ปฏิบัติการ/แพ็กเกจ/ซ็อกเก็ต และ systemd activation ปลายทาง TCP ขาออกต่อโปรเซส ตัวตั้งเวลา systemd งาน cron และกฎไฟร์วอลล์ที่ประกาศ | Kubernetes JSON จากคลัสเตอร์เดียวกันสำหรับ Pod/workload/Service/Ingress ป้ายการปรับใช้ และ `--network-evidence` ที่ตรงกับโฮสต์ |
| SaaSBOM | ข้อกำหนดบริการ/OpenAPI กลายเป็น `saasbom.cdx.json` รวมถึง OpenAPI YAML และ backend ที่ประกาศในการตั้งค่า nginx, Apache และ HAProxy | หลักฐานผู้ให้บริการ/แค็ตตาล็อก/API ส่วนพึ่งพาภายนอก การยืนยันตัวตน ขอบเขตความเชื่อถือ และการไหลของข้อมูลที่จำแนก |
| AI-BOM | การตั้งค่าในเครื่อง quantization/context ดัชนีน้ำหนัก ส่วนหัว/ขนาด GGUF/safetensors ชั้น Ollama อาร์ติแฟกต์ที่ระบุชัดได้ SHA-256 ทั้งไฟล์ เอาต์พุตคือ `aibom.cdx.json` รวมถึงส่วนหัว ONNX ความปลอดภัยของ import ใน pickle ของ PyTorch model card และ ref แคชของ Hugging Face และโมเดลที่เซิร์ฟเวอร์โมเดลระบุตอนเริ่มทำงาน | ตัวตน/revision/น้ำหนักโมเดล สายสืบทอดจากโมเดลแม่ model card/ใบอนุญาต แหล่งข้อมูลฝึก/ประเมิน |
| MBOM | SLSA provenance ที่ตรงกัน หรือการประกอบ/ทดสอบทางกายภาพที่ประกาศหรือรายงาน กลายเป็น `formulation` ใน `mbom.cdx.json` | ขั้นตอน/เครื่องมือ/อินพุต/เอาต์พุต/บันทึกการรัน CI หรือประวัติการประกอบ/กระบวนการ/การตรวจของผู้ผลิต |

## ชั้นการเก็บข้อมูล

| ชั้น | หลักฐานและขอบเขต |
|---|---|
| แพ็กเกจ OS | os-release/vendor release และฐาน RPM/DEB/APK สิทธิ์ ความเสียหาย และข้อมูล source-package/module-stream ที่หายอาจจำกัดผล |
| ฮาร์ดแวร์/เฟิร์มแวร์ | CPU/microcode/CPUID/โทโพโลยี/ตัวตน ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM ฟิลด์ RAID/HBA, RDMA, GPU VBIOS และ NIC ioctl ที่รองรับขึ้นกับไดรเวอร์ megaraid_sas ต้องใช้ข้อมูลส่งออก BMC IPMI ต้องใช้ root/โมดูลและเทียบ revision ผู้ผลิต อุปกรณ์ใน VM/คอนเทนเนอร์อาจอธิบายโฮสต์ทางกายภาพ |
| ทรัพย์สินภายนอก | Redfish ที่ขยายแล้ว fwupd, devlink หรือไฟล์ JSON รูปแบบร่วม เก็บรุ่น/สถานะที่รายงาน และทบทวนอุปกรณ์ที่ไม่จับคู่ |
| Windows/macOS | เมทาดาทาระบบ/OS/เฟิร์มแวร์และแอปที่ติดตั้งแบบเนทีฟ หลักฐาน Windows รวมการตรวจข้ามบิลด์ ส่วนพึ่งพาภายในแอปและอัปเดตผู้ผลิตต้องมีอินพุตเพิ่ม |
| ซอฟต์แวร์รันไทม์ | ตัวตนไฟล์ปฏิบัติการ/ไลบรารีที่แมปและเจ้าของแพ็กเกจภายในขอบเขตระบบไฟล์เดียวกัน ไฟล์ที่ถูกแทนให้หลักฐานสำหรับทบทวนการรีสตาร์ต |
| ตัวตนโฮสต์ | SHA-256 ของ machine-id/DMI UUID/ซีเรียล และป้ายทรัพย์สินที่ระบุสำหรับโฮสต์ `/` สิทธิ์อ่านซีเรียลและ placeholder ที่ใช้ร่วมกันกระทบข้อมูลที่มี การแฮชเป็นการใช้นามแฝง |
| ซ็อกเก็ตที่รอรับ | TCP LISTEN/UDP ที่ bind ใน namespace ตัวเก็บข้อมูล ระบุเจ้าของผ่าน FD โปรเซส การ bind เพียงอย่างเดียวไม่บอกการเข้าถึงผ่าน firewall ซ็อกเก็ตไม่มีเจ้าของยังเป็น `unattributedSockets` |
| การเชื่อมต่อขาออก | TCP ที่ ESTABLISHED ซึ่งพอร์ตในเครื่องไม่ใช่พอร์ตที่รอรับ รวมตามโปรเซสและปลายทาง สูงสุด 16,384 ซ็อกเก็ต การเชื่อมต่อจากพอร์ตในเครื่องคงที่ไปยังพอร์ตชั่วคราวของอีกฝั่งนับเป็นการเชื่อมต่อที่รับเข้ามา เห็นเฉพาะการเชื่อมต่อที่เปิดอยู่ขณะเก็บข้อมูล และเฉพาะโปรเซสของโฮสต์ การเชื่อมต่อไปยังพอร์ตที่โฮสต์นี้รอรับจะเชื่อมกับซ็อกเก็ตที่รอรับนั้นและโปรเซสเจ้าของ |
| งานตามกำหนดเวลา | `/etc/crontab`, `/etc/cron.d`, crontab ของผู้ใช้ และสคริปต์ใน `cron.{hourly,daily,weekly,monthly}` รวมถึงตัวตั้งเวลา systemd ที่เปิดใช้พร้อมกำหนดการ `On*` เก็บเฉพาะพาธสัมบูรณ์ของโปรแกรมและทิ้งอาร์กิวเมนต์ |
| ไฟร์วอลล์ | ไฟล์ iptables-save (RHEL/Debian/ufw) โซนเริ่มต้นของ firewalld พร้อมบริการ และเชน nftables ที่ hook input พร้อม include แบบระบุตรง เป็นข้อประกาศในไฟล์ ไม่ได้อ่านชุดกฎที่โหลดในเคอร์เนล base chain ที่ไม่มี policy ถือว่ายอมรับ ufw ที่ `ENABLED=no` บันทึกเป็น `disabled` และเฟรมเวิร์กที่ติดตั้ง systemd unit แล้วแต่ไม่ได้เปิดใช้และไม่ได้ทำงาน หรือถูก mask บันทึกเป็น `not-enabled` ทั้งสองกรณีไม่นับว่าใช้งานอยู่ กฎเฉพาะ loopback กฎตามสถานะ established และกฎที่ใช้เงื่อนไขปฏิเสธไม่นับเป็นพอร์ตที่เปิด การยอมรับ TCP/UDP ทั้งโปรโตคอลนับว่าเปิดทุกพอร์ตของโปรโตคอลนั้น ซ็อกเก็ตที่รอรับนอก loopback ในเนมสเปซเครือข่ายของโฮสต์ได้ `firewall-declared` เป็น `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined` หรือ `none-observed` เมื่อไม่พบการประกาศที่ใช้งานอยู่ ซ็อกเก็ตของคอนเทนเนอร์อยู่ในเนมสเปซเครือข่ายของตัวเองจึงไม่ได้ค่านี้ พอร์ตที่คอนเทนเนอร์เผยแพร่ผ่าน NAT ผ่านกฎ FORWARD ซึ่งไม่ได้ประเมิน |
| การตั้งค่า/รีบูต | SELinux, AppArmor, lockdown, FIPS, ตัวเลือกบูต allowlist การตั้งค่าเคอร์เนล `y`/`m` สัญญาณ reboot-required ต้นไม้โมดูลที่กำลังใช้ และเคอร์เนลตระกูลเดียวกันที่ใหม่กว่า ข้อมูลเหล่านี้ต้องตีความ การไม่มีสัญญาณไม่ยืนยันว่าไม่ต้องรีบูต |
| SSH | ข้อประกาศส่วนกลางในไฟล์ sshd ละ `Match` และไม่คำนวณลำดับความสำคัญ `Include` ที่มีผล |
| Taint/โมดูล | `kernel.tainted` แฟล็ก `/proc/modules` และ version/srcversion จาก sysfs เมื่อมี |
| ไฟล์ปฏิบัติการไม่ทราบที่มา | ไฟล์ที่รันในรากเดียวกันแต่ไม่ผูกแพ็กเกจ/ส่วนประกอบ/ผลิตภัณฑ์ ละ mount namespace อื่น ต้องตรวจเพิ่มเพื่อจำแนก |
| แหล่งแพ็กเกจ | apt Packages plain/gz/lz4, dnf history และ yumdb apt จับคู่ชื่อ ไม่รองรับรายการที่ถูกลบ dnf5 และ apk ละ URL/พาธในเครื่อง |
| บริการบูต | systemd wants/requires, unit/drop-in และ cgroup v1/v2 ใช้เฉพาะ ExecStart แรก ไฟล์ปฏิบัติการพาธสัมพัทธ์ไม่ผูกแพ็กเกจ custom slice อาจปรากฏว่าหยุด ไม่รองรับ SysV ตัวตั้งเวลาที่เปิดใช้บันทึกกำหนดการ `On*` และบริการที่เริ่ม |
| CPE ฮาร์ดแวร์ | Intel Xeon/Core, AMD EPYC/Ryzen, อุปกรณ์/BIOS Dell PowerEdge และอุปกรณ์ Lenovo ThinkSystem ที่รองรับ ช่องว่างพจนานุกรม/รุ่นอาจทำให้ไม่จับคู่ ละ CPE ของ HPE/BMC |
| ความสมบูรณ์แพ็กเกจ | แฮชไฟล์ปฏิบัติการ/ไลบรารีในฐาน RPM/dpkg/apk ละ config/ghost file งบ 8 GiB ต่อโฮสต์และ 1 GiB ต่อคอนเทนเนอร์ prelink อาจทำให้เกิดความไม่ตรงกันผิดพลาด |
| CBOM/ใบรับรอง | PEM/DER X.509 กุญแจ/อัลกอริทึมสาธารณะ public chain ของ JKS v1/v2 และแฮช alias ข้าม payload กุญแจเข้ารหัสและความสมบูรณ์ JKS ยังไม่ยืนยัน ละชื่อ subject/issuer กุญแจส่วนตัว เนื้อหา PKCS#12 trust store ของดิสทริบิวชัน และ bundle เกิน 20 ใบ รวมกุญแจสาธารณะของโฮสต์ SSH ส่วน `crypto-policies` และ MinProtocol/CipherString/Ciphersuites/Groups ใน `openssl.cnf` บันทึกเป็นข้อประกาศ โดยไม่ resolve `.include` และการเปิดใช้ section |
| เคอร์เนล | uname อิมเมจ/โมดูลที่ติดตั้ง vermagic และรุ่น RPM แยกเคอร์เนลที่รันกับที่ติดตั้งได้ การไม่มีหลักฐานโมดูลอาจเกิดจากคุณสมบัติ built-in |
| Livepatch | Linux livepatch sysfs สถานะดิบ Oracle Ksplice และรายงาน helper ทางเลือก Ksplice/Uptrack/Canonical ค่า boot/เคอร์เนล/เวลาไม่ตรงกันทำให้หลักฐานการใช้งานไม่ใช้ได้ การพิจารณาว่า CVE ใช้กับระบบหรือไม่ต้องวิเคราะห์แยก |
| Java | JDK/JRE release, manifest ของ JAR/WAR/EAR และเมทาดาทา Maven เมทาดาทา shaded ที่แก้หรือลบอาจจำกัดการระบุ |
| PHP | หลักฐานแพ็กเกจ/interpreter, Composer และ PEAR ที่ติดตั้ง ละแพ็กเกจที่มีแต่ lock และไม่ได้ติดตั้ง ความสามารถโจมตีขึ้นกับการตั้งค่า |
| snap/flatpak/conda | snap current revision/meta และ DEB ภายใน flatpak active/AppStream, conda-meta ใช้ PURL snap/flatpak ทั่วไป อาจไม่มีรุ่นหากไม่มี AppStream และเก็บเฉพาะชื่อ channel conda |
| Python | dist-info/egg-info, venv และเมทาดาทา bundle `.pyz`/`.pex` จริง เมทาดาทาที่ลบหรืออ่านไม่ได้จำกัดการเก็บ |
| Node.js/static JS | node_modules/runtime หลักฐาน jQuery/jQuery UI/Fancytree ในไฟล์และทรัพยากรเว็บ EAR/WAR/ZIP/JAR ชื่อไฟล์อย่างเดียวไม่พอ ใช้ได้ตามรูปแบบและขีดจำกัดสแกนที่รองรับ |
| Go/Rust | Go build info และ dependencies จาก cargo-auditable ELF ข้อมูลขาดทำให้ไม่ทราบ dependencies เมทาดาทาเสียหายหรือใหญ่เกินทำให้ผลบางส่วน |
| .NET | `.deps.json` ที่ publish, managed DLL และทรัพยากรรุ่น DLL เดี่ยว DLL เดี่ยวไม่ได้ NuGet PURL bundle ไฟล์เดียวต้องตรวจเพิ่ม |
| Ruby | specification/gem file ที่ติดตั้งและ default gem เฉพาะ Gemfile.lock หรือเมทาดาทาติดตั้งที่ถูกลบไม่เพียงพอ |
| เซิร์ฟเวอร์เนทีฟ | หลักฐานแพ็กเกจ/ไบนารีของ httpd, nginx, OpenSSL, OpenSSH, Redis, PostgreSQL, MySQL และ MariaDB สำเนาปรับแต่ง/stripped/static อาจยังไม่ทราบตัวตน |
| เซิร์ฟเวอร์ Java | Tomcat ServerInfo/manifest/catalina.jar เมทาดาทาผลิตภัณฑ์/การติดตั้ง/แพตช์ WebLogic/JBoss/WildFly `.patch_storage` อย่างเดียวไม่พิสูจน์แพตช์ที่ใช้งาน JEUS/รุ่นเชิงพาณิชย์ที่ไม่มี fixture จริงยังไม่ผ่านการยืนยัน |
| คอนเทนเนอร์ที่หยุด/อิมเมจ | Docker overlay2, containerd overlayfs รวม k3s/RKE2, rootful Podman/CRI-O overlay การสร้างรากชั่วคราวจำกัด 16 GiB/รากและตรวจพื้นที่ว่าง ไม่รองรับไดรเวอร์อื่น/rootless Podman ไม่มี listening socket |
| คอนเทนเนอร์ที่รัน | ราก procfs และเมทาดาทารันไทม์บนดิสก์ SBOM แยกใน `containers/<name>/` ละ volume/bind mount และ sandbox Kubernetes รากที่มองไม่เห็นมีเหตุผล ไม่มีการเชื่อม runtime API/ซ็อกเก็ต ผูกเฉพาะซ็อกเก็ตเจ้าของเป็นโปรเซสของคอนเทนเนอร์ |
| อาร์ไคฟ์อิมเมจ | Docker/OCI tar ของ Linux amd64 ที่ระบุชัด แฮชอาร์ไคฟ์ และ manifest digest ที่ตรวจสอบได้ตามการรองรับ ขอบเขตคือเนื้อหาอิมเมจ เคอร์เนล/รันไทม์โฮสต์ต้องมีการสังเกตแยก |
| AIX/Oracle | fileset ของ `aix-import`, interim fix, OPatch ต่อ Home และประวัติ SQL patch ทางเลือกจากสูงสุดแปด Home บนเซิร์ฟเวอร์ AIX เดียว สถานะการทำงานต้องมีหลักฐานแยก |

การติดตั้งด้วยตนเองคงตัวตนไดเรกทอรี/อินสแตนซ์ไว้ ชื่อและรุ่นตรงกันยังอาจเป็นคนละตำแหน่งหรือสถานะแพตช์ CPE ที่ระบุไม่ได้จะเว้นไว้ ใช้ตัวระบุที่ยืนยันแล้วและหลักฐานประกอบเพื่อทบทวนต่อ

รูปแบบเริ่มต้นคือ CycloneDX 1.6 และ SPDX 2.3 พร้อมตัวเลือก CycloneDX 1.7 [บัญชีรายการและการประเมินทรัพย์สิน](asset-inventory.th.md) อธิบาย `assess` การรองรับ OSV/CSAF รุ่นตรงตัว และสคีมาหลักฐาน [หลักฐาน BOM เพิ่มเติม](additional-bom.th.md) ครอบคลุมบริการ โมเดล และการผลิต

## สถานการณ์ทดสอบถดถอย

กรณีทดสอบครอบคลุม runtime PHP กับ Composer, runtime Node กับ node_modules, บิลด์ JDK เต็ม, ตัวตนการติดตั้ง/แพตช์ WebLogic, Tomcat ที่ติดตั้งเองและข้อประกาศ AJP/HTTP2, release ดิสทริบิวชัน httpd/mod_http2, ข้อประกาศ source/alias/rewrite ของ nginx, สำเนา OpenSSL CLI/libssl/libcrypto ที่แยกกัน และเคอร์เนล UEK/RHCK ที่รันกับที่ติดตั้ง fixture ทดสอบให้หลักฐานการระบุผลิตภัณฑ์ ต้องมีประกาศช่องโหว่ที่ตรงกันจึงจะสรุปช่องโหว่ได้
