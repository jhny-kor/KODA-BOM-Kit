# บัญชีรายการฮาร์ดแวร์และซอฟต์แวร์

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
  <strong>ไทย</strong>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


ใช้ไบนารี `koda-bom` ที่บิลด์สำหรับ OS และ CPU เป้าหมาย คำสั่ง Linux `scan` เก็บแพ็กเกจและฮาร์ดแวร์โฮสต์ ส่วน Windows/macOS `platform-inventory` เรียกเครื่องมือบัญชีรายการในเครื่องที่ OS จัดให้

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

ใน Windows PowerShell ใช้ `.\koda-bom.exe platform-inventory --output-dir .\reports` การสแกนไดเรกทอรี/อิมเมจ Linux ใช้ระบบไฟล์ที่เลือก สังเกตฮาร์ดแวร์จริงระหว่างเก็บโฮสต์ `/` เมื่อเปิด context อาร์ไคฟ์ Docker/OCI ที่ส่งเข้ามาโดยตรงรองรับอิมเมจ Linux amd64 ส่งเอกสาร CycloneDX ที่ตรวจสอบแล้วไปยัง Tracker และเก็บรูปแบบทั้งสองพร้อมเช็กซัมไว้ด้วยกัน

## หลักฐานที่เก็บ

| ด้าน | การเก็บและการตีความ |
|---|---|
| ฮาร์ดแวร์ | CPU/microcode, mitigations, บอร์ด, BIOS/UEFI, ESRT, PCI/ไดรเวอร์, NVMe/SCSI, USB และ TPM อ่าน RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS และ amdgpu `vbios_version` เมื่อระบบเปิดเผย เฟิร์มแวร์ NIC ใช้ ioctl อ่านอย่างเดียวเทียบเท่า `ethtool -i` ส่วน megaraid_sas ต้องใช้หลักฐานส่งออก เมื่อรันด้วย root ตาราง SMBIOS ดิบให้ผู้ผลิต หมายเลขชิ้นส่วน ความจุ และความเร็วของโมดูลหน่วยความจำ รุ่นและกำลังไฟของแหล่งจ่ายไฟ และสล็อตพร้อมที่อยู่ PCI หมายเลขซีเรียลบันทึกเป็น SHA-256 เท่านั้น |
| BMC | IPMI `Get Device ID` แบบอ่านอย่างเดียวผ่าน `/dev/ipmi0` ต้องใช้ root และ `ipmi_si`/`ipmi_devintf` บันทึก firmware revision ผู้ผลิต IANA, product ID และ auxiliary revision อธิบายกรณีอุปกรณ์ไม่ปรากฏ หากต้องเทียบป้ายบิลด์ของผู้ผลิตให้ใช้ Redfish export |
| ตัวตน CPU | x86 `cpuidSignature` และ `familyModelStepping` โทโพโลยี socket/core ชื่อผู้ผลิต/core ของ ARM และ revision เช่น `r3p1` ARM core ที่ไม่รู้จักจะเก็บตัวระบุดิบไว้ USB `bcdDevice` ยังคงเป็นตัวระบุรุ่นอุปกรณ์ |
| ทรัพย์สินภายนอก | ออบเจ็กต์ Redfish ที่ขยายแล้ว fwupd JSON, devlink JSON และสคีมาร่วมด้านล่าง เฟิร์มแวร์ที่รันกับที่จัดเก็บเป็นข้อมูลสังเกตแยก ฟิลด์ที่มีขึ้นกับผู้ผลิต/รุ่น |
| รันไทม์ | การเปลี่ยนไฟล์ปฏิบัติการ/ไลบรารีร่วม ตัวระบุไฟล์ และแพ็กเกจเจ้าของที่ระบุได้แน่นอน การเปลี่ยนไฟล์ให้ `restart_review` รุ่นแพ็กเกจที่ติดตั้งเพียงอย่างเดียวไม่ยืนยันรุ่นในหน่วยความจำ |
| ตัวตนโฮสต์ | SHA-256 ของ machine-id และ DMI UUID/product/board serial ที่ปรับรูปแบบแล้วบนโฮสต์ `/` แม้ใช้ `--no-context` แปลง machine-id/UUID เป็นตัวพิมพ์เล็ก ตัดช่องว่างหัวท้ายซีเรียล ละ placeholder ที่ใช้ร่วมกันและ UUID ศูนย์ แฮชซีเรียลเป็นข้อมูลนามแฝงที่อาจคาดเดาได้ `--asset-tag` บันทึกป้ายหนึ่งบรรทัดที่ระบุชัดเจนได้สูงสุด 128 ตัวอักษร ขอบเขตคอนเทนเนอร์เป็น `container-visible` |
| ซ็อกเก็ต | TCP LISTEN และ UDP ที่ยังไม่เชื่อมต่อใน network namespace ของตัวเก็บข้อมูล จับคู่ผ่าน file descriptor ของโปรเซส `bindScope` เป็น `all-interfaces`, `loopback` หรือ `address` การเข้าถึงผ่าน firewall/route ต้องมีหลักฐานแยก ซ็อกเก็ตไม่มีเจ้าของอยู่ใน `context.json.unattributedSockets` การเชื่อมต่อ TCP ขาออกที่ established บันทึกตามโปรเซสและปลายทางใน `outboundConnections` พร้อม `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`) |
| ความปลอดภัยและรีบูต | โหมด SELinux ปัจจุบัน/ที่ตั้งค่า สถานะและจำนวน profile ของ AppArmor, lockdown, FIPS และตัวเลือกบูตใน allowlist ตัดข้อมูลรับรองและอาร์กิวเมนต์อื่นออก `kernelConfig` บันทึก `y`/`m` จาก `/proc/config.gz` หรือ `/boot/config-<running-kernel>` สัญญาณรีบูตครอบคลุม `/run/reboot-required` โมดูลเคอร์เนลที่กำลังรันหาย และเคอร์เนลติดตั้งใหม่กว่าในตระกูล release เดียวกัน เมื่อพบสัญญาณตั้ง `reboot.recommended=true` มิฉะนั้นเป็น `not_observed` การจับคู่ตระกูลใช้ฮิวริสติกจากสตริง release |
| SSH | ข้อประกาศส่วนกลางใน `sshd_config` และ `sshd_config.d/*.conf` รวม `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding` ละบล็อก `Match` ค่าที่มีผลขึ้นกับลำดับ `Include` |
| โมดูลเคอร์เนลและโปรแกรมไม่ทราบที่มา | `kernel.tainted` และ `taintedModules` มีชื่อ แฟล็ก `O`/`E`/`P` รุ่น และ srcversion `unidentifiedExecutables` บันทึกพาธ/PID ของโปรแกรมรากเดียวกันที่ไม่พบเจ้าของแพ็กเกจ/ส่วนประกอบ/ผลิตภัณฑ์ รองรับการจับคู่พาธ usr-merge |
| ความสมบูรณ์ | เทียบแฮชฐาน RPM/dpkg/apk กับไฟล์ปฏิบัติการและ `.so` ละไฟล์ config และ ghost ข้อค้นพบ `modified`/`missing` อยู่ใน `collection.json.integrity.findings` และคุณสมบัติส่วนประกอบ งบแฮชคือ 8 GiB ต่อโฮสต์และ 1 GiB ต่อคอนเทนเนอร์ เมื่อหมดเป็น `partial` prelink อาจทำให้ไม่ตรงกัน |
| แหล่งแพ็กเกจ | apt `Packages` (plain/gz/lz4) จับคู่ชื่อ ส่วน dnf history และ yum `from_repo` ให้ ID repository ค่าเป็น `repository`, `local-file`, `not-recorded` ประวัติที่หาย dnf5 และ apk ไม่รองรับ ละ URL repository/พาธในเครื่อง คัดลอกฐาน dnf ไปไดเรกทอรีชั่วคราวแล้วเปิดอ่านอย่างเดียว |
| บริการบูต | systemd `*.wants`/`*.requires` ข้อประกาศ unit/drop-in, `ExecStart` แรก socket activation และ PURL แพ็กเกจ ละ unit ที่ถูก mask การมีโปรเซสใน `system.slice` ใช้ตัดสิน running/stopped บนโฮสต์ custom slice อาจปรากฏว่าหยุด ตัวตั้งเวลาที่เปิดใช้บันทึกกำหนดการ `On*` และบริการที่เริ่ม |
| CPE ฮาร์ดแวร์ | รูปแบบ Intel Xeon/Core, AMD EPYC/Ryzen, อุปกรณ์/BIOS Dell PowerEdge และอุปกรณ์ Lenovo ThinkSystem ที่รองรับ รุ่นที่ไม่รู้จัก HPE และ BMC จะไม่ถูกเดา CPE |
| ใบรับรอง | ลายนิ้วมือ X.509 สาธารณะ อายุใช้งาน อัลกอริทึม ขนาดกุญแจ และสถานะ ตัวบ่งชี้อ่อนแอรวมลายเซ็น SHA-1/MD5, RSA ต่ำกว่า 2048 บิต และ DSA อัลกอริทึมดั้งเดิมมี `nistQuantumSecurityLevel=0` ละชื่อ subject/issuer และข้อมูลกุญแจส่วนตัว ข้าม trust store ของดิสทริบิวชันและ bundle ที่เกิน 20 ใบ บันทึกกุญแจสาธารณะของโฮสต์ SSH (`etc/ssh/ssh_host_*_key.pub`) พร้อมลายนิ้วมือ SHA-256 แบบ OpenSSH ด้วย |
| แอปพลิเคชัน | snap revision ที่ใช้งานและแพ็กเกจ Debian ภายใน flatpak/AppStream release ที่ใช้งาน เมทาดาทา conda พร้อมชื่อ channel เมทาดาทา `.pyz`/`.pex`, JAR, static JS และหลักฐานบิลด์ Go/Rust เก็บแฮชอาร์ติแฟกต์ OCI/Docker และ digest ที่ตรวจสอบได้ |

## คอนเทนเนอร์และเอาต์พุต

คอนเทนเนอร์ที่รันมีผลเก็บแยกใน `containers/<name>/` ชื่อ Kubernetes ใช้ namespace, pod และ container และเติม ID 12 ตัวเมื่อชนกัน อ่านเมทาดาทา Docker, containerd, Podman และ CRI-O จากดิสก์ ไม่ติดต่อซ็อกเก็ต runtime API ระบุตำแหน่งรากที่เมานต์ผ่านการจับคู่อุปกรณ์ใน mountinfo รวมชั้นอิมเมจ/ชั้นเขียนได้ แต่ละ volume/bind mount ออก ซ็อกเก็ตคอนเทนเนอร์ผูกกับโปรเซสของคอนเทนเนอร์นั้น ให้ความสำคัญกับเจ้าของแพ็กเกจก่อน และไฟล์ปฏิบัติการ Go ใช้ main module รากที่หายหรือ timeout ให้ `not_collected` พร้อมเหตุผล `--no-containers` ปิดการเก็บนี้

คอนเทนเนอร์ที่หยุดและอิมเมจในเครื่องที่ไม่ได้ใช้รองรับ Docker overlay2, containerd overlayfs (รวม k3s/RKE2) และพื้นที่เก็บ rootful Podman/CRI-O คัดลอกชั้นไปไดเรกทอรีเอาต์พุตชั่วคราว จัดการ whiteout/opaque แล้วตรวจและลบ ตัด device file และบิต set-ID ออก ข้ามรากที่เกิน 16 GiB หรือพื้นที่ว่างต่ำกว่าขนาดราก + 1 GiB ผลใช้ `state: stopped` หรือ `state: image` และไม่มี listening socket การเปลี่ยนรันไทม์พร้อมกันอาจทำให้เก็บไม่ได้ ไม่รองรับ storage driver Docker อื่นและ rootless Podman `--no-images` ปิดเส้นทางนี้

การเก็บเริ่มต้นเขียนเจ็ดโปรไฟล์ใน `boms/` และรวมเป็น `bom.cdx.json` AI-BOM ใช้ `aibom.cdx.json` เอาต์พุตที่รองรับการใช้งานเดิมมี CycloneDX 1.6 `sbom.cdx.json` และ SPDX 2.3 `sbom.spdx.json` ตัวเลือก `--cyclonedx-17` เพิ่มไฟล์ 1.7 SPDX ใช้ `OTHER` และ annotation สำหรับชนิดที่ไม่มีตัวแทนตรง ตัวตนโฮสต์ใช้ `koda:host:*` ตัวตนคอนเทนเนอร์ใช้ `koda:container:*` ซ็อกเก็ตใช้ `koda:runtime:listening`/`koda:runtime:bind-scope` ตรวจ `assets.json`, `context.json`, `collection.json`, `inventory.syft.json` และตรวจสอบไฟล์ด้วย `SHA256SUMS`

## หลักฐานทรัพย์สินรูปแบบร่วม

ส่งได้สูงสุดแปดไฟล์ ไฟล์ละไม่เกิน 8 MiB `parentId` อ้างถึง `id` ทรัพย์สินในไฟล์เดียวกัน ละรุ่นที่ไม่ทราบ Redfish ต้องมีออบเจ็กต์ทรัพย์สิน/เฟิร์มแวร์ที่ขยายแล้วนอกเหนือจากรายการ URI ค่า SHA-256 อินพุตระบุไฟล์ที่นำเข้า

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

## ทรัพย์สินการเข้ารหัสและเซสชัน TLS

ใบรับรอง X.509 กุญแจสาธารณะ และอัลกอริทึมเป็นส่วนประกอบ `cryptographic-asset` ความสัมพันธ์ issuer ที่เป็นไปได้จะตรวจลายเซ็น ข้อกำหนด Nginx/Apache/sshd ใน allowlist บันทึกเป็นหลักฐานการตั้งค่า เก็บ public chain ของ JKS v1/v2 และ SHA-256 ของ alias ข้ามกุญแจเข้ารหัส และความสมบูรณ์ของ store แบบไม่ใช้รหัสผ่านเป็น `not-verified`

นำเข้าเมทาดาทาสาธารณะ PKCS#12/HSM/KMS ด้วย `--asset-evidence` รายการ `related-crypto-material` อาจมีชนิด/ขนาด/สถานะกุญแจและ `algorithmRef` รวมทั้ง `properties.storageType` กับ `keyAlias` ผู้ใช้กุญแจมี `dependsOn` ชี้ไปเมทาดาทากุญแจในไฟล์เดียวกัน

ตัวอย่างต่อไปนี้นำเข้าการเจรจา TLS ที่วัดโดยอิสระ แทนลายนิ้วมือ endpoint และเวลาด้วยข้อมูลสังเกตจริง แฮชใบรับรองที่ตรงกันเชื่อมบริการ → โปรโตคอล → ใบรับรอง

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

## การประเมินประกาศช่องโหว่แบบออฟไลน์

ใช้ไบนารีเดิมประเมินผลที่เก็บถาวรอีกครั้งด้วยไฟล์ประกาศใหม่

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--context` และ `--kev` เป็นตัวเลือก เมื่อใช้ context จะตรวจทั้ง SBOM และ context กับ `SHA256SUMS` ของชุดเก็บนั้น KEV เพิ่มข้อมูลจัดลำดับความสำคัญ อินพุตที่รองรับคือกฎชัดเจนด้านล่าง OSV ที่ระบุรุ่น/PURL ที่ได้รับผลกระทบแบบตรงตัว และ CSAF 2.0 ที่ระบุ product ID ตรงตัว/สถานะไม่มีเงื่อนไข ช่วงรุ่นหรือเงื่อนไข/ชุดผลิตภัณฑ์ที่ไม่รองรับจะหยุดการประเมินพร้อมเหตุผล

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

ใช้ distro ID เฉพาะ release และรุ่นแพ็กเกจตรงตัว รุ่น SBOM/PURL ขัดแย้งกันให้ `review_required` พิจารณา RPM epoch ด้วย แต่ละรอบจำกัด 1,000,000 รายการรุ่นตรงตัว กฎชัดเจนรองรับ `supportEndsAt` และ `affectedSemver` สำหรับระบบนิเวศซอฟต์แวร์ที่รองรับ ไฟล์ที่ถูกแทน/เฟิร์มแวร์ที่จัดเก็บจะกระตุ้นการทบทวนการเปิดใช้งาน ทรัพย์สินไม่ทราบชนิดและรุ่นที่ไม่อยู่ในประกาศต้องทบทวน ตรวจอุปกรณ์ Linux/Windows จริงเทียบกับบัญชีผู้ผลิต บัญชีรายการ Windows/macOS แบบเนทีฟเน้น OS ฮาร์ดแวร์ และแอปที่ติดตั้ง

## การสังเกตการเข้าถึง TCP

`--network-evidence` จับคู่ผล TCP ที่วัดไว้กับซ็อกเก็ต OBOM ของโฮสต์หรือผลที่เก็บถาวร `hostField` เป็น `machineIdSha256`, `productUuidSha256` หรือ `assetTag` ที่กำหนดชัดเจน `scope` เป็น `host` หรือ ID คอนเทนเนอร์เต็ม 64 ตัว

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

ผลเป็น `connected`, `refused`, `timed-out` เจ้าของที่กำกวมหรือซ็อกเก็ตที่ไม่พบจะยังไม่จับคู่ แต่ละจุดวัดและเวลาต้องมีข้อมูลสังเกตของตนเอง ตัวเก็บข้อมูลไม่ทดสอบเชื่อมต่อ ดู[ตารางขอบเขต](support-matrix.th.md)และ[หลักฐาน BOM เพิ่มเติม](additional-bom.th.md)
