<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="docs/badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="README.tr.md"><img src="docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="LICENSE"><img src="docs/badges/license.svg" alt="Apache-2.0"></a>
  <a href="docs/support-matrix.th.md"><img src="docs/badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>เก็บข้อมูลซอฟต์แวร์ ฮาร์ดแวร์ และหลักฐานการทำงานของเครื่อง Linux ด้วยไฟล์ปฏิบัติการเพียงไฟล์เดียวแบบออฟไลน์ KODA BOM Kit สร้างบัญชีรายการส่วนประกอบ CycloneDX เจ็ดประเภท รายการรวม และบัญชีซอฟต์แวร์ในรูปแบบ SPDX</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><b>ดาวน์โหลด v0.1.8</b></a> ·
  ผู้เขียนต้นฉบับ <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">คลังโค้ดทางการ</a>
</p>

## เริ่มต้นใช้งาน

ดาวน์โหลดไฟล์บีบอัดสำหรับ Linux amd64 และไฟล์ SHA-256 ที่ตรงกัน คัดลอกทั้งสองไฟล์ไปยังไดเรกทอรีว่างบนเซิร์ฟเวอร์เป้าหมาย แล้วเรียกใช้คำสั่งด้านล่าง เซิร์ฟเวอร์ไม่จำเป็นต้องติดตั้ง Go ดาวน์โหลดแพ็กเกจ หรือติดตั้งฐานข้อมูลช่องโหว่

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## ไฟล์ผลลัพธ์

บรรทัดสุดท้ายจะแสดงพาธของไดเรกทอรีที่สร้างขึ้นใน `bom-output/` เปิด `bom.cdx.json` เพื่อดูรายการรวม ส่วนรายการทั้งเจ็ดประเภทอยู่ใน `boms/`

| ไฟล์ | ข้อมูลที่บันทึก |
|---|---|
| `boms/sbom.cdx.json` | แพ็กเกจ ไลบรารี และแอปพลิเคชันที่ติดตั้ง |
| `boms/hbom.cdx.json` | อุปกรณ์ เฟิร์มแวร์ และไดรเวอร์ |
| `boms/cbom.cdx.json` | สินทรัพย์ด้านการเข้ารหัส เช่น ใบรับรองและอัลกอริทึม |
| `boms/obom.cdx.json` | ความสัมพันธ์ที่ตรวจพบระหว่างบริการ โปรเซส ซ็อกเก็ต และแพ็กเกจ |
| `boms/aibom.cdx.json` | ไฟล์โมเดลในเครื่อง ค่าน้ำหนัก และข้อมูลกำกับที่ผู้ใช้ส่งให้ |
| `boms/saasbom.cdx.json` | บริการที่ระบุในเอกสาร OpenAPI หรือรายการบริการ |
| `boms/mbom.cdx.json` | กระบวนการผลิตและการบิลด์ตามหลักฐานที่ให้มา |

หากไม่พบหลักฐานที่เกี่ยวข้อง รายการบางประเภทอาจว่างเปล่า ตรวจสอบสถานะหลักฐานและ `collection.json` เพื่อดูสาเหตุ สามารถส่ง `sbom.cdx.json` หรือ `sbom.spdx.json` จากไดเรกทอรีหลักไปยัง Tracker ได้ รูปแบบเริ่มต้นคือ CycloneDX 1.6 และ SPDX 2.3 เพิ่ม `--cyclonedx-17` เพื่อสร้าง CycloneDX 1.7 พร้อมกัน

เมื่อต้องการรวมรายการอีกครั้ง ให้คัดลอกไดเรกทอรี `boms/` ทั้งหมด รวมถึงไฟล์กำกับ ความสัมพันธ์ และผลรวมตรวจสอบ กำหนด `run_dir` ให้เป็นพาธที่เครื่องมือแสดงเมื่อเก็บข้อมูลเสร็จ

```sh
(
  cd koda-bom-linux-amd64-0.1.8-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## เอกสาร

- [การติดตั้งแบบออฟไลน์และการตรวจผล](docs/air-gapped.th.md)
- [คำสั่งเก็บข้อมูลและไฟล์ผลลัพธ์](docs/collector-guide.th.md)
- [หลักฐานด้านฮาร์ดแวร์ การเข้ารหัส และการทำงาน](docs/asset-inventory.th.md)
- [รายการบริการ โมเดล AI และกระบวนการผลิต](docs/additional-bom.th.md)
- [แพลตฟอร์มที่รองรับและขีดจำกัดการเก็บข้อมูล](docs/support-matrix.th.md)
- [ขั้นตอนการบิลด์และการตรวจสอบ](docs/verification.th.md)
- [ผลและขอบเขตการทดสอบ](docs/verification-results.th.md)

### คู่มือซอร์สโค้ดและการทดสอบ

- [การนำเข้าข้อมูลสินทรัพย์ภายนอก](internal/assetimport/README.th.md)
- [บัญชีรายการตามแพลตฟอร์ม](internal/platforminventory/README.th.md)
- [การระบุผลิตภัณฑ์](internal/products/README.th.md)
- [Oracle Linux VM](tests/oracle-vm/README.th.md)
- [Ubuntu VM](tests/ubuntu-vm/README.th.md)

## สัญญาอนุญาตและการระบุผู้เขียน

KODA BOM Kit เผยแพร่ภายใต้สัญญาอนุญาต Apache-2.0 เอกสารด้านล่างระบุผู้เขียนต้นฉบับและสัญญาอนุญาตของส่วนประกอบที่รวมอยู่ในชุดเผยแพร่ [Apache-2.0](LICENSE) · [ประกาศของผู้เขียน](NOTICE) · [ประกาศของบุคคลที่สาม](THIRD_PARTY_NOTICES.th.md)
