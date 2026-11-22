# ผลการตรวจสอบ

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

บันทึก KODA BOM Kit และรุ่นก่อนระบุวันที่ แฮช สภาพแวดล้อม ผลบางส่วน และส่วนที่ยังไม่ทดสอบ รุ่น 0.1.8 ทางการระบุแพ็กเกจ เช็กซัม และขอบเขต ไฟล์รุ่นใหม่ต้องมีผลทดสอบของตน

[รุ่นเผยแพร่ 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 2026-11-21 — แยกและรวม

`f0610ca-worktree-00ed83f2acd8` ทดสอบ `scan --separate-boms`, `bom-split`, `bom-merge`, `domain-bom` กับผลเก่า 0.1.6 สองชุด เปรียบเทียบทุกรายการและความสัมพันธ์ เพิ่มความสัมพันธ์ระหว่างรากหนึ่งเส้นต่อการรวม ID ใบรับรอง Ubuntu สิบคู่เป็นยี่สิบตำแหน่งที่เก็บครบ ไม่มี ID ซ้ำหลังรวม Linux ARM64 รวม BOM ที่สังเกตได้สี่ชนิดกับตัวอย่าง OpenAPI โมเดล SLSA และการผลิต เชื่อม TCP 18443 จริงกับ Perl และแพ็กเกจ สคีมาและแฮชผ่าน ลายเซ็นและหลักฐานหน้างานต้องตรวจแยก

| ชุดเก็บ | องค์ประกอบ ก่อน / หลัง | ความสัมพันธ์ ก่อน / หลัง |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — ความสัมพันธ์ขณะทำงาน

`f0610ca-worktree-06f22395e26f` สร้าง OBOM ใหม่จากผลบางส่วนสองชุด นับ socket ตาม namespace/process Debian ARM64 เชื่อม `127.0.0.1:18443/tcp` กับ `/usr/bin/perl` และ `perl-base` ตรวจหมายเลข Redfish สามรายการ ตัวอย่าง TLS ความสัมพันธ์ build สองเส้น และเช็กซัม 11 รายการ OBOM สร้างใหม่ตรงกันทุกไบต์ เชื่อมทรัพยากร Kubernetes จำลองห้ารายการกับ ID container เต็ม ยังไม่ได้ตรวจคลัสเตอร์จริง อุปกรณ์จริง หรือ TLS จริง

| ชุดเก็บ | Container | Socket host + container | เชื่อมแพ็กเกจ host + container | ความสัมพันธ์ที่เทียบ |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — แก้ Daybreak 12 รายการ

แก้ข้อค้นพบของ KODA-SBOM-Maker `cc86c1b` ครอบคลุมแยกค่า Go แฮชสตรีมเดียวกับที่แตก จำกัด 256 ชั้นและใช้แฮชซ้ำ จำกัด ZIP/ZIP64 ตรวจ whiteout จองโฟลเดอร์ผลลัพธ์ ทำดัชนีและจำกัดงานประกาศ ปฏิเสธ Python optimized อ่านในรากที่ตรวจแล้ว จัดการ ID สั้น เทียบ RPM epoch และเดินไดเรกทอรีครั้งละ 256 รายการพร้อมยกเลิกได้

Go, vet และการตรวจแพ็กเกจผ่านบน macOS ARM64 ใช้ Go 1.26.11 / Syft 1.57.1 สร้าง Linux amd64 แบบ static ออฟไลน์ เช็กซัม 306 รายการและ CLI/ไดเรกทอรีบน Debian ปิดเครือข่ายผ่าน ก่อน/หลังตรงกันที่ 88 แพ็กเกจ OS หนึ่ง อุปกรณ์ 20 และไดรเวอร์ 15 ทั้งสองเป็น partial พร้อมเหตุผล แพลตฟอร์มอื่นผ่านการคอมไพล์ข้าม แต่ยังไม่รันหรือทดสอบ VM ใหม่

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Linux, Go และ vet ผ่านใน Docker Desktop `7.0.14-linuxkit` CPU ตรงกับ lscpu อ่านค่าเคอร์เนล 1,736 รายการ Debian มีแพ็กเกจท้องถิ่นไร้แหล่งหนึ่งจาก 147 Rocky พบจาก repository 167 และแยก local/ไม่มีบันทึก container รันเก้า หยุด 14 และ image ไม่ใช้ 11 สร้าง 35 SBOM ในประมาณ 3 นาที 30 วินาที จำนวนแพ็กเกจ 796, 71, 51 ตรงกัน overlay2 เก็บ curl และ busybox ที่ไม่ใช้ container ถูกลบเป็น `not_collected` ยังไม่ตรวจ x86 จริง systemd Kubernetes/k3s/Podman/CRI-O และ VM ใหม่

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` ตรวจตัวตน socket จริง container 16 และโมดูลนอกต้นไม้ห้ารายการ ตรวจไฟล์ 735 ประมาณ 89 MB พบไฟล์แก้หนึ่งและย้าย/ขาดหนึ่งตามที่สร้างไว้ ตรวจอายุและกุญแจอ่อน RSA-1024 กับ ECDSA P-384 โดยไม่ส่งออก private key ฮาร์ดแวร์ snap/flatpak/conda และการตั้งค่าบางอย่างใช้ข้อมูลจำลอง ยังไม่ตรวจ RAID/NIC/BMC จริง SELinux งานจริง runtime อื่นและ VM ใหม่

## 2026-11-18 — 0.1.6-dev

Go, vet สคริปต์ช่วยและ shell ผ่าน Linux amd64/ARM64 และการสำรวจพื้นฐาน macOS ARM64 จริงผ่านสคีมา/เช็กซัม Windows คอมไพล์เท่านั้น ทดสอบไฟล์ลบ/เปลี่ยน แฮช image และกฎท้องถิ่น Tracker ในเครื่องอ่าน CycloneDX สองรุ่นได้ ยังไม่ตรวจ production/เบราว์เซอร์ เก็บความหมายใบอนุญาต 704/811 และส่วนเพิ่ม 107 จำนวนเช็กซัมขึ้นกับขอบเขต

## ประวัติ 0.1.2–0.1.5

0.1.5 เพิ่มความสัมพันธ์ pnpm/Maven POM, 0.1.4 เพิ่มสคริปต์ไดเรกทอรี, 0.1.3 เพิ่มจำนวนไฟล์/เวลา เทียบแฮชกับ `release.json`, `VERIFICATION.json`, `dist/evidence/v0.1.x/final-verification.json` ที่ให้มา 0.1.2 รันทวน Ubuntu และ Oracle สองเคอร์เนลด้วยไฟล์สุดท้าย การติดตั้งไคลเอนต์สมัครสมาชิกและแพตช์จริงอยู่นอกการทดสอบจำลอง

## 2026-10-29 — โปรแกรมและ Oracle VM

ผ่าน 68 การตรวจ Linux และ vet ใช้ uid 65534 ข้อมูล/rootfs อ่านอย่างเดียว ไม่มี capability/เครือข่าย ตรวจสคีมา PURL canary และข้อผิดพลาด container Oracle มี RPM 182, Python 5, binary 2 trace guest syscall พบการเรียกเครือข่ายและ execve เพิ่มศูนย์ครั้ง Tracker SQLite แยกรับสองรูปแบบด้วย HTTP 202 ตัวอย่างเล็ก 0.1.0 ใช้ 0.78 วินาที RSS สูงสุด 219,644 KiB

VM Oracle Linux 8.2 บูต RHCK/UEK ลงนาม uname/proc และ loop ตรงกัน แต่ละตัวมี 5,516 องค์ประกอบ รวม RPM 186 เคอร์เนลสอง โมดูล 5,321 Python 5 binary 2 ต้นไม้ RHCK 2,478 และ UEK 2,843 โมดูล สคีมาและเช็กซัมตัวละห้าผ่าน ออก 3, partial และ context completed เก็บเหตุผลไฟล์ป้องกัน ลิงก์นอกขอบเขต OpenSSH ขัดแย้ง และคำเตือน Syft

| Kernel | เก็บ / รวม วินาที |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## ข้อจำกัดหลักฐาน

VM แรกใช้แฮช 0.1.0 ด้านล่าง รุ่นถัดไปมีรายงานของตน ยังไม่ครอบคลุม x86 จริง OS/บริการเต็มรูปแบบ และแพตช์ผู้ขายจริง QEMU guest trace และ ptrace native ใช้สภาพแวดล้อมต่างกัน การเก็บขณะทำงานอาจรวมข้อมูลต่างเวลา เลือกช่วงเปลี่ยนแปลงน้อยหรือ snapshot อ่านอย่างเดียว รุ่นแพ็กเกจและสิ่งที่ไม่พบอย่างเดียวไม่พอยืนยันผลกระทบหรือการแก้ CVE

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## เอกสาร

[ใช้งานในเครือข่ายปิดและตรวจผล](air-gapped.th.md) · [การสร้างและตรวจสอบ](verification.th.md) · [ผลการตรวจสอบ](verification-results.th.md)
