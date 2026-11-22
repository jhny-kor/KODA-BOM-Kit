# การตรวจสอบ VM เคอร์เนลจริง Ubuntu 24.04.1

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
  <strong>ไทย</strong>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

นี่คือเครื่องมือทดสอบ KODA BOM Kit ไม่ใช่ส่วนพึ่งพาของไฟล์ปฏิบัติการที่ส่งไปยังเซิร์ฟเวอร์เครือข่ายแยก บูต Ubuntu Base **24.04.1 amd64** และเคอร์เนล Ubuntu ทางการ **6.8.0-47-generic / แพ็กเกจ 6.8.0-47.47** โดยตรงด้วย initramfs ปรับแต่ง QEMU user-mode หรือ fixture ไดเรกทอรีไม่เป็นหลักฐานการบูตเคอร์เนลจริง

Ubuntu Base มาจากมิเรอร์แจกจ่าย Ubuntu ที่เก็บถาวร ตรวจ SHA256SUMS.gpg ด้วย Ubuntu CD Image Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092` ใช้ Ubuntu archive keyring ใน rootfs ที่ยืนยันแล้วตรวจ noble-updates InRelease วันที่ 2024-10-18 จากบริการ Snapshot ทางการ เชื่อมสายตรวจสอบ Release ที่ลงนาม → Packages.xz → SHA-256 และขนาด DEB สองไฟล์ เก็บ URL อินพุต เช็กซัม บันทึกลายเซ็น และ ID อิมเมจ Docker ทั้งหมด

โฮสต์บิลด์ต้องมี Go, Python 3 พร้อม `jsonschema`, Docker และ GnuPG (`gpg`/`gpgv`) ใช้อิมเมจเครื่องมือ Oracle VM ซ้ำ ไม่ต้องติดตั้งเครื่องมือเหล่านี้บนเซิร์ฟเวอร์เป้าหมาย เรียกจากรากโครงการและแทน `<ID>` ด้วย ID รอบทดสอบจริง

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` ใช้การส่งออกแบบมีขอบเขตและ baseline อิสระจากชุด Oracle Ubuntu มีไดรเวอร์ loop ในตัว จึงโหลด `dummy.ko` จริงเพื่อตรวจการสังเกตโมดูล บันทึก uname, proc release ที่ทำงาน OS, SHA ตัวเก็บข้อมูล และโมดูลที่โหลดแบบอิสระ จากนั้นเทียบ SBOM ทั้งสองกับสคีมาทางการที่ตรึง เช็กซัม รุ่น/source/PURL ของ DEB ต้นฉบับ และเคอร์เนล/โมดูลที่ติดตั้ง รัน prepare, run, validate ใหม่ทุกครั้งที่ส่งไบนารีสุดท้ายตัวใหม่

rootfs ทดสอบใช้ `dpkg --unpack` แตก DEB ต้นฉบับและสร้างฐาน dpkg จริง อนุญาตข้ามข้อกำหนดส่วนพึ่งพาและคงแพ็กเกจเป็น unpack ไม่ถือว่าติดตั้ง apt ปกติหรือกำหนดค่าเสร็จแล้ว การบูต systemd เต็ม GRUB, UEFI/Secure Boot บริการใช้งานจริง และฮาร์ดแวร์ทางกายภาพต้องทดสอบแยก QEMU ไม่มี NIC/ดิสก์ Docker ใช้ `--network none`, rootfs อ่านอย่างเดียวและเอา capabilities ออก การติดตั้ง live patch เชิงพาณิชย์หรือแบบสมัครสมาชิกจริงอยู่นอกการทดสอบ

การตรวจสอบ 0.1.3 ใช้ `--max-files 0 --timeout 0` เพื่อปิดขีดจำกัดทั้งสองของตัวเก็บข้อมูล คง watchdog แยก 11 นาทีของ PID 1 และ timeout QEMU ฝั่งโฮสต์ไว้

เก็บ provenance บันทึกลายเซ็น บันทึก dpkg, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, SBOM ทั้งสอง และ `validation.json` ไว้ด้วยกัน คงรหัสออก 3 สำหรับเก็บบางส่วน ไม่เปลี่ยนเป็นรหัส 0 สำหรับเก็บครบ
