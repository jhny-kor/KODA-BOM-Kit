# ชุดตรวจสอบการบูตเคอร์เนล Oracle Linux 8.2 โดยตรง

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` เป็น **PID 1 ของ VM ตรวจสอบ** สำหรับ KODA BOM Kit ใช้ข้อกำหนด `//go:build ignore` เพื่อแยกออกจากการทดสอบแพ็กเกจ Go ปกติ ให้บิลด์โดยระบุไฟล์ตามคำสั่งนี้

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker และ QEMU เป็นเครื่องมือตรวจสอบบน PC บิลด์ ส่งไฟล์ปฏิบัติการ `koda-bom` ไปยังเซิร์ฟเวอร์เครือข่ายแยก ชุดตรวจสอบและตัวแปล Python ไม่ใช่ส่วนพึ่งพาของไฟล์ที่นำไปใช้งาน

## ขั้นตอนทำซ้ำ

runner จำลอง x86_64 ด้วย TCG ในคอนเทนเนอร์ QEMU บนโฮสต์บิลด์ ARM64 เกสต์ใช้ RAM 4 GiB และ 2 vCPU ส่วนคอนเทนเนอร์จำกัดหน่วยความจำ 6 GiB เรียกจากรากโครงการบน PC ภายนอก แทน `<ID>` ด้วย ID จริงที่ `run.py` แสดง และเก็บรายงานก่อนหน้าไว้

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

โฮสต์ตรวจสอบต้องมี `jsonschema` และตรวจแบบออฟไลน์ด้วยสคีมาทางการที่ตรึงไว้ใน `tests/schemas` การดาวน์โหลดระหว่างเตรียมต้องใช้เครือข่าย แต่ VM เคอร์เนลทำงานโดยไม่มีการเชื่อมต่อภายนอก เก็บ ID อิมเมจที่ใช้จริงเพราะแท็กเปลี่ยนได้

`prepare.py` ตรวจ SHA-256 และขนาด RPM สี่ไฟล์ที่ตรึงใน [kernels.json](../../../tests/oracle-vm/kernels.json) รวม 120,245,036 ไบต์ และลายนิ้วมือกุญแจลงนาม Oracle Linux 8 นำเข้ากุญแจสาธารณะในฐาน RPM ของคอนเทนเนอร์ Oracle ทดสอบใหม่ ตรวจลายเซ็นด้วย `rpm -Kv` แล้วติดตั้งเคอร์เนลด้วย `--nodeps --noscripts --notriggers` เพื่อสร้างระบบไฟล์สำหรับตรวจอิมเมจเคอร์เนล โมดูล และเมทาดาทา RPM สคริปต์ติดตั้งปกติ dracut และการตั้งค่า GRUB อยู่นอกขั้นตอนนี้

เรียก `prepare.py` อีกครั้งด้วยไบนารีเผยแพร่สุดท้ายในไดเรกทอรีเดิม เพื่อสร้างตัวเก็บข้อมูล PID 1 และ initramfs ใหม่จากระบบไฟล์เคอร์เนล/RPM ที่แคชไว้ บูต VM ทั้งสองอีกครั้งและเทียบ **SHA-256 ของไบนารีสุดท้าย** กับ baseline ผล VM ของบิลด์เก่าไม่สามารถยืนยันรุ่นเผยแพร่ใหม่ได้

เก็บ `input-provenance.json`, `rpm-signature-install.log` และแต่ละรอบมี `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, SBOM ทั้งสองและเช็กซัม provenance บันทึกแฮช RPM เคอร์เนล initramfs PID 1 ตัวเก็บข้อมูล และ ID อิมเมจ Oracle/QEMU ใช้รายงานตรวจสอบรุ่นเผยแพร่แยกเพื่อเชื่อมหลักฐานกับ SHA-256 ของไฟล์แจกจ่าย

## เตรียมเกสต์

initramfs ตรวจสอบมีระบบไฟล์ Oracle Linux 8.2 ฐาน RPM ของเคอร์เนลที่ติดตั้งทั้งสอง อิมเมจใน `/boot` ต้นไม้ `/lib/modules` ทั้งสอง `/koda-bom` ที่จะทดสอบ และชุดตรวจสอบเป็น `/init` RHCK และ UEK ต้องบูตโดยตรงจากอิมเมจของตนเอง การรันเฉพาะคอนเทนเนอร์หรือ QEMU user-mode ไม่สร้างหลักฐานการบูตนี้ อาจวางโมดูลรุ่นที่ตรงกันจาก RPM เคอร์เนลทางการในตำแหน่งนี้

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

ชุดตรวจสอบบันทึก SHA-256 โมดูลและพยายามโหลดด้วย `init_module` แยกสถานะและข้อผิดพลาดเมื่อโมดูลหาย โหลดแล้ว หรือผิดพลาดจากลายเซ็นหรือส่วนพึ่งพา เทียบ `loadedModulesAfter` กับ `loadedModules` ของตัวเก็บข้อมูลเพื่อยืนยันการโหลดจริง การไม่พบโมดูลไม่ได้พิสูจน์ว่าไม่มีคุณสมบัตินั้น

QEMU ไม่ได้รับอินเทอร์เฟซเครือข่ายภายนอกหรือดิสก์เสมือน runner ใช้ `-accel tcg,thread=single -cpu max -smp 2 -m 4096` เกสต์ทดสอบใช้ `random.trust_cpu=on` เพื่อเลี่ยงการรอ `getrandom` ช่วงบูตแรก พารามิเตอร์นี้ไม่ใช่คำแนะนำสำหรับระบบใช้งานจริง เก็บการตั้งค่า CPU/การเร่งจริงและเช็กซัมเคอร์เนล RPM initramfs ตัวเก็บข้อมูลไว้ในหลักฐานฝั่งโฮสต์

## การรันและเก็บข้อมูล

ชุดตรวจสอบเมานต์ `/proc`, `/sys`, `/dev`, `/tmp`, `/results` และตั้ง hostname จำลอง baseline อิสระบันทึก uname, `/proc/sys/kernel/osrelease`, OS release รายชื่อโมดูลก่อนและหลัง บรรทัดคำสั่งเคอร์เนล VM และเช็กซัมตัวเก็บข้อมูล hostname และบรรทัดคำสั่งอยู่เฉพาะในหลักฐาน VM จำลองนี้ นโยบายเก็บข้อมูลปกติของผลิตภัณฑ์ยังใช้ตามเดิม เรียกตัวเก็บข้อมูลหนึ่งครั้งดังนี้

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

ใช้โหมด live-host เริ่มต้นโดยไม่ส่ง `--target /payload` การตรวจสอบ 0.1.3 ตั้งขีดจำกัดจำนวนไฟล์และเวลาเป็น 0 เพื่อปิดข้อจำกัด คง watchdog แยก 11 นาทีของ PID 1 และ timeout QEMU ฝั่งโฮสต์เพื่อคืนทรัพยากร stdout และ stderr จำกัดอย่างละ 1 MiB และเก็บคนละไฟล์ รหัสออก เวลา และข้อผิดพลาดบันทึกใน `/results/baseline.json` รหัส 3 หมายถึงเก็บบางส่วนและต้องคงค่าไว้

ส่งผลผ่านเอาต์พุต serial เป็น **base64(gzip(tar))** ระหว่างเครื่องหมายต่อไปนี้

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

หากขนาดก่อนบีบอัดเกิน 256 MiB หรือ 10,000 ไฟล์ จะส่งออกเฉพาะ baseline ที่อธิบายความล้มเหลว หลังส่งออกพยายาม sync และ poweroff หากล้มเหลว PID 1 จะยังทำงานเพื่อเลี่ยง kernel panic เมื่อเกสต์เกินกำหนด runner ฝั่งโฮสต์ต้องหยุด QEMU

## รายการตรวจสอบที่จำเป็น

- uname ใน baseline ตรงกับ proc release และ RHCK/UEK บูตรุ่นที่กำหนด
- `context.json.mode=live-host` และ `runningKernel` ตรงกับ baseline อิสระทุกประการ
- UEK รายงาน `kernelFlavor=UEK` และ RHCK รายงาน `RHCK-compatible` ตามรูปแบบปัจจุบัน
- บัญชีรายการเนทีฟเก็บเคอร์เนลที่ติดตั้งทั้งสอง พร้อม epoch/version/release/arch/source package ของแต่ละ RPM
- แยกเคอร์เนลที่ติดตั้งออกจากเคอร์เนลที่กำลังทำงานตาม context
- `metadata.kernelVersion` และ `versionMagic` ตรงกับแต่ละต้นไม้ติดตั้ง รายชื่อโมดูลที่โหลดตรงกับ baseline เคอร์เนลที่ใช้งาน
- สคีมาและเช็กซัม SBOM ทั้งสองผ่าน พร้อมรายงานความล้มเหลวและสถานะบางส่วนตามจริง

## ขอบเขตการตรวจสอบ

- บูตเคอร์เนลเกสต์ Oracle RHCK/UEK จริง การตรวจเซิร์ฟเวอร์ x86_64 ทางกายภาพเป็นงานแยก
- ใช้ user space Oracle Linux 8.2 และเคอร์เนลทางการใน initramfs ปรับแต่ง การบูต systemd เต็มรูปแบบ การติดตั้ง GRUB, UEFI/Secure Boot, SELinux enforcing และบริการใช้งานจริงอยู่นอกการทดสอบ
- การทดสอบ `loop` ยืนยันการโหลดและสังเกตโมดูลจริงหนึ่งตัว ไม่ครอบคลุมทุกไดรเวอร์หรือฮาร์ดแวร์ ห้ามถือว่าโมดูลติดตั้งของเคอร์เนลที่ไม่ได้ใช้งานถูกโหลดแล้ว
- ยอมรับรหัส `3` และ `collection.status=partial` พร้อมเก็บเหตุผล การผ่านการระบุเคอร์เนล เอาต์พุตมาตรฐาน และความสมบูรณ์ไม่ยืนยันว่าเก็บทุกไฟล์ครบ
