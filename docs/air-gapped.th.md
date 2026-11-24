# ใช้งานในเครือข่ายปิดและตรวจผล

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 สำหรับ Linux x86_64 (amd64) เคอร์เนล 3.2 ขึ้นไป นำแพ็กเกจและ `.tar.gz.sha256` ที่ตรงกันจากรุ่นทางการเข้ามา ไม่ต้องติดตั้ง Go, Python, Docker หรือ jq เพิ่มบนเป้าหมาย NOTICE ระบุ jhny-kor และคลังทางการ

[รุ่นเผยแพร่ 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## ตรวจสอบและแตกไฟล์

วางแพ็กเกจที่ตรงกันเพียงหนึ่งไฟล์และเช็กซัมในโฟลเดอร์ที่รันได้ ตรวจแพ็กเกจก่อนแตกและไฟล์ภายในหลังแตก เช็กซัมตรวจไบต์ที่ถ่ายโอน ให้ใช้แหล่งทางการที่เชื่อถือได้ USB แบบ noexec ต้องคัดลอกไปพื้นที่ที่รันได้

```bash
set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.9 archive.' >&2
fi
```

## ตรวจเซิร์ฟเวอร์

ตรวจสถาปัตยกรรม เคอร์เนล และ `doctor` ค่า `supported=true` หมายถึงผ่านเงื่อนไขรัน `doctor.kernel` และ `context.json.runningKernel` ระบุเคอร์เนล แม้ `kernelFlavor=unknown/unconfirmed` ก็อาจบันทึกรุ่นแล้ว root เพิ่มการมองเห็น DMI, BMC, process และ container

```bash
uname -m
uname -r
./koda-bom doctor
```

## เลือกขอบเขต

รัน `koda-bom` โดยไม่มีอาร์กิวเมนต์จะสร้างโฟลเดอร์ใหม่ใน `bom-output/` มี `bom.cdx.json` รวมและเอกสารเจ็ดชนิดใน `boms/` AI-BOM คือ `aibom.cdx.json` เนื้อหาขึ้นกับหลักฐานในเครื่อง Qwen ใช้โฟลเดอร์โมเดลจริง H100 อยู่ใน HBOM ค่า config/header/แพ็กเกจไม่ระบุการจัดสรร GPU ปัจจุบันหรือค่า serving ที่มีผลจริง

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

การเก็บโฟลเดอร์ใช้ `--no-context` วางผลนอกข้อมูลเข้า สคริปต์ปฏิเสธ `/` และใช้เส้นทางยกเว้นสัมพัทธ์ได้สำหรับโฟลเดอร์เดียว หลายเป้าหมายต้องไม่ซ้อนกันและยกเว้นด้วยเส้นทางสัมบูรณ์ ใช้จำนวนไฟล์/เวลาร่วมกัน อาจไม่พบ dependency ภายนอก

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## เก็บ livepatch

สคริปต์เสริมถาม Ksplice, Uptrack หรือ Canonical ที่มีอยู่ ทำความสะอาดหลักฐาน แล้วรัน scan เก็บหลักฐานข้างผลลัพธ์ จับ `$?` ทันที ยังจำกัดการถามที่ 30 วินาที และเคอร์เนลมีผลที่ 10 วินาที แม้ยกเลิกเวลา scan ไคลเอนต์และ daemon มีพฤติกรรมเครือข่ายของตน

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## ขีดจำกัดและรหัสออก

ค่าเริ่มต้น 1,000,000 ไฟล์และ 30 นาที `--max-files 0 --timeout 0` ยกเลิกสองอย่างนี้ Ctrl+C ยกเลิกงาน ข้อจำกัดสิทธิ์ การยกเว้น ลิงก์ 2 GiB ต่อไฟล์ และการแตก image ยังใช้ `--no-containers` ข้าม container/image ไม่ใช้ `--no-images` ข้าม container หยุดและ image ไม่ใช้ 0 คือครบ 3 คือบางส่วนมีผล 2 คือล้มเหลว ตรวจรหัสผิดปกติอื่นด้วย

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## ค้นหาและตรวจผล

ใช้โฟลเดอร์จริงที่คำสั่งพิมพ์ สคริปต์พิมพ์ doctor/หลักฐานก่อนบรรทัดสุดท้ายที่เป็นเส้นทาง ตั้ง `result` เป็นเส้นทางนั้น ไฟล์ของ root อาจต้อง sudo ตรวจ manifest หลักและของ container/image แต่ละชุด เก็บเหตุผลการเก็บบางส่วน

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## อ่านสถานะและแพตช์

`collection.json` มี `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues` ตัวตน แหล่งที่มา ความสมบูรณ์ และ container จำนวนไฟล์คือไฟล์ที่เลือกขณะเดินไดเรกทอรี `file_limit_exceeded` มี `limit` และ `observed` ส่วน `context.json` มีเคอร์เนล process socket service การตั้งค่า และแพตช์ `assets.json` เก็บฮาร์ดแวร์ firmware และใบรับรอง

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` มาจากเคอร์เนลโดยตรง `reported-applied` จากไคลเอนต์ `disabled` และ `transitioning` คือสถานะนั้น `stale`, `identity_mismatch`, `unknown` ต้องเพิ่มหลักฐาน อ่านสถานะปัจจุบันกับ `patches[].state` เพราะ `reportedState` อาจเก่า ข้อมูลเกิน 24 ชั่วโมง ต่าง boot/เคอร์เนล หรือเวลาล่วงหน้าเกินเกณฑ์ไม่ยืนยันสถานะปัจจุบัน ตรวจ Last-Check/CheckState ของ Canonical ด้วย ตีความสิ่งที่ไม่พบและ `not-reported-patched` ร่วมกับหลักฐานเคอร์เนล/ผู้ขาย

`integrity.findings[].state=modified` หรือ `missing` คือเนื้อหาต่างหรือขาด `bindScope=all-interfaces` คือที่อยู่ผูก การเปิดผ่าน firewall ต้องตรวจแยก `unidentifiedExecutables` คือยังไม่เชื่อมแพ็กเกจ `reboot.recommended=not_observed` คือไม่พบสัญญาณ อ่านร่วมกับบริบทและขอบเขต

## เทียบผู้ขายและเก็บรักษา

SBOM ผู้ขาย WAR/EAR ต้องระบุ SHA-256 จริง แฮชขาด/ไม่ตรงออก 2 ตรวจ `reconcile.json` และเหตุผลบางส่วน เก็บทั้งโฟลเดอร์แม่รวมหลักฐาน livepatch ที่ทำความสะอาดแล้วและคำนวณเช็กซัมไฟล์ส่งออก

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## ส่งเข้าและวิเคราะห์

ส่ง `sbom.cdx.json` หรือ `sbom.spdx.json` ให้ Tracker ที่รองรับ container/image มี SBOM ของตน เก็บ collection, context และ Syft เป็นหลักฐานประกอบ เวลาอัปโหลดตั้งแยก ผลเก็บใช้วิเคราะห์ประกาศต่อ ประสิทธิผลแพตช์และแก้ CVE ต้องมีหลักฐานเอง ดูประวัติสำหรับขอบเขตแต่ละรุ่นและ VM

## เอกสาร

[ใช้งานในเครือข่ายปิดและตรวจผล](air-gapped.th.md) · [การสร้างและตรวจสอบ](verification.th.md) · [ผลการตรวจสอบ](verification-results.th.md)
