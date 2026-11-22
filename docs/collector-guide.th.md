# KODA BOM Kit — คำสั่งเก็บข้อมูลและไฟล์ผลลัพธ์

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## เลือกขอบเขต

การเรียกใช้บนเครื่องที่กำลังทำงานจะเก็บข้อมูลระบบปฏิบัติการ แพ็กเกจ คอนเทนเนอร์ และฮาร์ดแวร์ที่อ่านได้ การสแกนไดเรกทอรีตรวจเฉพาะภายในต้นไม้นั้น ส่วนการสแกนอิมเมจจะอ่านไฟล์ Docker หรือ OCI ที่ส่งออกมา เลือกอินพุตหนึ่งประเภทต่อรอบ ค่าเริ่มต้นจำกัดที่ไฟล์ปกติหนึ่งล้านไฟล์และ 30 นาที ใช้ `--max-files 0 --timeout 0` เพื่อยกเลิกสองค่านี้ ข้อจำกัดด้านสิทธิ์ ระบบไฟล์ และการอ่านไฟล์บีบอัดยังมีผล

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## สแกนหนึ่งไดเรกทอรีหรือหลายไดเรกทอรี

สคริปต์รับไดเรกทอรีเป้าหมายและไดเรกทอรีแม่สำหรับเก็บผลลัพธ์ซึ่งระบุหรือไม่ก็ได้ สคริปต์ใช้ `--no-context` และไม่รับ `/` เป็นเป้าหมาย ครอบพาธที่มีช่องว่างด้วยเครื่องหมายคำพูด ใช้ `--exclude-dir` เพื่อยกเว้นไดเรกทอรีและ `--exclude` เพื่อยกเว้นตามรูปแบบ เมื่อมีหลายเป้าหมายให้เลือกไดเรกทอรีที่ไม่ซ้อนกันและใช้พาธสัมบูรณ์สำหรับไดเรกทอรีที่ยกเว้น หลังรวมผลยังคงมี `target-1` และ `target-2` ระบุตำแหน่งที่พบ

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## อ่านหลักฐานการแพตช์ขณะทำงาน

การสแกนโฮสต์จะอ่านสถานะการแพตช์เคอร์เนลจาก sysfs สคริปต์เสริมสอบถามไคลเอนต์ Canonical Livepatch, Ksplice หรือ Uptrack ที่ติดตั้งไว้และกรองผลลัพธ์ รายงานนำเข้าต้องตรงกับการบูตและเคอร์เนลปัจจุบัน และต้องมีอายุไม่เกิน 24 ชั่วโมง จึงจะใช้เป็นสถานะปัจจุบันได้ การไม่มีรายการไม่เพียงพอที่จะสรุปว่าแก้ไข CVE นั้นแล้ว

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## สร้างกราฟการทำงานหรือรวมชุดข้อมูลอีกครั้ง

OBOM เชื่อมโยงซ็อกเก็ตที่รอรับการเชื่อมต่อ โปรเซส และแพ็กเกจที่ติดตั้ง ที่อยู่ที่ผูกไว้ภายในเครื่องเพียงอย่างเดียวไม่ยืนยันว่าจะเข้าถึงจากภายนอกได้ เพิ่มข้อมูลที่ส่งออกมาด้วย `--kubernetes-evidence` หรือ `--network-evidence` กำหนด `set_dir` เป็นไดเรกทอรีที่มี `bom-set.json` หลังแยกชุด เก็บไฟล์ความสัมพันธ์และผลรวมตรวจสอบไว้ด้วยกัน ชุดเก่าที่ใช้ชื่อ `mlbom.cdx.json` ยังรวมได้

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## ให้หลักฐานสำหรับรายการประเภทอื่น

ระบุไดเรกทอรีของโมเดลที่ติดตั้งให้ตัวเก็บข้อมูล AI สำหรับ SaaS หรือการผลิตให้ระบุไฟล์รายการบริการหรือกระบวนการ ใช้ `--asset-evidence` เพื่อนำเข้าหลักฐานเกี่ยวกับอุปกรณ์ Redfish เฟิร์มแวร์ หรือการเข้ารหัส รายการขณะบิลด์จะเชื่อมโยงกับไฟล์ที่สแกนเมื่อ SHA-256 ตรงกัน ดูรูปแบบข้อมูลในคู่มือท้ายหน้า

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## นำเข้าข้อมูล IBM AIX และ Oracle

เรียกใช้สคริปต์บน AIX แล้วเรียกใช้ตัวนำเข้าบนเครื่อง Linux ที่ใช้วิเคราะห์ ระบุผล OPatch ที่เจ้าของ Oracle Home บันทึกไว้ และประวัติแพตช์ SQL จาก DBA หากมี รองรับ Home ต่างกันได้ไม่เกินแปดแห่ง การระบุเวอร์ชัน Listener ต้องใช้หลักฐานจาก Home เดียวกัน เทียบรหัสแพตช์กับประกาศที่เกี่ยวข้องของผู้ผลิต

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## ระบุส่วนประกอบที่ใช้งานจริง

npm และ pnpm ตรวจตำแหน่งติดตั้ง การแก้ความสัมพันธ์แบบ peer และเวอร์ชัน การตรวจ JavaScript แบบสแตติกรองรับ jQuery, jQuery UI และ Fancytree ไบนารี Go ต้องมีข้อมูลการบิลด์ฝังอยู่ ส่วน Rust ELF ต้องมีข้อมูล cargo-auditable สำหรับ .NET จะเทียบ .deps.json กับ managed DLL ที่ติดตั้ง ส่วน Ruby ใช้ gemspec ที่ติดตั้งแล้ว การสแกน Java รักษาพาธของไลบรารีภายใน WAR, EAR และ Spring Boot หากยังระบุพิกัดไม่ได้ รายการจะคงสถานะนั้นไว้

## เปรียบเทียบไฟล์ที่นำไปใช้กับรายการของผู้จัดหา

ระบุ WAR หรือ EAR หนึ่งไฟล์ และเอกสาร CycloneDX 1.4–1.7 หรือ SPDX 2.3 ที่มี SHA-256 ของไฟล์นั้นโดยตรง ตรวจ `common`, `observedOnly`, `supplierOnly` และ `unresolved` ใน `reconcile.json` แล้วส่ง SBOM ที่ตรวจพบจริงไปยัง Tracker ขนาดสูงสุดคือ 512 MiB สำหรับไฟล์ที่นำไปใช้และ 32 MiB สำหรับรายการของผู้จัดหา

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## ตรวจสอบความครอบคลุม

ใช้ KODA, Syft และ Trivy เปรียบเทียบชุดไฟล์เดียวกันที่ไม่มีการแก้ไขบนเครื่องบิลด์หรือเครื่องทดสอบ สคริปต์ต้องใช้ Python 3.11 ขึ้นไป ระบุส่วนประกอบและความสัมพันธ์ที่ยืนยันแล้วด้วย `--expected` หรือตรวจการถดถอยด้วย `--baseline` การทดสอบ Tracker แบบเสริมจะอัปโหลดไปยังบริการทดสอบที่ระบุ การตรวจกราฟที่จัดเก็บแล้วใช้ `--normalized-bom-command`

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## อ่านผลการเก็บข้อมูล

กำหนด `run_dir` ให้เป็นพาธที่โปรแกรมพิมพ์ออกมา รหัสออก 0 หมายถึงเสร็จสมบูรณ์ 3 หมายถึงได้ผลบางส่วน และ 2 หมายถึงล้มเหลว ดูข้อจำกัด รายการที่ขาด และข้อผิดพลาดใน `collection.json` ดูความสัมพันธ์ขณะทำงานใน `context.json` และหลักฐานอุปกรณ์หรือใบรับรองใน `assets.json` แต่ละไดเรกทอรีคอนเทนเนอร์หรืออิมเมจมีผลรวมตรวจสอบของตนเอง เวอร์ชันกับวันที่เพียงอย่างเดียวยังใช้ตัดสินสถานะช่องโหว่ไม่ได้

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## บิลด์บนเครื่องแยก

เครื่องบิลด์ต้องมี Go และ Python 3 รุ่นนี้บิลด์ด้วย Go 1.26.11 หากใช้ไฟล์ปฏิบัติการ Go อื่น ให้ระบุพาธและค่า SHA-256 ที่ตรวจสอบแล้ว การบิลด์แบบออฟไลน์ต้องมีแคชโมดูลพร้อมใช้ ไฟล์เผยแพร่จัดทำสำหรับ Linux amd64 และซอร์สโค้ดยังบิลด์สำหรับ Linux ARM64 ได้ ข้อมูลที่มาของการบิลด์อยู่ใน `release.json`

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## เอกสาร

- [การติดตั้งแบบออฟไลน์และการตรวจผล](air-gapped.th.md)
- [หลักฐานด้านฮาร์ดแวร์ การเข้ารหัส และการทำงาน](asset-inventory.th.md)
- [รายการบริการ โมเดล AI และกระบวนการผลิต](additional-bom.th.md)
- [แพลตฟอร์มที่รองรับและขีดจำกัดการเก็บข้อมูล](support-matrix.th.md)
- [ขั้นตอนการบิลด์และการตรวจสอบ](verification.th.md)
- [ผลและขอบเขตการทดสอบ](verification-results.th.md)
