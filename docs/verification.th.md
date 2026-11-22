# การสร้างและตรวจสอบ

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 มีแพ็กเกจออฟไลน์ Linux amd64 และ SHA-256 ให้ระบุไฟล์ที่ทดสอบด้วยแฮชและสภาพแวดล้อมจริง การเก็บข้อมูล Linux รองรับ x86_64 และ ARM64 ส่วน Docker/OCI ใช้ linux/amd64 การสำรวจ macOS/Windows ใช้คำสั่งอ่านอย่างเดียวที่กำหนดไว้ ยังไม่ได้ทดสอบการรันจริงบน Windows ผล VM ในอดีตใช้กับรุ่นที่บันทึกไว้

[รุ่นเผยแพร่ 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## รูปแบบและความครบถ้วน

ค่าเริ่มต้นคือ CycloneDX 1.6 และ SPDX 2.3 เพิ่ม `--cyclonedx-17` เพื่อสร้าง 1.7 จากข้อมูลเดียวกัน เมื่อใช้ `--format cyclonedx` จะได้สองเอกสาร ส่วน `--format spdx` จะถูกปฏิเสธก่อนสร้างผลลัพธ์ คำสั่ง `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` และสคริปต์ช่วยเก็บข้อมูลรองรับตัวเลือกนี้ ตรวจไฟล์ตามตัวเลือกที่ใช้

| ผลลัพธ์ | รูปแบบ |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` ตรวจสคีมาในเครื่อง ตัวระบุ หลักฐาน คุณสมบัติ ความหมายใบอนุญาต ความสัมพันธ์ ขอบเขต และรายการเช็กซัมที่ขาดหรือซ้ำ สคีมา 1.7 ตรึงกับ 1.7.1 commit `b29bae660048e0ad2fbc5f2972927b442ce951c4` แหล่งที่มาอยู่ใน `tests/schemas/provenance.json` รุ่น 1.6 มี 704 ID รุ่น 1.7 มี 811 ID อีก 107 รายการใช้ `license.name` ใน 1.6 และ `license.id` ใน 1.7 ต้องตรวจสถานะบางส่วนใน `collection.json` ด้วย

## ตรวจบนเครื่องสร้าง

เตรียม Go, Python, Docker แคชโมดูลและเครื่องมือตรวจสคีมา ตั้ง `trusted_go_sha256` เป็นแฮช Go ที่ตรวจสอบแล้ว `GOPROXY=off` ใช้แคช QA ปฏิเสธ `python3 -O` และ `PYTHONOPTIMIZE` เซิร์ฟเวอร์เป้าหมายใช้ไฟล์ที่จัดส่ง บน macOS ใช้ `shasum -a 256 -c SHA256SUMS`

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## ทดสอบการทำงานร่วมกัน

ใช้คำสั่งกับแพ็กเกจสุดท้ายที่แตกแล้ว เตรียมแคชก่อนปิดเครือข่าย .NET/Ruby ต้องใช้ .NET 10 SDK ส่วน Go/Rust ใช้แคชและ ripgrep ELF ที่ตรึงไว้ หรือ `--rust-binary` Fancytree ตรวจ npm SHA-512 หรือ GitHub SHA-256 การทดสอบที่รองรับใช้ `--tracker-root /path/to/tracker` เพื่อตรวจตัวอ่าน Tracker จริง

`domain_bom_integration.py` รันไฟล์เป้าหมายโดยตรง ให้ทดสอบคำสั่งนี้บน Linux amd64

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

ครอบคลุม Java ซ้อน, pyz/pex, Go/Rust แหล่งติดตั้ง ขอบเขต แฮชผู้ขาย PURL และความสัมพันธ์ ชุดข้อมูล Linux ตรวจ socket, container, firmware, service การตั้งค่า ความสมบูรณ์ และใบรับรอง ส่วน AIX ตรวจ Oracle Home, Listener และ OPatch อุปกรณ์ BMC/NIC/OT จริง Kubernetes จริง และไคลเอนต์แพตช์แบบสมัครสมาชิกต้องมีหลักฐานจากสภาพแวดล้อมนั้น

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## เคอร์เนล Linux และ VM

ทดสอบส่วนเฉพาะ Linux บน Linux macOS สามารถคอมไพล์ข้ามไปยังสถาปัตยกรรมของ container ได้ ใช้ไฟล์สุดท้ายใน VM บูต RHCK `4.18.0-193.el8.x86_64` และ UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` แยกกันด้วย RPM ลงนามใน `tests/oracle-vm/kernels.json` เก็บแหล่งที่มา ลายเซ็น image ID บันทึก serial ค่าฐาน และรายงาน

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle ใช้ QEMU system TCG, RAM 4 GiB, CPU สองตัว และ PID 1 เฉพาะ โดย guest ไม่มีเครือข่ายหรือดิสก์ ตรวจ uname, proc, การโหลด loop และเคอร์เนลที่ติดตั้ง/กำลังรัน Ubuntu บูต `6.8.0-47-generic` จากแพ็กเกจที่รับรองแล้ว GRUB, UEFI/Secure Boot, systemd เต็มรูปแบบ, SELinux enforcing ไดรเวอร์จริง และบริการจริงต้องทดสอบเพิ่ม container Oracle ใช้เคอร์เนลร่วมกับ host

[Oracle VM](../tests/oracle-vm/README.th.md) · [Ubuntu VM](../tests/ubuntu-vm/README.th.md)

## System call ทรัพยากร และการวิเคราะห์

ติดตามไฟล์สุดท้ายใน container แยก หาก ARM64 จำลองอ่าน ptrace ไม่ได้ `trace-network.sh` คืน 77 ใช้ QEMU guest syscall โดยระบุสภาพแวดล้อมให้ชัด การอ้างว่ามีความพยายามศูนย์ครั้งต้องมี trace ที่ใช้งานได้ ไคลเอนต์และ daemon ที่สคริปต์ livepatch เรียกมีพฤติกรรมเครือข่ายของตน

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

ค่าเริ่มต้นคือไฟล์ปกติที่เลือก 1,000,000 ไฟล์และ 30 นาที ทดสอบขีดจำกัด ตัวเลือกผิด การยกเลิก สิทธิ์ ไฟล์เสีย และการยกเว้น `--max-files 0 --timeout 0` ยกเลิกสองข้อจำกัดนี้ บันทึกเวลาและ RSS สูงสุด งานขนานสองงานไม่ได้กำหนดเพดานหน่วยความจำ Tracker ทดสอบสองรูปแบบด้วยฐานข้อมูลชั่วคราวแยก การเทียบประกาศขึ้นกับกฎและสิ่งที่พบ การใช้งานจริงและแก้ CVE ต้องมีหลักฐานเฉพาะ

## เอกสาร

[ใช้งานในเครือข่ายปิดและตรวจผล](air-gapped.th.md) · [การสร้างและตรวจสอบ](verification.th.md) · [ผลการตรวจสอบ](verification-results.th.md)
