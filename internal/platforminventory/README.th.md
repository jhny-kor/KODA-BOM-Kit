# ข้อมูลสังเกตแพลตฟอร์มแบบเนทีฟ

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

`Collect(ctx)` ของ KODA BOM Kit เก็บข้อมูลสังเกตแบบมีขอบเขตโดยใช้เครื่องมือที่ติดตั้งอยู่แล้วบนเป้าหมาย ใช้อาร์กิวเมนต์คงที่ จำกัดคำสั่งละ 60 วินาทีและเอาต์พุต 32 MiB เลือกฟิลด์ก่อนเขียนลง SBOM โดยตัดหมายเลขซีเรียล UUID ชื่อผู้ใช้ และพาธแอปพลิเคชันเต็มออก พาธในเครื่องใช้เฉพาะในการคำนวณแฮชตัวตนส่วนประกอบ

บน macOS ใช้ `/usr/sbin/system_profiler` เพื่อรับเมทาดาทาฮาร์ดแวร์ ซอฟต์แวร์ และแอปพลิเคชัน ตัวเก็บข้อมูลส่งออกเฟิร์มแวร์ระบบ ตัวโหลด OS, CPU และแอปพลิเคชัน โดยเก็บหมายเลขบิลด์ OS ในสตริงรุ่น OS บางแอปพลิเคชันอาจไม่มีรุ่นหรือเมทาดาทา

บน Windows ใช้ PowerShell ของระบบโดยไม่โหลดโปรไฟล์ เพื่ออ่านระเบียน CIM computer, BIOS, OS, QuickFixEngineering และรายการถอนการติดตั้งในรีจิสทรีของเครื่องกับผู้ใช้ปัจจุบัน เก็บบิลด์และสถาปัตยกรรม OS ไว้ QuickFixEngineering ครอบคลุมเฉพาะการอัปเดตที่รายงานเอง บัญชีรายการรีจิสทรีไม่ได้แจกแจงทุกโปรไฟล์ผู้ใช้ แอป Store หรือส่วนพึ่งพาที่ฝังมา ตัวเก็บข้อมูลบันทึกข้อจำกัดเหล่านี้เป็นปัญหาด้านความครอบคลุม

เรียกการตรวจสอบ macOS แบบเนทีฟด้วย `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory` fixture การแยกวิเคราะห์ Windows และการคอมไพล์ข้ามแพลตฟอร์มตรวจสอบโครงสร้างซอร์ส การทดสอบรันจริงต้องใช้เป้าหมาย Windows
