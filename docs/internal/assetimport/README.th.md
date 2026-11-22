# หลักฐานอุปกรณ์แบบออฟไลน์

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

`Load` ของ KODA BOM Kit อ่านไฟล์ JSON ปกติหนึ่งไฟล์ ขนาดไม่เกิน 8 MiB และ 4096 ระเบียน รองรับข้อมูลส่งออก fwupd `get-devices --json` (`Devices`) ออบเจ็กต์ Redfish `SoftwareInventory`, `Manager`, `ComputerSystem` ที่ขยายข้อมูลแล้ว และคอลเลกชันของออบเจ็กต์เหล่านี้ สมาชิก Redfish ที่มีเพียง URI จะสร้างรายการปัญหาการเก็บข้อมูลไม่ครบ ค่าที่นำเข้าเป็นข้อมูลสังเกตที่ผู้ดูแลระบบส่งออก ค่าเฟิร์มแวร์ `ImageState` จะเก็บไว้เมื่อมี มิฉะนั้นจะเป็นไม่ทราบ แฮชระบุไบต์ของหลักฐานและไม่ได้ยืนยันแหล่งที่มา

ผู้ให้บริการบัญชีรายการ Windows, macOS, OT และระบบอื่นสามารถส่งออกด้วยรูปแบบที่ระบุชัดเจนดังต่อไปนี้

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id":"board", "kind":"device", "name":"Controller", "vendor":"Vendor", "model":"Model", "revision":"A"},
    {"id":"firmware", "parentId":"board", "kind":"firmware", "name":"Controller firmware", "version":"1.2", "properties":{"applicationState":"Active", "storedVersion":"1.3"}}
  ]
}
```

ชนิดที่รองรับคือ `device`, `firmware` และ `device-driver` คุณสมบัติที่อนุญาตคือ `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem` และ `updateState` ID มีขอบเขตตามไดเจสต์ของหลักฐานเพื่อป้องกันการรวมข้อมูลนำเข้าต่างชุดโดยไม่ตั้งใจ หากขาดรุ่นเฟิร์มแวร์จะบันทึกปัญหาการเก็บข้อมูลไม่ครบ ไม่มีการอนุมาน CPE เวลาสังเกตหมายถึงเวลาส่งออกต้นทาง หากละไว้จะเป็นไม่ทราบ

รูปแบบทั่วไปยังรองรับ `library`, `application`, `operating-system` และ `container` ฟิลด์ `purl` ที่เลือกใส่ได้จะถูกแยกวิเคราะห์ และรุ่นภายในต้องตรงกับรุ่นที่ระบุชัดเจน qualifier จำกัดเฉพาะ `arch`, `distro`, `epoch`, `type` และ `classifier` ฟิลด์ `sha256` ที่เลือกใส่ได้ต้องเป็นเลขฐานสิบหก 64 ตัวและระบุส่วนประกอบที่นำเข้า ตัวนำเข้าจะคำนวณแฮชไฟล์หลักฐานแยกต่างหาก Windows และ macOS สามารถใช้คำสั่งบัญชีรายการแพลตฟอร์มแบบเนทีฟได้ ใช้รูปแบบนี้สำหรับหลักฐานเพิ่มเติมจากผู้ให้บริการรายอื่น

ข้อมูลส่งออก `devlink -j dev info` รับผ่านออบเจ็กต์ `info` การอ้างอิงบัสใช้ระบุรายการ กลุ่มรุ่น fixed, running และ stored เก็บแยกกัน ค่า `fw` ที่รายงานว่ากำลังทำงานจะเป็นรุ่นส่วนประกอบ คีย์รุ่นทางเลือกเฉพาะไดรเวอร์จะอยู่ในคุณสมบัติ หากขาด `fw` จะบันทึกปัญหาไม่ทราบรุ่น และตัดหมายเลขซีเรียลออก
