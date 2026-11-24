# ตัวเก็บหลักฐานผลิตภัณฑ์

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`Collect(context.Context, root string, paths []string)` ของ KODA BOM Kit รับรายการไฟล์ปกติแบบพาธสัมพัทธ์ที่ตรวจสอบล่วงหน้าแล้ว ไม่ค้นหาไฟล์ รันโปรแกรมที่ติดตั้ง แตกไฟล์เก็บถาวร ติดต่อเซิร์ฟเวอร์ หรืออ่านความลับจากสภาพแวดล้อมและการตั้งค่า `os.OpenRoot` จำกัดการแก้พาธ และปฏิเสธพาธสัมบูรณ์หรือองค์ประกอบที่ย้อนขึ้นไดเรกทอรีแม่ การอ่านเนื้อหาและเมทาดาทาไฟล์เก็บถาวรมีขอบเขต รายการพาธว่างไม่ทำการค้นหาไฟล์

## หลักฐานแบบคงที่ที่ยอมรับ

- ฟิลด์รุ่น runtime บิลด์ ผู้ผลิต และสถาปัตยกรรมที่อนุญาตใน JDK/JRE `release`
- การตรวจสอบรุ่นระหว่าง `ServerInfo.properties` กับ `MANIFEST` ใน Tomcat `catalina.jar`
- แมนนิเฟสต์ผลิตภัณฑ์ WebLogic `weblogic.jar` และตัวตนส่วนประกอบจาก `inventory/ContentsXML/comps.xml` ในโฮมการติดตั้งปัจจุบัน เก็บ ID แพตช์เป็นข้อมูลสังเกต XML ทั่วไปหรือรายการ `.patch_storage` ไม่ยืนยันว่าใช้แพตช์ CPU/PSU แล้ว ค่า `patchState` จึงเป็น `unknown`
- แมนนิเฟสต์รุ่นผลิตภัณฑ์ JBoss EAP/WildFly ใต้โมดูลผลิตภัณฑ์ที่ติดตั้ง
- ไฟล์ ELF ของ OpenSSH, OpenSSL, PHP และ Node.js ที่มีลายเซ็นรุ่นฝังเฉพาะผลิตภัณฑ์ การจำแนกนี้เสริม Syft ยังไม่ได้ยืนยันความครอบคลุมไบนารี stripped หรือไบนารีปรับแต่งทั้งหมด อินพุตสแกนเนทีฟจำกัด 32 MiB และรายการที่ใหญ่กว่าจะระบุว่าไม่ครบอย่างชัดเจน

เมทาดาทา Tomcat, JDK หรือ WebLogic ในโฮมเดียวกันที่ขัดแย้งกันจะติดสถานะขัดแย้งและไม่ยืนยันรุ่น ไม่รวมโฮมการติดตั้งต่างกัน อาร์ติแฟกต์ไลบรารี ไคลเอนต์ และเซิร์ฟเวอร์เนทีฟมี ID แยกกัน แม้รุ่นเดียวกันในไดเรกทอรีเดียวกัน ไม่มีการอนุมาน CPE หรือวินิจฉัย CVE

เมทาดาทาผลิตภัณฑ์และแพตช์ JEUS **ยังไม่รองรับ** ตัวจัดทำแค็ตตาล็อก Java ทั่วไปอาจเก็บไลบรารี JAR ได้ แต่ไม่ได้พิสูจน์ตัวตนผลิตภัณฑ์ JEUS หรือระดับแพตช์ที่ใช้

การทดสอบสร้างโครงสร้างเมทาดาทาตัวแทนโดยไม่ใช้ภาพผลิตภัณฑ์ที่มีใบอนุญาต การตรวจสอบการติดตั้งเชิงพาณิชย์ต้องมี fixture จากผู้ผลิตเป้าหมาย
