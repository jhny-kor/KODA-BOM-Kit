# หลักฐานเพิ่มเติมสำหรับ SaaSBOM, AI-BOM และ MBOM

<!-- koda-doc-nav -->
<p align="center">
  <a href="additional-bom.md"><img src="badges/en.svg" alt="English"></a>
  <a href="additional-bom.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="additional-bom.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="additional-bom.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="additional-bom.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="additional-bom.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="additional-bom.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="additional-bom.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="additional-bom.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <strong>ไทย</strong>
  <a href="additional-bom.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


`domain-bom` อ่านหลักฐานและอาร์ติแฟกต์ในเครื่องเพื่อสร้าง `saasbom.cdx.json`, `aibom.cdx.json` และ `mbom.cdx.json` ตัวเลือก `--cyclonedx-17` เพิ่มไฟล์รุ่น 1.7 คำสั่ง `scan` รับแฟล็กหลักฐานเดียวกัน การเก็บข้อมูลโฮสต์แบบเริ่มต้นวาง BOM ทั้งเจ็ดแยกใน `boms/` และเอกสารรวมใน `bom.cdx.json`

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./services.json \
  --model-evidence ./model.json --model-artifact ./model.safetensors \
  --provenance ./provenance.json --provenance-artifact ./product.bin
```

ระเบียนหลักฐานมี SHA-256 ขอบเขตการสังเกต และข้อมูลว่าเป็นการประกาศหรือการรายงาน ความแท้จริงของลายเซ็นยังไม่ได้รับการยืนยันใน `koda:domain:authenticity` หลักฐานที่ส่งเข้ามาสร้าง `compositions.aggregate=incomplete` เมื่อข้อมูลประกาศตรงกับอาร์ติแฟกต์จะได้ `artifact-binding=sha256-matched` โดเมนที่ไม่มีหลักฐานในการสแกนโฮสต์เต็มรูปแบบจะระบุ `no-evidence` และไม่ทราบความครอบคลุม

คำสั่งรับอินพุตได้รวมสูงสุด 12 รายการในสามโดเมนนี้ ไฟล์หลักฐาน JSON แต่ละไฟล์จำกัด 16 MiB แต่ละรายการจำกัด 10,000 สมาชิก ปฏิเสธคีย์ JSON ซ้ำ ข้อมูลผู้ใช้ใน URL query string, fragment และเทมเพลตเซิร์ฟเวอร์ที่ยังไม่แก้ค่า แฮชอาร์ติแฟกต์คำนวณแบบสตรีม ไม่มีการรันน้ำหนักโมเดลหรืออาร์ติแฟกต์ที่เป็นไฟล์ปฏิบัติการ

## SaaSBOM

`--saas-evidence` รับ OpenAPI 3.x JSON หรือ `koda-services-1` OpenAPI ให้ชื่อ รุ่น เซิร์ฟเวอร์แบบ URL สัมบูรณ์ที่ระบุชัดเจนในระดับราก/พาธ/operation และข้อประกาศการยืนยันตัวตนของ operation เซิร์ฟเวอร์เริ่มต้นแบบสัมพัทธ์จะมีตำแหน่งปรับใช้ที่ไม่ทราบ operation ที่ระบุให้ใช้แบบไม่ยืนยันตัวตนจะตั้ง `authenticated=false` หากทุก operation ที่ตรวจต้องยืนยันตัวตน ค่าจะเป็น `true` หากข้อประกาศไม่เพียงพอจะละฟิลด์ไว้ ตัดตัวอย่างเนื้อหา รายละเอียด security scheme คำอธิบาย และความลับออก [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.1.html)

OpenAPI ใช้ YAML ได้ด้วย YAML ต้องมีเอกสารเดียว คีย์ซ้ำจะถูกปฏิเสธ และตัวเลขคงข้อความตามที่เขียน ดังนั้น `version: 1.0` ยังคงเป็น `1.0`

การเก็บข้อมูลโฮสต์ยังอ่านการตั้งค่า reverse proxy และ load balancer ได้แก่ `upstream`, `proxy_pass`, `grpc_pass` ของ nginx, `ProxyPass`, `BalancerMember` ของ Apache และ `server` ใน `backend` ของ HAProxy แต่ละ backend บันทึกเป็นบริการที่มี `observation=declared-proxy-backend` พร้อมไฟล์และบรรทัดที่ประกาศ เก็บเฉพาะ scheme โฮสต์ และพอร์ต ทิ้งพาธ query และข้อมูลรับรอง ปลายทางที่ใช้ตัวแปรรายงานว่ายัง resolve ไม่ได้ การเข้าถึง backend ได้จริงหรือไม่ดูจากการเชื่อมต่อขาออกใน OBOM ไม่ใช่จากข้อประกาศนี้ ไฟล์ `*-available` ของ Debian มีผลเฉพาะผ่านลิงก์ `*-enabled` และใช้กฎเดียวกันกับข้อประกาศ TLS ใน CBOM เมื่อการสแกนไดเรกทอรีตามลิงก์เหล่านั้นไม่ได้ จะยังอ่านไฟล์และบันทึก issue ว่ายังระบุสถานะการเปิดใช้ไม่ได้

ใช้สคีมานี้ระบุผู้ให้บริการ ขอบเขตความเชื่อถือ การจำแนกข้อมูล และส่วนพึ่งพาของบริการ

```json
{
  "schema": "koda-services-1",
  "services": [
    {
      "id": "app",
      "name": "Application",
      "provider": "Example",
      "endpoints": ["https://app.example.invalid/api"],
      "authenticated": true,
      "trustBoundary": true,
      "trustZone": "production",
      "data": [{"flow": "outbound", "classification": "personal-data", "name": "customer-record"}],
      "dependsOn": ["database"]
    },
    {
      "id": "database",
      "name": "Database service",
      "endpoints": ["https://database.example.invalid"],
      "authenticated": true
    }
  ]
}
```

ต้องมี `id` และ `name` ฟิลด์อื่นในตัวอย่างและ `version` เป็นตัวเลือก `dependsOn` อ้างถึง ID บริการภายในไฟล์เดียวกัน ค่า `flow` ของข้อมูลเป็น `inbound`, `outbound`, `bi-directional` หรือ `unknown` เมื่อเทียบกับบริการ การยืนยันตัวตน ความเชื่อถือ และความสัมพันธ์การเรียกสะท้อนข้อประกาศที่ส่งมา

## AI-BOM

ตรวจไดเรกทอรีโมเดลบนเซิร์ฟเวอร์เป้าหมาย การเก็บข้อมูลโฮสต์ใช้การตรวจแบบเดียวกันกับพาธที่รับเข้าสแกน

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./ai-results
```

- Hugging Face `config.json` ให้สถาปัตยกรรม จำนวนชั้นและ attention head ของโมเดลข้อความ context สูงสุด และ quantization ดัชนีน้ำหนักให้จำนวน tensor ที่ประกาศและรายการ shard
- ส่วนหัว safetensors และ GGUF ให้รูปแบบ จำนวน tensor และเมทาดาทาที่มี ส่วนประกอบโมเดลกับไฟล์น้ำหนักเชื่อมกันผ่าน dependencies การค้นหาอ่านส่วนหัวแบบจำกัดขนาดแม้น้ำหนักจะใหญ่ แฮชการตั้งค่า ดัชนี และส่วนหัวระบุแยกจากแฮชทั้งไฟล์
- แมนนิเฟสต์ Ollama เชื่อมชั้นโมเดลกับส่วนหัว blob ในเครื่องที่อ่านได้ การยืนยันว่าเซิร์ฟเวอร์โมเดลโหลดอะไรอยู่ในขณะนั้นต้องใช้หลักฐานรันไทม์
- model card `README.md` ของ Hugging Face ที่อยู่ข้าง `config.json` ให้ใบอนุญาต `base_model`, `datasets`, `pipeline_tag` ภาษา และไลบรารี โมเดลฐานและชุดข้อมูลกลายเป็นคอมโพเนนต์ที่ประกาศและเชื่อมกับโมเดล ในแคช Hugging Face จะบันทึก `refs/main` และ ref อื่นที่ชี้ไปยัง snapshot เป็น `cache-ref` ค่าใน model card ยังเป็นข้อประกาศของผู้เผยแพร่
- ไฟล์ ONNX ให้รุ่น IR ผู้สร้าง รุ่นโมเดล และชุดตัวดำเนินการ โดเมนตัวดำเนินการนอก `ai.onnx` และ `ai.onnx.ml` แสดงเป็น `onnx:custom-operator-domain` เพราะต้องใช้ไลบรารีตัวดำเนินการแบบกำหนดเองที่เป็น native code
- checkpoint ของ PyTorch (`pytorch_model*.bin`, `.pt`, `.pth`, `.ckpt` แบบ zip หรือแบบเดิม) เป็น pickle ที่เรียกฟังก์ชันที่ import ไว้เมื่อโหลด KODA ไล่ดู opcode ของ pickle โดยไม่รัน และบันทึก `pickle:safety` เป็น `allowlisted-imports-only`, `unknown-imports` หรือ `dangerous-imports` พร้อม `pickle:dangerous-import` แต่ละรายการ เช่น `os.system` ไฟล์ที่ไล่ไม่ถึงท้ายรายงานด้วย `pickle:inspection=incomplete` และไม่ถือว่าเป็น allowlisted-only โดยยังเก็บ import ที่พบก่อนล้มเหลว pickle โปรโตคอล 0/1 และทั้งห้าสตรีมของไฟล์ `torch.save` แบบเดิมก็ถูกตรวจด้วย ไฟล์ที่ไม่ใช่ allowlisted-only ควรเปลี่ยนไปใช้ safetensors ไฟล์ pickle และ ONNX ในโฟลเดอร์โมเดลของ Hugging Face เช่น `pytorch_model.bin`, `training_args.bin` หรือ `optimizer.pt` จะเชื่อมกับโมเดลนั้น และโมเดลบันทึกผลที่ปลอดภัยน้อยที่สุดเป็น `artifact-pickle-safety` หากมีไฟล์ที่ตรวจไม่ได้ โมเดลจะได้อย่างน้อย `unknown-imports` พร้อม `artifact-inspection=incomplete`
- บนโฮสต์ที่ทำงานอยู่ โปรเซส vLLM, TGI, llama.cpp, SGLang, Triton หรือ LMDeploy ที่เริ่มด้วยพาธโมเดลหรือ ID ของ repository จะทำให้โมเดลที่ตรงกันได้ `runtime-state=referenced-by-running-process` และ `serving-process` และโปรเซสใน OBOM มี `model-reference` ผลนี้อิงอาร์กิวเมนต์ตอนเริ่มทำงาน Ollama เลือกโมเดลตามคำขอจึงไม่ถูกจับคู่

### Qwen บนเซิร์ฟเวอร์ Linux ที่ใช้ NVIDIA GPU

```sh
sudo ./koda-bom --output-dir ./koda-results

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

แทน `/srv/models/Qwen` ด้วยพาธจริงบนเซิร์ฟเวอร์ สำหรับ symlink Hugging Face จาก `snapshots/<revision>/` ไป `blobs/` ให้เลือกไดเรกทอรี `models--organization--model` ที่ครอบอยู่ สำหรับ bind mount ของคอนเทนเนอร์ ให้ใช้พาธจัดเก็บที่โฮสต์มองเห็น

| หลักฐาน | เอาต์พุต |
|---|---|
| สถาปัตยกรรมโมเดล context ความแม่นยำ quantization, shard และ tensor | ส่วนประกอบและ dependencies ใน `boms/aibom.cdx.json` ตามรูปแบบที่จัดเก็บและฟิลด์ที่มี |
| รุ่น H100 ตัวระบุ PCI ไดรเวอร์ และเฟิร์มแวร์ | `boms/hbom.cdx.json` โดยใช้ Linux PCI sysfs และข้อมูลไดรเวอร์ NVIDIA |
| รุ่นแพ็กเกจ PyTorch, Transformers, vLLM และ CUDA | SBOM ของโฮสต์หรือคอนเทนเนอร์เมื่ออ่านเมทาดาทาที่ติดตั้งได้ |
| โปรเซสให้บริการและซ็อกเก็ตที่รอรับ | `boms/obom.cdx.json` เมื่อสังเกตพบโปรเซสและไฟล์ปฏิบัติการ |

ข้อมูลฝึกและประเมินและสายสืบทอดที่ไม่มีใน model card ต้องมีข้อประกาศ provenance การใช้ GPU/VRAM ปัจจุบัน การจัดสรร MIG และ context ที่ให้บริการ ต้องมีการสังเกตรันไทม์แยกต่างหาก

อาร์ติแฟกต์น้ำหนักแบบแยกบันทึก SHA-256 ทั้งไฟล์และเมทาดาทาส่วนหัว safetensors หรือ GGUF v2/v3 ที่มี พร้อม `artifact-binding=sha256-calculated` safetensors ให้ dtype และช่วงข้อมูล GGUF อาจให้ `general.name`, `general.architecture` และ `general.file_type` ข้อมูล tensor และการคำนวณโมเดลต้องตรวจสอบแยก [รูปแบบ safetensors](https://github.com/safetensors/safetensors#format)

```sh
./koda-bom domain-bom --output-dir ./results \
  --model-artifact ./model.safetensors
```

ใช้ `koda-model-1` ประกาศตัวตน revision ใบอนุญาต แหล่งที่มา โมเดลฐาน และชุดข้อมูล แทน `sha256` ตัวอย่างด้วยแฮชอาร์ติแฟกต์จริง 64 ตัวอักษร จับคู่ข้อประกาศแต่ละรายการกับ `--model-artifact` ตามลำดับ ข้อประกาศที่ตรงกันสามารถผูกไฟล์โมเดลรูปแบบอื่นได้ด้วย

```json
{
  "schema": "koda-model-1",
  "name": "example-model",
  "version": "revision-2",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "license": "Apache-2.0",
  "source": "https://models.example.invalid/example-model",
  "task": "classification",
  "architecture": "transformer",
  "baseModels": [{"name": "base-model", "version": "revision-1"}],
  "datasets": [{"name": "training-data", "version": "v1", "source": "https://data.example.invalid/training"}]
}
```

โมเดลใช้ชนิดส่วนประกอบ `machine-learning-model` และชุดข้อมูลใช้ `data` เก็บ dependencies และการอ้างอิง `modelCard.modelParameters.datasets` ไว้ โมเดลฐาน/ชุดข้อมูลแต่ละรายการต้องมี `name` และอาจมี `version`, `sha256`, `source`, `license` เมทาดาทาเหล่านี้เป็นข้อประกาศจากผู้จัดหา แฮชของอาร์ติแฟกต์หลักที่ส่งมาแยกจะได้รับการตรวจสอบโดยตรง

## MBOM

### Provenance ของการบิลด์ซอฟต์แวร์

`--provenance` รับ in-toto Statement v1 ที่มี SLSA provenance v1 ส่งผลิตภัณฑ์จริงผ่าน `--provenance-artifact` ต้องมี `subject` เพียงหนึ่งรายการที่ตรงกับ SHA-256 ของผลิตภัณฑ์ ผู้บิลด์ ชนิดการบิลด์ อินพุตที่แก้ค่าแล้ว invocation ID และเวลาเริ่ม/สิ้นสุด เติมใน CycloneDX `formulation.workflows` ละพารามิเตอร์ภายนอก/ภายในดิบ [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)

ฟิลด์จำเป็นคือ `_type=https://in-toto.io/Statement/v1`, `predicateType=https://slsa.dev/provenance/v1`, `subject[].name`, `subject[].digest.sha256`, `predicate.buildDefinition.buildType` และ `predicate.runDetails.builder.id` ใช้ `resolvedDependencies` และฟิลด์ `invocationId`, `startedOn`, `finishedOn` ใน `runDetails.metadata` เมื่อมี ตรวจสอบและแยกซอง DSSE ด้วยเครื่องมือภายนอกก่อนส่ง Statement JSON

### การผลิตทางกายภาพ

ใช้ `koda-manufacturing-1` กับ `--provenance` ID ผลิตภัณฑ์/ชิ้นส่วนและหมายเลขชิ้นส่วนระบุสิ่งของทางกายภาพ

```sh
./koda-bom domain-bom --output-dir ./results \
  --provenance ./manufacturing.json
```

```json
{
  "schema": "koda-manufacturing-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "observation": "reported",
  "product": {"id": "server", "name": "Server", "model": "R1", "partNumber": "SRV-R1", "manufacturer": "Example"},
  "parts": [{"id": "board", "name": "Mainboard", "partNumber": "MB-1"}],
  "steps": [
    {"name": "Install board", "action": "assembly", "inputIds": ["board"]},
    {"name": "Acceptance test", "action": "test", "inputIds": ["board"]}
  ]
}
```

`observation` เป็น `declared` สำหรับขั้นตอนที่วางแผน หรือ `reported` สำหรับการทำงานที่รายงาน ตั้ง `observedAt` เป็นเวลาที่บันทึกข้อมูล การกระทำที่รองรับคือ `assembly`, `inspection`, `test`, `packaging` เชื่อมขั้นตอนได้สูงสุด 1,000 ขั้นตามลำดับในอาร์เรย์ `startedOn`/`finishedOn` เป็นฟิลด์ทางเลือกอธิบายแต่ละขั้น `inputIds` ต้องอ้างถึง `parts` ผลิตภัณฑ์และชิ้นส่วนอาจมี `version`

## ตัวอย่างซอร์สที่เรียกใช้ได้

คลังซอร์สมี fixture จำลองขนาดเล็กสำหรับบริการ/OpenAPI โมเดล SLSA และการผลิตใน `internal/domainbom/testdata/`

```sh
./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --saas-evidence ./internal/domainbom/testdata/services.json \
  --saas-evidence ./internal/domainbom/testdata/openapi.json \
  --model-evidence ./internal/domainbom/testdata/model.json \
  --model-artifact ./internal/domainbom/testdata/model.safetensors \
  --provenance ./internal/domainbom/testdata/provenance.json \
  --provenance-artifact ./internal/domainbom/testdata/product.bin

./koda-bom domain-bom --output-dir ./results --cyclonedx-17 \
  --provenance ./internal/domainbom/testdata/manufacturing.json
```

[ขอบเขตการเก็บข้อมูล](support-matrix.th.md) · [บัญชีรายการทรัพย์สิน](asset-inventory.th.md)
