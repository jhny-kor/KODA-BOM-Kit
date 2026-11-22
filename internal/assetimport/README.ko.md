# 오프라인 장치 증거

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit의 `Load`는 최대 8 MiB, 4096개 레코드의 일반 JSON 파일 하나를 읽습니다. fwupd `get-devices --json` 내보내기(`Devices`), 확장된 Redfish `SoftwareInventory`, `Manager`, `ComputerSystem` 객체와 해당 객체 모음을 지원합니다. URI만 있는 Redfish 멤버는 불완전 수집 이슈를 생성합니다. 가져온 값은 관리자가 내보낸 관측값입니다. 펌웨어 `ImageState`는 제공될 때 보존하며 없으면 미상으로 둡니다. 내보낸 파일의 해시는 증거 바이트를 식별하며 출처를 인증하지 않습니다.

Windows, macOS, OT 및 다른 인벤토리 제공자는 다음 명시적 형식으로 내보낼 수 있습니다.

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

지원 종류는 `device`, `firmware`, `device-driver`입니다. 허용 속성은 `runningVersion`, `storedVersion`, `versionFormat`, `rawVersion`, `applicationState`, `platform`, `productCode`, `pciVendor`, `pciDevice`, `pciSubsystem`, `updateState`입니다. ID는 증거 다이제스트 범위로 제한하여 서로 다른 가져오기를 잘못 병합하지 않게 합니다. 펌웨어 버전 누락은 불완전 수집 이슈로 기록합니다. CPE는 추론하지 않습니다. 관측 시각은 원본 내보내기의 시각이며 생략하면 미상입니다.

일반 형식은 `library`, `application`, `operating-system`, `container`도 허용합니다. 선택 사항인 `purl`은 파싱하며 버전을 포함하면 명시적 버전과 일치해야 합니다. qualifier는 `arch`, `distro`, `epoch`, `type`, `classifier`로 제한합니다. 선택 사항인 `sha256`은 64자리 16진수여야 하며 가져온 구성 요소를 식별합니다. 가져오기 도구는 증거 파일의 해시를 별도로 계산합니다. Windows와 macOS에서는 네이티브 플랫폼 인벤토리 명령을 사용할 수 있습니다. 다른 제공자의 추가 증거에는 이 형식을 사용합니다.

`devlink -j dev info` 내보내기는 `info` 객체를 통해 수용합니다. 버스 참조가 항목을 식별합니다. fixed, running, stored 버전 그룹은 따로 보존합니다. 실행 중인 `fw`가 보고되면 구성 요소 버전으로 사용합니다. 드라이버별 대체 버전 키는 속성에 남깁니다. `fw` 누락은 버전 미상 이슈가 되며 일련번호는 제외합니다.
