# 한 파일로 하드웨어와 소프트웨어 수집

대상 OS와 CPU 종류에 맞는 `koda-sbom` 실행 파일 한 개를 사용합니다. Linux에서는 기존 `scan` 명령으로 패키지와 호스트 하드웨어를 함께 수집합니다. Windows와 macOS용 실행 파일의 `platform-inventory`는 운영체제가 제공하는 로컬 인벤토리 도구를 호출합니다.

```sh
# Linux x86_64 또는 ARM64 호스트
./koda-sbom scan --output-dir ./reports

# 운영자가 정한 자산 라벨을 SBOM에 기록
./koda-sbom scan --output-dir ./reports --asset-tag 'web-01'

# CycloneDX 1.6과 1.7을 함께 저장
./koda-sbom scan --output-dir ./reports --cyclonedx-17

# 호스트와 외부 장비의 증적을 같은 결과에 기록
./koda-sbom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

# BMC·네트워크·OT 장비의 내보낸 증적만 표준 SBOM으로 변환
./koda-sbom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

# macOS 또는 Windows에서 해당 OS용 바이너리 사용
./koda-sbom platform-inventory --output-dir ./reports
```

Windows PowerShell에서 위 마지막 명령은 `.\koda-sbom.exe platform-inventory --output-dir .\reports`입니다. Linux 디렉터리와 이미지 수집은 지정한 범위를 사용합니다. 실행 중인 Linux 하드웨어는 호스트 `/`에서 컨텍스트가 활성화되어 있을 때 관측합니다. OCI/Docker 아카이브 지원 범위는 Linux amd64 이미지입니다. CycloneDX 확인본 한 개를 Tracker에 등록하고, 두 버전의 파일과 체크섬은 동일한 회차에서 보관할 수 있습니다.

## 어떤 정보를 남기는가

- **Linux 장비**. CPU와 마이크로코드, 커널 완화 관측값, 시스템·보드, BIOS·UEFI, ESRT, PCI 장치와 드라이버, NVMe·SCSI 저장장치, USB, TPM에서 노출된 필드를 읽습니다. 컨테이너에서 보이는 장치가 물리 호스트 소유인지 확인이 필요한 경우를 기록합니다. USB의 `bcdDevice`는 장치 릴리스 식별자로 보존합니다.
- **외부 장비**. 관리자 내보내기에서 얻은 확장 Redfish 객체, fwupd 장치 JSON, devlink JSON, [공통 장비 증적](#공통-장비-증적)을 반입합니다. devlink의 실행·저장 펌웨어를 구분합니다. BMC·RAID·OT 장비가 필요한 필드를 제공하는지는 제조사·모델마다 다릅니다.
- **실행 중 소프트웨어**. 프로세스에서 교체된 실행 파일·공유 라이브러리와 관측 가능한 파일 식별자를 기록합니다. 소유 패키지가 하나로 확인되면 설치 버전을 연결합니다. 교체가 관측되면 `restart_review`를 표시합니다. 설치 버전으로 메모리에서 실행 중인 버전을 확정하지 않습니다.
- **호스트 식별**. 호스트 `/` 수집이면 `/etc/machine-id`(없으면 `/var/lib/dbus/machine-id`)와 DMI `product_uuid`·`product_serial`·`board_serial`의 SHA-256만 기록하고 원문은 남기지 않습니다. 같은 서버를 다시 수집한 결과를 묶는 데 사용합니다. `--no-context`여도 수집하며, 디렉터리·이미지 수집은 다른 시스템의 파일일 수 있어 제외합니다. machine-id와 UUID는 소문자, 시리얼은 앞뒤 공백만 제거한 값의 해시입니다. CMDB 값과 대조할 때는 `printf %s '<값>' | sha256sum`으로 같은 값을 만듭니다. `To Be Filled By O.E.M.`, 전부 0인 UUID처럼 여러 서버가 공유하는 값은 기록하지 않습니다. DMI 시리얼은 보통 root만 읽을 수 있습니다. 시리얼은 경우의 수가 작아 해시에서 원문을 추측할 수 있으므로 익명화가 아니라 가명화로 취급하세요. `--asset-tag`(최대 128자, 한 줄)는 운영자가 지정한 라벨을 그대로 기록합니다. 호스트 이름이 필요하면 `--asset-tag "$(hostname)"`처럼 명시합니다. 컨테이너 안에서 수집하면 `observationScope`가 `container-visible`이며, 이때 DMI 값은 물리 호스트의 값일 수 있습니다.
- **수신 대기 소켓**. 수집기와 같은 네트워크 네임스페이스의 `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`에서 LISTEN TCP와 상대가 없는 UDP 소켓을 읽습니다. 각 프로세스의 `/proc/<pid>/fd`를 대조해 소켓을 연 프로세스에 연결하고, 실행 파일의 소유 패키지가 하나로 확인되면 그 패키지에 표시합니다. `bindScope`는 바인딩 주소만 나타냅니다(`all-interfaces`, `loopback`, `address`). 방화벽·라우팅을 확인하지 않으므로 `all-interfaces`가 외부에서 접근 가능하다는 뜻은 아닙니다. 소유 프로세스를 확인하지 못한 소켓(비root 실행, 제외 경로의 실행 파일 등)은 `context.json`의 `unattributedSockets`에 남깁니다. 다른 네트워크 네임스페이스(컨테이너 등)에서만 열린 소켓은 보이지 않습니다.
- **배포물**. 기존 JAR, 정적 JS, Go/Rust 등 수집과 함께 `.pyz`·`.pex`의 실제 `dist-info/METADATA`를 읽습니다. Docker/OCI에서는 원본 아카이브 SHA-256과 config digest를 기록하며, OCI에서는 검증된 manifest digest도 기록합니다.
- **출력**. CycloneDX 1.6과 SPDX 2.3에 장비·펌웨어·드라이버를 기록합니다. `--cyclonedx-17`을 지정하면 같은 인벤토리를 `sbom.cdx-1.7.json`으로도 저장합니다. SPDX 2.3에 전용 드라이버 유형이 없어 `OTHER`와 KODA 주석을 사용합니다. 호스트 식별은 CycloneDX `metadata.properties`의 `koda:host:*`와 SPDX 문서 `annotations`에 기록합니다. 수신 대기 소켓은 해당 패키지 구성요소의 `koda:runtime:listening`(소켓마다 하나)과 가장 넓은 범위인 `koda:runtime:bind-scope`로 기록하며, SPDX에서는 같은 이름으로 패키지 `annotations`에 기록합니다. Tracker에서 `koda:runtime:bind-scope = all-interfaces`인 구성요소의 취약점을 먼저 검토할 수 있습니다. `assets.json`에는 장비 증적, `context.json`에는 실행·설정 관측, `collection.json`에는 미확인 사유와 수집 범위가 있습니다. `inventory.syft.json`은 패키지 인벤토리입니다. `SHA256SUMS`로 결과를 검증할 수 있습니다.

## 공통 장비 증적

장비가 제공하는 JSON을 직접 지원하지 않으면 다음과 같이 구성합니다. 한 파일은 최대 8 MiB이며 명령 한 번에 최대 여덟 파일을 지정할 수 있습니다.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

`parentId`는 같은 파일의 장치 `id`를 가리킵니다. 버전을 확인할 수 없으면 해당 값을 생략해 미확인 상태를 보존합니다. Redfish는 URI 목록에서 한 단계 더 조회한 개별 장비·펌웨어 객체가 필요합니다. devlink의 실행·저장 버전은 각각의 관측값으로 남습니다. 결과에 기록한 원본 파일의 SHA-256은 어떤 파일을 반입했는지 확인하는 근거입니다.

## 오프라인 권고 대조

같은 바이너리의 `assess`에 SBOM과 확보한 권고 파일을 지정합니다. 새 권고 파일이 도착하면 기존 결과를 다시 대조할 수 있습니다.

```sh
./koda-sbom assess \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--context`와 `--kev`는 선택입니다. 컨텍스트를 사용하면 같은 수집 디렉터리의 `SHA256SUMS`에서 SBOM과 컨텍스트를 검증합니다. KEV는 결과 우선순위에 사용할 정보를 표시합니다. 평가는 실행 시 제공한 권고와 수집 당시 증적을 기준으로 합니다.

권고 파일에는 아래 형식이나 **정확한 영향 버전과 PURL을 가진 OSV**, **정확한 제품 식별자와 무조건부 상태를 가진 CSAF 2.0**을 사용할 수 있습니다. OSV 범위, CSAF의 제품 조합·정책 조건 등 지원되지 않는 표현은 대조를 중단하고 이유를 반환합니다. 공급사 조치 문구와 장비 조건은 출처를 확인해 명시 규칙으로 작성할 수 있습니다.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "공급사 권고에 따라 펌웨어 활성화 확인"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Linux 배포판 패키지는 릴리스가 포함된 distro 식별자와 정확한 버전을 사용합니다. 명시 규칙의 지원 종료는 `supportEndsAt`에 날짜를 기록하며, 버전 비교는 지원되는 소프트웨어 생태계에 한해 `affectedSemver`를 사용할 수 있습니다. 교체 파일이나 저장 상태가 확인되면 활성화 검토 상태로 나타납니다. 권고에 없는 버전이나 미확인 장비는 검토 대상으로 봅니다.

Linux 물리 서버와 Windows 운영 장비에서는 장비 권고 및 각 제조사 인벤토리를 대조해 범위를 확인해야 합니다. macOS·Windows 네이티브 기능은 OS·하드웨어와 설치 앱 중심이며, 장치가 보고하지 않는 버전이나 앱 내부 의존성은 추가 증적이 필요합니다.
