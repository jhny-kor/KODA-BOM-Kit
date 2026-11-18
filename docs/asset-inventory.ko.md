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

- **Linux 장비**. CPU와 마이크로코드, 커널 완화 관측값, 시스템·보드, BIOS·UEFI, ESRT, PCI 장치와 드라이버, NVMe·SCSI 저장장치, USB, TPM에서 노출된 필드를 읽습니다. RAID/HBA 컨트롤러(mpt3sas, qla2xxx, lpfc, hpsa, smartpqi)의 펌웨어·BIOS 버전, InfiniBand·Mellanox 어댑터의 `fw_ver`, NVIDIA GPU의 Video BIOS와 amdgpu의 `vbios_version`도 읽습니다. 물리 NIC의 펌웨어는 `ethtool -i`와 같은 읽기 전용 ioctl로 읽어 해당 PCI 장치에 연결합니다. 외부 프로그램은 실행하지 않습니다. megaraid_sas는 sysfs에 펌웨어 버전을 제공하지 않으므로 `storcli` 등으로 내보낸 결과를 `--asset-evidence`로 지정합니다. BMC(iDRAC·iLO·XClarity·Supermicro 등)는 커널 IPMI 드라이버의 `/dev/ipmi0`에 읽기 전용 명령 `Get Device ID`를 보내 펌웨어 리비전, 제조사(IANA 번호), 제품 ID, 보조 펌웨어 리비전을 기록합니다. root 권한과 `ipmi_si`·`ipmi_devintf` 모듈이 필요합니다. SMBIOS에 BMC가 있는데 장치 파일이 없으면 그 사유를 남깁니다. `Get Device ID`의 리비전은 제조사의 공개 펌웨어 버전 표기와 자릿수가 다를 수 있으므로 정확한 빌드 대조가 필요하면 Redfish 내보내기를 함께 사용합니다. 컨테이너에서 보이는 장치가 물리 호스트 소유인지 확인이 필요한 경우를 기록합니다. USB의 `bcdDevice`는 장치 릴리스 식별자로 보존합니다.
- **외부 장비**. 관리자 내보내기에서 얻은 확장 Redfish 객체, fwupd 장치 JSON, devlink JSON, [공통 장비 증적](#공통-장비-증적)을 반입합니다. devlink의 실행·저장 펌웨어를 구분합니다. BMC·RAID·OT 장비가 필요한 필드를 제공하는지는 제조사·모델마다 다릅니다.
- **실행 중 소프트웨어**. 프로세스에서 교체된 실행 파일·공유 라이브러리와 관측 가능한 파일 식별자를 기록합니다. 소유 패키지가 하나로 확인되면 설치 버전을 연결합니다. 교체가 관측되면 `restart_review`를 표시합니다. 설치 버전으로 메모리에서 실행 중인 버전을 확정하지 않습니다.
- **호스트 식별**. 호스트 `/` 수집이면 `/etc/machine-id`(없으면 `/var/lib/dbus/machine-id`)와 DMI `product_uuid`·`product_serial`·`board_serial`의 SHA-256만 기록하고 원문은 남기지 않습니다. 같은 서버를 다시 수집한 결과를 묶는 데 사용합니다. `--no-context`여도 수집하며, 디렉터리·이미지 수집은 다른 시스템의 파일일 수 있어 제외합니다. machine-id와 UUID는 소문자, 시리얼은 앞뒤 공백만 제거한 값의 해시입니다. CMDB 값과 대조할 때는 `printf %s '<값>' | sha256sum`으로 같은 값을 만듭니다. `To Be Filled By O.E.M.`, 전부 0인 UUID처럼 여러 서버가 공유하는 값은 기록하지 않습니다. DMI 시리얼은 보통 root만 읽을 수 있습니다. 시리얼은 경우의 수가 작아 해시에서 원문을 추측할 수 있으므로 익명화가 아니라 가명화로 취급하세요. `--asset-tag`(최대 128자, 한 줄)는 운영자가 지정한 라벨을 그대로 기록합니다. 호스트 이름이 필요하면 `--asset-tag "$(hostname)"`처럼 명시합니다. 컨테이너 안에서 수집하면 `observationScope`가 `container-visible`이며, 이때 DMI 값은 물리 호스트의 값일 수 있습니다.
- **수신 대기 소켓**. 수집기와 같은 네트워크 네임스페이스의 `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`에서 LISTEN TCP와 상대가 없는 UDP 소켓을 읽습니다. 각 프로세스의 `/proc/<pid>/fd`를 대조해 소켓을 연 프로세스에 연결하고, 실행 파일의 소유 패키지가 하나로 확인되면 그 패키지에 표시합니다. `bindScope`는 바인딩 주소만 나타냅니다(`all-interfaces`, `loopback`, `address`). 방화벽·라우팅을 확인하지 않으므로 `all-interfaces`가 외부에서 접근 가능하다는 뜻은 아닙니다. 소유 프로세스를 확인하지 못한 소켓(비root 실행, 제외 경로의 실행 파일 등)은 `context.json`의 `unattributedSockets`에 남깁니다. 다른 네트워크 네임스페이스(컨테이너 등)에서만 열린 소켓은 보이지 않습니다.
- **보안 설정과 재부팅 신호**. 호스트 `/` 수집이면 `context.json`의 `settings`에 다음을 기록합니다. SELinux 실행 모드(`/sys/fs/selinux/enforce`)와 다음 부팅에 적용될 `/etc/selinux/config`의 `SELINUX=` 값, AppArmor 활성화 여부와 모드별 프로필 수(root 권한 필요), 커널 lockdown 모드, FIPS 모드(`crypto.fips_enabled`)입니다. 재부팅 신호는 각각 따로 남깁니다. `/run/reboot-required` 존재 여부(Debian·Ubuntu), 실행 중 커널의 모듈 트리가 아직 설치돼 있는지(`kernel.running-modules-installed`), 같은 계열의 더 새 커널이 설치됐는지(`kernel.newer-installed`)입니다. 같은 계열은 릴리스 문자열의 영문 토큰으로 묶습니다. 예를 들어 Oracle UEK와 RHCK는 서로 다른 계열로 취급합니다. 신호가 하나라도 있으면 `reboot.recommended`가 `true`이고, 없으면 `not_observed`입니다. 신호가 없다는 것이 재부팅이 필요 없다는 증명은 아닙니다. 이 값들은 `assess` 규칙의 `setting` 조건으로 대조할 수 있습니다. 컨테이너 안에서 수집하면 SELinux·securityfs가 보이지 않을 수 있습니다.
- **SSH 서버 설정**. `/etc/ssh/sshd_config`와 `sshd_config.d/*.conf`에서 `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`의 선언값을 파일별로 기록합니다. 예를 들어 `LoginGraceTime 0`은 CVE-2024-6387의 완화 설정입니다. `Match` 이후는 조건부 설정이라 읽지 않습니다. sshd는 처음 읽은 값을 사용하므로 `Include` 순서가 실제 적용값을 결정하며, 이 기록은 실제 적용값의 계산이 아니라 선언 관측입니다.
- **배포판 밖 커널 모듈**. `kernel.tainted` 값과, 로드된 모듈 중 커널을 taint시키는 모듈의 이름·플래그·`version`·`srcversion`을 `context.json`의 `taintedModules`에 기록합니다. `O`는 커널 트리 밖, `E`는 서명 없음, `P`는 독점 모듈입니다. 벤더 RAID·NIC·GPU 드라이버나 DKMS 모듈은 배포판 커널 보안 공지에 포함되지 않으므로 별도로 관리해야 합니다.
- **식별되지 않은 실행 중 프로그램**. 실행 중인 프로세스 중 설치 패키지가 소유하지 않고, 수집기가 구성요소로 식별하지 않았으며, 확인된 제품 설치 경로 밖에 있는 실행 파일을 `unidentifiedExecutables`에 경로와 PID로 기록합니다. SBOM에 나타나지 않는데 실행 중인 소프트웨어를 찾는 데 사용합니다. `/bin`이 `/usr/bin`을 가리키는 usr-merge 시스템에서는 패키지 DB의 `/bin/...` 경로를 `/usr/bin/...`과 같은 파일로 대조합니다.
- **패키지 파일 무결성**. 호스트·디렉터리·이미지 수집과 컨테이너별 수집에서 RPM·dpkg·apk DB에 해시가 기록된 실행 파일(`bin`·`sbin`·`libexec` 아래)과 공유 라이브러리(`.so`)를 실제 파일과 비교합니다(`rpm -V`, `debsums`와 같은 방식). 설정 파일(`%config`, dpkg conffile)과 `%ghost` 파일은 제외합니다. 해시가 다르면 `modified`, 파일이 없으면 `missing`으로 `collection.json`의 `integrity.findings`에 기록하고 SBOM의 해당 패키지에 `koda:integrity:modified`·`koda:integrity:missing`을 붙입니다. 패키지 버전은 최신인데 바이너리가 수동으로 교체된 경우처럼 SBOM 버전과 실제 파일이 다를 수 있음을 알려 줍니다. 사용자가 제외한 경로는 읽지 않습니다. 호스트는 8 GiB, 컨테이너마다 1 GiB를 해시하면 멈추고 `partial`로 표시합니다. 오래된 Red Hat 계열의 prelink 바이너리는 교체되지 않아도 불일치로 나올 수 있습니다.
- **인증서·암호 인벤토리(CBOM)**. 수집 범위의 `.pem`·`.crt`·`.cer`·`.der`·`.cert` 파일에서 X.509 인증서를 읽어 CycloneDX 1.6·1.7의 `cryptographic-asset`(`assetType: certificate`)으로 기록하고, 서명·공개키 알고리즘을 `assetType: algorithm` 구성요소로 함께 기록합니다. 유효기간, 서명 알고리즘, 키 종류·길이, CA 여부, 자체 서명 여부, 상태(`expired`, `expiring-within-30-days`, `not-yet-valid`, `valid`), 약한 설정(`sha1-signature`, `md5-signature`, `rsa-key-below-2048`, `dsa-key`)을 남기며 지문은 DER의 SHA-256입니다. 나열한 알고리즘은 모두 고전 암호이므로 `nistQuantumSecurityLevel`은 0이고 PQC 전환 대상 파악에 사용할 수 있습니다. 주체·발급자 이름은 내부 호스트명이나 이메일을 포함할 수 있어 기록하지 않고 경로와 지문으로 식별합니다. 개인키 블록은 읽지 않고 건너뜁니다. 배포판 신뢰 저장소(`/etc/ssl/certs`, `/etc/pki/ca-trust` 등)와 인증서가 20개를 넘는 번들 파일은 운영자 인증서가 아니므로 제외합니다. SPDX에는 `OTHER` 패키지와 KODA 주석으로 기록합니다.
- **snap·flatpak·conda**. snap은 `snap/<이름>/current`가 가리키는 리비전의 `meta/snap.yaml`로 snap 자체의 이름·버전을 기록하고, 롤백용으로 남은 이전 리비전은 제외합니다. snap 안에 포함된 Debian 패키지도 기록합니다. flatpak은 `active` 배포만 기록하며 AppStream의 최신 `release` 버전을 사용합니다. conda는 `conda-meta/*.json`에서 읽고 `pkg:conda` PURL을 부여합니다. 사설 미러 주소가 남지 않도록 채널은 이름만 기록합니다.
- **실행 중인 컨테이너**. 호스트 `/` 수집이면 실행 중인 컨테이너마다 `containers/<이름>/`에 `sbom.cdx.json`·`sbom.spdx.json`·`collection.json`·`SHA256SUMS`를 별도로 만듭니다. Kubernetes 컨테이너는 `<namespace>_<pod>_<container>` 이름을 사용하고, 같은 이름이 겹치면 컨테이너 ID 앞 12자리를 붙입니다. 이름과 이미지는 Docker·containerd(Kubernetes·nerdctl)·Podman·CRI-O가 디스크에 남긴 상태 파일에서 읽으며 런타임 API나 소켓에는 연결하지 않습니다. 컨테이너 root filesystem은 컨테이너 프로세스의 `mountinfo`와 수집기의 `mountinfo`를 장치 번호로 대조해 찾습니다. 이미지 계층과 쓰기 계층이 대상이며 볼륨·bind mount는 포함하지 않습니다. 각 SBOM의 `koda:container:*` 속성에 이름·ID·런타임·이미지·이미지 digest, `koda:host:*` 속성에 같은 호스트 식별을 기록하므로 Tracker에서 컨테이너별 프로젝트로 등록해도 호스트와 연결할 수 있습니다. 컨테이너의 네트워크 네임스페이스에서 수신 대기 중인 소켓은 컨테이너 프로세스의 실행 파일과 대조해 `collection.json`의 `listeningSockets`에 기록하고, 실행 파일을 제공하는 구성요소가 하나로 확인되면 컨테이너 SBOM의 해당 구성요소에 `koda:runtime:listening`과 `koda:runtime:bind-scope`를 붙입니다. 설치 패키지가 소유한 파일이 우선이며, Go 바이너리는 main module을 사용합니다. root filesystem이 보이지 않거나 시간 제한에 걸린 컨테이너는 호스트 `collection.json`의 `containers`에 `not_collected`와 사유를 남깁니다. 끄려면 `--no-containers`를 지정합니다.
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
