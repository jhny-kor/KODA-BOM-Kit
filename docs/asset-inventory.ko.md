# 한 파일로 하드웨어와 소프트웨어 수집

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="asset-inventory.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


대상 OS와 CPU 종류에 맞는 `koda-bom` 실행 파일 한 개를 사용합니다. Linux에서는 기존 `scan` 명령으로 패키지와 호스트 하드웨어를 함께 수집합니다. Windows와 macOS용 실행 파일의 `platform-inventory`는 운영체제가 제공하는 로컬 인벤토리 도구를 호출합니다.

```sh
# Linux x86_64 또는 ARM64 호스트
./koda-bom scan --output-dir ./reports

# 운영자가 정한 자산 라벨을 SBOM에 기록
./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

# CycloneDX 1.6과 1.7을 함께 저장
./koda-bom scan --output-dir ./reports --cyclonedx-17

# 호스트와 외부 장비의 증적을 같은 결과에 기록
./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

# BMC·네트워크·OT 장비의 내보낸 증적만 표준 SBOM으로 변환
./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

# macOS 또는 Windows에서 해당 OS용 바이너리 사용
./koda-bom platform-inventory --output-dir ./reports
```

Windows PowerShell에서 위 마지막 명령은 `.\koda-bom.exe platform-inventory --output-dir .\reports`입니다. Linux 디렉터리와 이미지 수집은 지정한 범위를 사용합니다. 실행 중인 Linux 하드웨어는 호스트 `/`에서 컨텍스트가 활성화되어 있을 때 관측합니다. OCI/Docker 아카이브 지원 범위는 Linux amd64 이미지입니다. CycloneDX 확인본 한 개를 Tracker에 등록하고, 두 버전의 파일과 체크섬은 동일한 회차에서 보관할 수 있습니다.

## 어떤 정보를 남기는가

- **Linux 장비**. CPU와 마이크로코드, 커널 완화 관측값, 시스템·보드, BIOS·UEFI, ESRT, PCI 장치와 드라이버, NVMe·SCSI 저장장치, USB, TPM에서 노출된 필드를 읽습니다. RAID/HBA 컨트롤러(mpt3sas, qla2xxx, lpfc, hpsa, smartpqi)의 펌웨어·BIOS 버전, InfiniBand·Mellanox 어댑터의 `fw_ver`, NVIDIA GPU의 Video BIOS와 amdgpu의 `vbios_version`도 읽습니다. 물리 NIC의 펌웨어는 `ethtool -i`와 같은 읽기 전용 ioctl로 읽어 해당 PCI 장치에 연결합니다. 외부 프로그램은 실행하지 않습니다. root로 실행하면 SMBIOS 원본 테이블에서 메모리 모듈의 제조사·부품번호·용량·속도, 전원공급장치의 모델·정격 출력, 시스템 슬롯과 장착된 PCI 주소를 읽습니다. 일련번호는 SHA-256으로만 기록합니다. megaraid_sas는 sysfs에 펌웨어 버전을 제공하지 않으므로 `storcli` 등으로 내보낸 결과를 `--asset-evidence`로 지정합니다. BMC(iDRAC·iLO·XClarity·Supermicro 등)는 커널 IPMI 드라이버의 `/dev/ipmi0`에 읽기 전용 명령 `Get Device ID`를 보내 펌웨어 리비전, 제조사(IANA 번호), 제품 ID, 보조 펌웨어 리비전을 기록합니다. root 권한과 `ipmi_si`·`ipmi_devintf` 모듈이 필요합니다. SMBIOS에 BMC가 있는데 장치 파일이 없으면 그 사유를 남깁니다. `Get Device ID`의 리비전은 제조사의 공개 펌웨어 버전 표기와 자릿수가 다를 수 있으므로 정확한 빌드 대조가 필요하면 Redfish 내보내기를 함께 사용합니다. 컨테이너에서 보이는 장치가 물리 호스트 소유인지 확인이 필요한 경우를 기록합니다. USB의 `bcdDevice`는 장치 릴리스 식별자로 보존합니다. CPU에는 x86이면 CPUID 시그니처(`cpuidSignature`, 예: `00050657`)와 마이크로코드 파일 이름 형식(`familyModelStepping`, 예: `06-55-07`)을 남겨 Intel·AMD 마이크로코드 권고와 바로 대조할 수 있게 합니다. 각 논리 CPU의 소켓(`socket`)과 코어(`core`) 번호는 sysfs topology에서 읽습니다. arm64는 `/proc/cpuinfo`에 16진수 코드만 있으므로 util-linux `lscpu`와 같은 표로 제조사(`vendor`)와 코어 이름(`model`, 예: `Neoverse-N1`), `r3p1` 형식 리비전을 채웁니다. 표에 없는 코어는 이름을 비워 두고 원래 코드를 보존합니다.
- **외부 장비**. 관리자 내보내기에서 얻은 확장 Redfish 객체, fwupd 장치 JSON, devlink JSON, [공통 장비 증적](#공통-장비-증적)을 반입합니다. devlink의 실행·저장 펌웨어를 구분합니다. BMC·RAID·OT 장비가 필요한 필드를 제공하는지는 제조사·모델마다 다릅니다.
- **실행 중 소프트웨어**. 프로세스에서 교체된 실행 파일·공유 라이브러리와 관측 가능한 파일 식별자를 기록합니다. 소유 패키지가 하나로 확인되면 설치 버전을 연결합니다. 교체가 관측되면 `restart_review`를 표시합니다. 설치 버전으로 메모리에서 실행 중인 버전을 확정하지 않습니다.
- **호스트 식별**. 호스트 `/` 수집이면 `/etc/machine-id`(없으면 `/var/lib/dbus/machine-id`)와 DMI `product_uuid`·`product_serial`·`board_serial`의 SHA-256만 기록하고 원문은 남기지 않습니다. 같은 서버를 다시 수집한 결과를 묶는 데 사용합니다. `--no-context`여도 수집하며, 디렉터리·이미지 수집은 다른 시스템의 파일일 수 있어 제외합니다. machine-id와 UUID는 소문자, 시리얼은 앞뒤 공백만 제거한 값의 해시입니다. CMDB 값과 대조할 때는 `printf %s '<값>' | sha256sum`으로 같은 값을 만듭니다. `To Be Filled By O.E.M.`, 전부 0인 UUID처럼 여러 서버가 공유하는 값은 기록하지 않습니다. DMI 시리얼은 보통 root만 읽을 수 있습니다. 시리얼은 경우의 수가 작아 해시에서 원문을 추측할 수 있으므로 익명화가 아니라 가명화로 취급하세요. `--asset-tag`(최대 128자, 한 줄)는 운영자가 지정한 라벨을 그대로 기록합니다. 호스트 이름이 필요하면 `--asset-tag "$(hostname)"`처럼 명시합니다. 컨테이너 안에서 수집하면 `observationScope`가 `container-visible`이며, 이때 DMI 값은 물리 호스트의 값일 수 있습니다.
- **수신 대기 소켓**. 수집기와 같은 네트워크 네임스페이스의 `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`에서 LISTEN TCP와 상대가 없는 UDP 소켓을 읽습니다. 각 프로세스의 `/proc/<pid>/fd`를 대조해 소켓을 연 프로세스에 연결하고, 실행 파일의 소유 패키지가 하나로 확인되면 그 패키지에 표시합니다. `bindScope`는 바인딩 주소만 나타냅니다(`all-interfaces`, `loopback`, `address`). 방화벽·라우팅을 확인하지 않으므로 `all-interfaces`가 외부에서 접근 가능하다는 뜻은 아닙니다. 소유 프로세스를 확인하지 못한 소켓(비root 실행, 제외 경로의 실행 파일 등)은 `context.json`의 `unattributedSockets`에 남깁니다. 다른 네트워크 네임스페이스(컨테이너 등)에서만 열린 소켓은 보이지 않습니다. 호스트 프로세스가 맺고 있는 외부 TCP 연결은 프로세스와 원격 주소별로 `outboundConnections`에 기록하며, `remoteScope`로 `loopback`·`private`·`link-local`·`public`·`local-host`를 구분합니다.
- **보안 설정과 재부팅 신호**. 호스트 `/` 수집이면 `context.json`의 `settings`에 다음을 기록합니다. SELinux 실행 모드(`/sys/fs/selinux/enforce`)와 다음 부팅에 적용될 `/etc/selinux/config`의 `SELINUX=` 값, AppArmor 활성화 여부와 모드별 프로필 수(root 권한 필요), 커널 lockdown 모드, FIPS 모드(`crypto.fips_enabled`), `/proc/cmdline`의 보안 관련 부팅 옵션(`cmdline.mitigations`, `cmdline.nosmt`, `cmdline.spectre_v2` 등)입니다. 부팅 옵션은 허용 목록에 있는 것만 기록하며 `root=`나 iSCSI·NFS 인증 정보 같은 나머지 값은 남기지 않습니다. 실행 커널의 빌드 설정은 `context.json`의 `kernelConfig`에 기록합니다. `/proc/config.gz`가 있으면 그것을, 없으면 `/boot/config-<실행 커널>`을 읽고 내장(`y`)·모듈(`m`) 옵션만 남깁니다. 둘 다 없으면 생략합니다. 재부팅 신호는 각각 따로 남깁니다. `/run/reboot-required` 존재 여부(Debian·Ubuntu), 실행 중 커널의 모듈 트리가 아직 설치돼 있는지(`kernel.running-modules-installed`), 같은 계열의 더 새 커널이 설치됐는지(`kernel.newer-installed`)입니다. 같은 계열은 릴리스 문자열의 영문 토큰으로 묶습니다. 예를 들어 Oracle UEK와 RHCK는 서로 다른 계열로 취급합니다. 신호가 하나라도 있으면 `reboot.recommended`가 `true`이고, 없으면 `not_observed`입니다. 신호가 없다는 것이 재부팅이 필요 없다는 증명은 아닙니다. 이 값들은 `assess` 규칙의 `setting` 조건으로 대조할 수 있습니다. 컨테이너 안에서 수집하면 SELinux·securityfs가 보이지 않을 수 있습니다.
- **SSH 서버 설정**. `/etc/ssh/sshd_config`와 `sshd_config.d/*.conf`에서 `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`의 선언값을 파일별로 기록합니다. 예를 들어 `LoginGraceTime 0`은 CVE-2024-6387의 완화 설정입니다. `Match` 이후는 조건부 설정이라 읽지 않습니다. sshd는 처음 읽은 값을 사용하므로 `Include` 순서가 실제 적용값을 결정하며, 이 기록은 실제 적용값의 계산이 아니라 선언 관측입니다.
- **배포판 밖 커널 모듈**. `kernel.tainted` 값과, 로드된 모듈 중 커널을 taint시키는 모듈의 이름·플래그·`version`·`srcversion`을 `context.json`의 `taintedModules`에 기록합니다. `O`는 커널 트리 밖, `E`는 서명 없음, `P`는 독점 모듈입니다. 벤더 RAID·NIC·GPU 드라이버나 DKMS 모듈은 배포판 커널 보안 공지에 포함되지 않으므로 별도로 관리해야 합니다.
- **식별되지 않은 실행 중 프로그램**. 실행 중인 프로세스 중 설치 패키지가 소유하지 않고, 수집기가 구성요소로 식별하지 않았으며, 확인된 제품 설치 경로 밖에 있는 실행 파일을 `unidentifiedExecutables`에 경로와 PID로 기록합니다. SBOM에 나타나지 않는데 실행 중인 소프트웨어를 찾는 데 사용합니다. `/bin`이 `/usr/bin`을 가리키는 usr-merge 시스템에서는 패키지 DB의 `/bin/...` 경로를 `/usr/bin/...`과 같은 파일로 대조합니다.
- **패키지 파일 무결성**. 호스트·디렉터리·이미지 수집과 컨테이너별 수집에서 RPM·dpkg·apk DB에 해시가 기록된 실행 파일(`bin`·`sbin`·`libexec` 아래)과 공유 라이브러리(`.so`)를 실제 파일과 비교합니다(`rpm -V`, `debsums`와 같은 방식). 설정 파일(`%config`, dpkg conffile)과 `%ghost` 파일은 제외합니다. 해시가 다르면 `modified`, 파일이 없으면 `missing`으로 `collection.json`의 `integrity.findings`에 기록하고 SBOM의 해당 패키지에 `koda:integrity:modified`·`koda:integrity:missing`을 붙입니다. 패키지 버전은 최신인데 바이너리가 수동으로 교체된 경우처럼 SBOM 버전과 실제 파일이 다를 수 있음을 알려 줍니다. 사용자가 제외한 경로는 읽지 않습니다. 호스트는 8 GiB, 컨테이너마다 1 GiB를 해시하면 멈추고 `partial`로 표시합니다. 오래된 Red Hat 계열의 prelink 바이너리는 교체되지 않아도 불일치로 나올 수 있습니다.
- **패키지 출처**. 설치된 패키지가 저장소에서 왔는지 기록합니다. dpkg 패키지는 `/var/lib/apt/lists`의 `Packages` 목록(평문·gz·lz4)에 이름이 있으면 `repository`, 목록이 있는데 이름이 없으면 `not-recorded`입니다. 저장소 목록은 현재 내용만 담으므로 버전이 아니라 이름으로 판단합니다. RPM은 dnf 이력(`/var/lib/dnf/history.sqlite`, 완료된 설치·업그레이드·다운그레이드·재설치)이나 yum의 `yumdb`(`from_repo`)에서 설치한 저장소 ID를 읽습니다. `dnf install ./파일.rpm`은 `local-file`, 이력에 없는 패키지(`rpm -i`로 설치, 삭제된 저장소)는 `not-recorded`입니다. `gpg-pubkey`는 제외합니다. dnf 이력 DB는 결과 폴더의 임시 디렉터리에 복사해 읽기 전용으로 엽니다. 저장소 주소(미러 호스트)와 로컬 파일 경로는 기록하지 않고 저장소 ID만 남깁니다. apt 목록이나 dnf·yum 이력이 없으면(예: `apt-get clean` 이후 목록 삭제, dnf5) 분류하지 않습니다. 결과는 `collection.json`의 `packageOrigin`과 SBOM의 `koda:package:origin`·`koda:package:repository`에 있으며 `not-recorded`·`local-file` 패키지는 저장소 업데이트로 패치되지 않을 수 있습니다.
- **부팅 시 시작되는 서비스**. `/etc/systemd/system`, `/usr/lib/systemd/system`(호스트 수집이면 `/run/systemd/system`도)의 `*.wants`·`*.requires`에 연결된 서비스와 소켓을 `context.json`의 `enabledServices`에 기록합니다. 단위 파일과 drop-in(`*.d/*.conf`)을 적용한 첫 `ExecStart` 실행 파일, 소켓이면 `ListenStream` 등의 값과 활성화하는 서비스, 실행 파일을 소유한 패키지 PURL을 남깁니다. 마스크된 단위는 제외합니다. 활성화된 타이머는 `On*` 일정과 시작하는 서비스를 함께 기록합니다. 호스트 수집이면 서비스 cgroup(`system.slice`)에 프로세스가 있는지로 `running`·`stopped`를 표시합니다. 지금은 멈춰 있지만 재부팅하면 시작되는 서비스(예: 소켓 활성화 `ssh.socket`)를 찾는 데 씁니다. SBOM의 해당 패키지에는 `koda:runtime:enabled-service`가 붙습니다. `Slice=`로 다른 slice에서 실행되는 서비스는 `stopped`로 보일 수 있습니다.
- **하드웨어 CPE**. NVD CPE 사전의 명명과 대조한 형식만 생성합니다. x86 CPU 모델명에서 `cpe:2.3:h:intel:xeon_gold_6248`, `cpe:2.3:h:amd:epyc_7763` 같은 하드웨어 CPE를 만들고, Dell PowerEdge는 장치와 BIOS 버전 펌웨어 CPE(`cpe:2.3:o:dell:poweredge_r740_firmware:2.9.4`), Lenovo ThinkSystem은 장치 CPE만 만듭니다. 모델 번호가 없는 가상 CPU 이름, HPE(NVD에서 `hp`와 `hpe`가 섞여 있음), 세대를 알 수 없는 BMC에는 CPE를 붙이지 않습니다.
- **인증서·암호 인벤토리(CBOM)**. `etc/ssh/ssh_host_*_key.pub`의 SSH 호스트 공개키를 OpenSSH SHA-256 지문과 함께 기록합니다. 수집 범위의 `.pem`·`.crt`·`.cer`·`.der`·`.cert` 파일에서 X.509 인증서를 읽어 CycloneDX 1.6·1.7의 `cryptographic-asset`(`assetType: certificate`)으로 기록하고, 서명·공개키 알고리즘을 `assetType: algorithm` 구성요소로 함께 기록합니다. 유효기간, 서명 알고리즘, 키 종류·길이, CA 여부, 자체 서명 여부, 상태(`expired`, `expiring-within-30-days`, `not-yet-valid`, `valid`), 약한 설정(`sha1-signature`, `md5-signature`, `rsa-key-below-2048`, `dsa-key`)을 남기며 지문은 DER의 SHA-256입니다. 나열한 알고리즘은 모두 고전 암호이므로 `nistQuantumSecurityLevel`은 0이고 PQC 전환 대상 파악에 사용할 수 있습니다. 주체·발급자 이름은 내부 호스트명이나 이메일을 포함할 수 있어 기록하지 않고 경로와 지문으로 식별합니다. 개인키 블록은 읽지 않고 건너뜁니다. 배포판 신뢰 저장소(`/etc/ssl/certs`, `/etc/pki/ca-trust` 등)와 인증서가 20개를 넘는 번들 파일은 운영자 인증서가 아니므로 제외합니다. SPDX에는 `OTHER` 패키지와 KODA 주석으로 기록합니다.
- **snap·flatpak·conda**. snap은 `snap/<이름>/current`가 가리키는 리비전의 `meta/snap.yaml`로 snap 자체의 이름·버전을 기록하고, 롤백용으로 남은 이전 리비전은 제외합니다. snap 안에 포함된 Debian 패키지도 기록합니다. flatpak은 `active` 배포만 기록하며 AppStream의 최신 `release` 버전을 사용합니다. conda는 `conda-meta/*.json`에서 읽고 `pkg:conda` PURL을 부여합니다. 사설 미러 주소가 남지 않도록 채널은 이름만 기록합니다.
- **실행 중인 컨테이너**. 호스트 `/` 수집이면 실행 중인 컨테이너마다 `containers/<이름>/`에 `sbom.cdx.json`·`sbom.spdx.json`·`collection.json`·`SHA256SUMS`를 별도로 만듭니다. Kubernetes 컨테이너는 `<namespace>_<pod>_<container>` 이름을 사용하고, 같은 이름이 겹치면 컨테이너 ID 앞 12자리를 붙입니다. 이름과 이미지는 Docker·containerd(Kubernetes·nerdctl)·Podman·CRI-O가 디스크에 남긴 상태 파일에서 읽으며 런타임 API나 소켓에는 연결하지 않습니다. 컨테이너 root filesystem은 컨테이너 프로세스의 `mountinfo`와 수집기의 `mountinfo`를 장치 번호로 대조해 찾습니다. 이미지 계층과 쓰기 계층이 대상이며 볼륨·bind mount는 포함하지 않습니다. 각 SBOM의 `koda:container:*` 속성에 이름·ID·런타임·이미지·이미지 digest, `koda:host:*` 속성에 같은 호스트 식별을 기록하므로 Tracker에서 컨테이너별 프로젝트로 등록해도 호스트와 연결할 수 있습니다. 컨테이너의 네트워크 네임스페이스에서 수신 대기 중인 소켓은 컨테이너 프로세스의 실행 파일과 대조해 `collection.json`의 `listeningSockets`에 기록하고, 실행 파일을 제공하는 구성요소가 하나로 확인되면 컨테이너 SBOM의 해당 구성요소에 `koda:runtime:listening`과 `koda:runtime:bind-scope`를 붙입니다. 설치 패키지가 소유한 파일이 우선이며, Go 바이너리는 main module을 사용합니다. root filesystem이 보이지 않거나 시간 제한에 걸린 컨테이너는 호스트 `collection.json`의 `containers`에 `not_collected`와 사유를 남깁니다. 끄려면 `--no-containers`를 지정합니다.
- **중지된 컨테이너와 로컬 이미지**. 호스트 `/` 수집이면 런타임이 디스크에 남긴 메타데이터로 실행 중이 아닌 컨테이너와 로컬 이미지도 찾습니다. Docker overlay2 저장소(`/var/lib/docker/image/overlay2`), containerd 저장소(`/var/lib/containerd`, Docker 29의 containerd 이미지 저장소, Kubernetes·nerdctl, k3s·RKE2), Podman·CRI-O의 containers-storage(`/var/lib/containers/storage`, rootful)를 읽습니다. containerd의 bolt DB는 내장한 읽기 전용 파서로 열며 런타임 API·소켓에는 연결하지 않습니다. 이미지 계층(과 컨테이너의 쓰기 계층)을 결과 폴더의 임시 디렉터리에 합쳐 복사하고 overlay whiteout·opaque 디렉터리를 적용한 뒤 실행 중인 컨테이너와 같은 방식으로 수집하고, 끝나면 복사본을 지웁니다. 장치 파일과 set-ID 비트는 복사하지 않습니다. 중지된 컨테이너는 `containers/<이름>/`에 `state: stopped`로, 어느 컨테이너(실행·중지)도 쓰지 않는 이미지는 `images/<이름>/`에 `state: image`로 만듭니다. 이미 컨테이너가 쓰는 이미지는 그 컨테이너 SBOM에 포함되므로 다시 만들지 않습니다. 여러 플랫폼 이미지는 이 서버 아키텍처의 매니페스트를 먼저, 없으면 내려받아진 다른 Linux 매니페스트를 사용합니다. 하나의 root filesystem이 16 GiB를 넘거나 결과 폴더 디스크 여유 공간이 크기+1 GiB보다 적으면 복사하지 않고 `not_collected`와 사유를 남깁니다. 실행 중이 아니므로 수신 소켓은 기록하지 않습니다. 수집하는 동안 시작되거나 삭제된 컨테이너는 계층이 바뀌어 `not_collected`가 될 수 있습니다. 끄려면 `--no-images`를 지정합니다. Docker의 btrfs·zfs·devicemapper 등 다른 저장 드라이버와 rootless Podman 저장소는 읽지 않습니다.
- **배포물**. 기존 JAR, 정적 JS, Go/Rust 등 수집과 함께 `.pyz`·`.pex`의 실제 `dist-info/METADATA`를 읽습니다. Docker/OCI에서는 원본 아카이브 SHA-256과 config digest를 기록하며, OCI에서는 검증된 manifest digest도 기록합니다.
- **출력**. 기본 실행은 `boms/` 아래에 7종의 개별 BOM과 루트 `bom.cdx.json` 병합본을 만듭니다. AI-BOM 파일명은 `aibom.cdx.json`입니다.  CycloneDX 1.6과 SPDX 2.3에 장비·펌웨어·드라이버를 기록합니다. `--cyclonedx-17`을 지정하면 같은 인벤토리를 `sbom.cdx-1.7.json`으로도 저장합니다. SPDX 2.3에 전용 드라이버 유형이 없어 `OTHER`와 KODA 주석을 사용합니다. 호스트 식별은 CycloneDX `metadata.properties`의 `koda:host:*`와 SPDX 문서 `annotations`에 기록합니다. 수신 대기 소켓은 해당 패키지 구성요소의 `koda:runtime:listening`(소켓마다 하나)과 가장 넓은 범위인 `koda:runtime:bind-scope`로 기록하며, SPDX에서는 같은 이름으로 패키지 `annotations`에 기록합니다. Tracker에서 `koda:runtime:bind-scope = all-interfaces`인 구성요소의 취약점을 먼저 검토할 수 있습니다. `assets.json`에는 장비 증적, `context.json`에는 실행·설정 관측, `collection.json`에는 미확인 사유와 수집 범위가 있습니다. `inventory.syft.json`은 패키지 인벤토리입니다. `SHA256SUMS`로 결과를 검증할 수 있습니다.

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

## 암호 자산과 TLS 세션 증적

호스트·디렉터리·컨테이너에서 확인한 X.509 인증서와 공개키, 알고리즘을 CycloneDX `cryptographic-asset`으로 기록합니다. 발급자 후보가 있으면 서명을 확인해 관계를 기록합니다. Nginx·Apache·sshd에서 읽은 허용 지시문은 설정 증거로 표시합니다. JKS v1/v2에서는 공개 인증서 체인과 엔트리 별칭의 SHA-256을 기록하며 암호화된 키 내용을 건너뜁니다. 비밀번호 없이 읽은 JKS의 저장소 무결성은 미검증으로 표시합니다.

보호된 PKCS#12·HSM·KMS는 관리자가 공개 가능한 메타데이터를 공통 장비 증적에 기록해 `--asset-evidence`로 반입합니다. 예를 들어 `cryptographic-asset`에 `cryptoProperties.assetType=related-crypto-material`과 `relatedCryptoMaterialProperties`의 키 종류·크기·상태·`algorithmRef`를 지정하고, `properties.storageType`과 `keyAlias`에 저장 방식과 별칭을 둡니다. 소비 애플리케이션의 `dependsOn`은 같은 파일 안의 키 메타데이터 ID를 가리킵니다.

다음은 별도 계측에서 관측한 TLS 협상을 반입하는 형식의 예시입니다. 지문과 주소, 시각은 해당 관측값으로 채웁니다. 같은 증적에 있는 인증서의 SHA-256과 세션에서 제시한 지문이 일치하면 서비스→프로토콜→인증서 관계를 출력합니다.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## 오프라인 권고 대조

같은 바이너리의 `assess`에 SBOM과 확보한 권고 파일을 지정합니다. 새 권고 파일이 도착하면 기존 결과를 다시 대조할 수 있습니다.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`, `--context`, `--kev`는 선택입니다. 컨텍스트를 사용하면 같은 수집 디렉터리의 `SHA256SUMS`에서 SBOM과 컨텍스트를 검증합니다. KEV는 결과 우선순위에 사용할 정보를 표시합니다. 평가는 실행 시 제공한 권고와 수집 당시 증적을 기준으로 합니다.

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

Linux 배포판 패키지는 릴리스가 포함된 distro 식별자와 정확한 버전을 사용합니다. SBOM의 버전 필드와 PURL 버전 정보가 충돌하면 `review_required`를 기록합니다. RPM의 별도 epoch 표기는 이를 반영해 비교합니다. 한 번의 대조에 정확 버전 항목은 최대 100만 개를 사용하며, 상한을 초과하면 처리를 중단하고 이유를 반환합니다. 명시 규칙의 지원 종료는 `supportEndsAt`에 날짜를 기록하며, 버전 비교는 지원되는 소프트웨어 생태계에 한해 `affectedSemver`를 사용할 수 있습니다. 교체 파일이나 저장 상태가 확인되면 활성화 검토 상태로 나타납니다. 권고에 없는 버전이나 미확인 장비는 검토 대상으로 봅니다.

Linux 물리 서버와 Windows 운영 장비에서는 장비 권고 및 각 제조사 인벤토리를 대조해 범위를 확인해야 합니다. macOS·Windows 네이티브 기능은 OS·하드웨어와 설치 앱 중심이며, 장치가 보고하지 않는 버전이나 앱 내부 의존성은 추가 증적이 필요합니다.

결과의 `risks` 배열에는 수집기가 BOM에 기록한 위험 항목이 출처 `KODA collection evidence`로 나옵니다. 권고 파일이 필요 없고, 권고 대조 결과인 `findings`와 따로 기록합니다. `sbom.cdx.json`과 `sbom.spdx.json`에는 암호 위험이 있고, 병합본 `bom.cdx.json`에는 AI-BOM과 OBOM 위험이 더 들어 있습니다. `bom.cdx.json`에서는 호스트 패키지를 다시 가리키는 OBOM 노드를 권고 대조에서 빼고, 실행 중인 컨테이너의 패키지는 해당 OBOM 노드로 대조하지만, 프로세스가 사용하는 패키지만 포함됩니다. 컨테이너 전체 인벤토리는 `containers/<name>/sbom.cdx.json`으로 대조하세요. `risk_observed`는 기록된 증적이 그 상태를 보여 준다는 뜻이고, `review_required`는 그 상태를 배제하지 못했다는 뜻입니다.

| 결과 ID | 상태 | 기록된 증적 |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | 2048비트 미만 RSA 또는 DSA를 쓰는 인증서나 SSH 호스트 키 |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | MD5 또는 SHA-1로 서명한 인증서(수집기가 자체 서명으로 확인한 인증서 제외) |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | TLS 1.2 미만 프로토콜을 허용하는 설정 또는 LEGACY 시스템 암호 정책 |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | 모델 파일이나 모델 디렉터리 체크포인트의 pickle이 코드를 실행할 수 있는 호출 대상을 가져옴 |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | pickle이 허용 목록 밖의 모듈을 가져오거나 검사가 끝나지 않음 |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | 선언된 방화벽 규칙이 허용하는 호스트의 loopback 밖 수신 소켓. 출발지가 제한된 규칙, 평가하지 못한 규칙, 활성 방화벽 선언이 없는 경우(`none-observed`)는 검토 필요 |

## NIS-SBOM 표

`nis-sbom`은 수집한 CycloneDX SBOM을 NIS-SBOM 1.0 기본항목 20개(「SW 공급망 보안 가이드라인 1.0」 표 35)로 변환합니다. 가이드라인은 항목과 표 형태만 정하고 파일 스키마는 정하지 않으므로, 결과는 소프트웨어 컴포넌트마다 한 행인 UTF-8 CSV입니다. 소프트웨어 컴포넌트만 적습니다. 하드웨어, 파일, 암호 자산은 제외합니다.

```sh
./koda-bom nis-sbom \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --organization EXAMPLE \
  --output ./nis-sbom.csv
```

`--organization`과 `--sequence`(기본값 1)로 SBOM ID `EXAMPLE-YYYYMMDD-000001`을 만듭니다. `--product`, `--product-version`, `--author`는 스캔 대상 이름과 수집기 이름을 대신합니다. 공급자는 SBOM에 기록된 값을 쓰고, 없으면 PURL 네임스페이스를 씁니다. 해시는 SHA-256 이상만 적습니다. `SBOM Type`은 SBOM에 기록된 수명주기 단계를 따르고, 기록이 없으면 `Deployed`입니다. `SPDX Doc. ID`와 `Component Alias`는 비워 둡니다. 수집기는 취약점을 대조하지 않으므로 `Vul. DB`와 `Vul. Info`도 비워 둡니다. 스프레드시트가 수식으로 실행할 수 있는 값은 앞에 `'`를 붙입니다.

## TCP 접속 관측

`--network-evidence`는 관리자가 이미 측정한 TCP 연결 결과를 현재 호스트 또는 보관본의 OBOM 소켓과 대조합니다. `hostField`에는 `machineIdSha256`, `productUuidSha256` 또는 명시적으로 부여한 `assetTag`를 사용합니다. `scope`는 `host` 또는 전체 64자리 컨테이너 ID입니다. 다음 예시는 지점 한 곳에서 확인한 한 차례의 연결입니다.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

지원하는 결과는 `connected`, `refused`, `timed-out`입니다. 같은 바인딩에 여러 프로세스가 있거나 해당 소켓을 찾지 못하면 어느 서비스에도 귀속하지 않고 미연결 수를 기록합니다. 방화벽·NAT 정책, 다른 지점의 접근성, 이후 시각의 상태는 각각의 관측을 추가해야 합니다. 수집기 자체가 접속 시험을 수행하지 않습니다.
