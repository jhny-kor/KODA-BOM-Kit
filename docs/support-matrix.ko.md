# 수집 범위와 확인 한계

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="support-matrix.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


이 목록은 식별 가능한 자료 종류를 설명합니다. 모든 버전의 모든 제품에 대한 완전 수집이나 취약점 판정을 보장하는 목록이 아닙니다. 실행 결과 `collection.json`의 상태와 근거를 함께 확인하세요.

## CycloneDX 7종과 Linux 수집 범위

호스트 `/`를 기본 옵션으로 수집하면 `boms/` 아래에 `sbom.cdx.json`, `hbom.cdx.json`, `cbom.cdx.json`, `obom.cdx.json`, `saasbom.cdx.json`, `aibom.cdx.json`, `mbom.cdx.json`을 만들고 `bom.cdx.json`으로 병합합니다. 호환용 루트 `sbom.cdx.json`에는 소프트웨어·장비·암호 자산을 함께 기록합니다. 증적이 없는 도메인은 `no-evidence`와 `unknown` 범위로 표시합니다. `--cyclonedx-17`을 추가하면 각 문서의 1.7 출력도 생성합니다. 아래 표의 보강 자료는 Linux에서 관측할 수 있는 범위를 더 넓히려는 경우에 해당합니다. [CycloneDX 공식 분류](https://github.com/CycloneDX/specification#readme)

| 종류 | 현재 Linux 수집과 출력 | 범위를 넓히는 데 필요한 자료 |
|---|---|---|
| SBOM · 소프트웨어 | OS·언어 패키지, 버전·PURL, 수집 가능한 라이선스·의존관계, JAR·내장 모듈, 컨테이너별 인벤토리 | 최종 파일에서 식별하기 어려운 정적 링크·빌드 전용 의존성은 공급사 또는 CI의 CycloneDX/SPDX와 대상 산출물 SHA-256을 대조해 `build-sbom.cdx.json`으로 보강 |
| HBOM · 하드웨어 | 커널이 보고하는 CPU·보드·장치·드라이버·펌웨어, SMBIOS 메모리 모듈(제조사·부품번호·속도)·전원공급장치·슬롯, EDAC DIMM과 전원·팬 센서 | 호스트에서 보이지 않는 물리 부품·부품번호·공급사·수명주기는 Redfish 등 장비 관리자 내보내기나 자산대장 필요 |
| CBOM · 암호 자산 | 공개 인증서·공개키·알고리즘·확인된 발급 관계, 지원하는 TLS/SSH 설정의 사용처, SSH 호스트 공개키, 시스템 암호 정책과 OpenSSL 프로토콜·암호군·그룹 선언, JKS 공개 인증서와 엔트리 메타데이터 | 실제 협상된 TLS 버전·암호군은 관측 기록, HSM/KMS·보호된 키 저장소는 관리자가 내보낸 공개 메타데이터 필요 |
| OBOM · 운영 구성 | 호스트·컨테이너·프로세스·실행 파일·소유 패키지·수신 소켓, 프로세스별 외부 TCP 연결 대상, systemd 서비스·타이머, cron 작업, 방화벽 설정 선언. 패키지를 확인할 수 있는 포트만 소유 패키지에 연결 | 전체 Pod·워크로드·Service·Ingress 관계는 같은 클러스터의 Kubernetes JSON 내보내기, 배포 식별은 운영 측 라벨 필요. 접속 여부는 호스트 식별자가 일치하는 지점별 TCP 접속 관측을 `--network-evidence`로 반입 |
| SaaSBOM · 서비스 | 서비스 명세나 OpenAPI JSON·YAML, nginx·Apache·HAProxy 설정에 선언된 백엔드에서 서비스·엔드포인트를 `saasbom.cdx.json`으로 출력. 운영 측 로컬 소켓은 별도 OBOM에서 조회 | 서비스 카탈로그·API 명세, 제공자·외부 서비스 의존성, 인증·신뢰 경계, 데이터 흐름의 방향·분류 필요 |
| AI-BOM · 모델·데이터 | 승인된 로컬 경로에서 모델 설정, 양자화·컨텍스트, 가중치 인덱스, GGUF·safetensors·ONNX 헤더·크기, PyTorch pickle import 안전성, Hugging Face 모델 카드·캐시 ref, Ollama 모델 레이어, 모델 서버가 시작 시 지정한 모델을 관측. 명시한 산출물의 전체 SHA-256 및 일치하는 선언의 모델·데이터 계보를 `aibom.cdx.json`으로 출력. 프레임워크 패키지는 SBOM에서도 조회 | 가중치·모델 식별자·리비전·해시, 기반 모델과 파생 관계, 모델 카드·라이선스, 학습·평가 데이터 출처 필요 |
| MBOM · 제조·빌드 공정 | 산출물과 SHA-256이 일치하는 SLSA 빌드 기록 또는 제공된 물리 조립·검사 단계를 CycloneDX `formulation`으로 변환해 `mbom.cdx.json`에 기록 | 소프트웨어는 CI 작업 단계·도구·입출력·빌드 실행 기록, 하드웨어는 제조사의 조립·공정·검사 이력 필요 |

## 계층별 수집 근거

| 계층 | 주요 증거 | 확인 한계 |
|---|---|---|
| OS | os-release, vendor release, RPM/DEB/APK 패키지 DB | 읽기 권한·DB 손상·source package/module stream 누락 가능 |
| 하드웨어·펌웨어 | Linux CPU·마이크로코드(x86 CPUID 시그니처, 소켓·코어, ARM 코어 이름), DMI/BIOS, UEFI·ESRT, PCI/드라이버, NVMe/SCSI, USB, TPM에서 노출되는 식별 정보. RAID/HBA(mpt3sas, qla2xxx, lpfc, hpsa, smartpqi), RDMA(InfiniBand·Mellanox), GPU VBIOS(NVIDIA, amdgpu), NIC 펌웨어(`ethtool -i`와 같은 읽기 전용 ioctl) | 모델과 구성에 따라 필드가 다릅니다. megaraid_sas는 sysfs에 펌웨어 버전이 없어 내보낸 증적이 필요합니다. BMC는 `/dev/ipmi0`의 IPMI `Get Device ID`로 읽으며 root와 IPMI 커널 모듈이 필요하고, 리비전 표기는 제조사 공개 버전과 다를 수 있습니다. NIC 펌웨어는 드라이버가 보고하는 값입니다. VM과 컨테이너 관측에는 물리 호스트 확인이 필요할 수 있습니다. |
| 외부 장비 | 로컬 파일로 내보낸 Redfish·fwupd·devlink 또는 공통 JSON | 장비가 보고한 버전과 상태를 보존합니다. 매칭되지 않은 장비와 미확인 필드는 수집 범위를 함께 확인합니다. |
| Windows·macOS | `platform-inventory`의 시스템·OS·펌웨어 및 설치 앱 메타데이터 | Windows는 교차 빌드 확인 범위입니다. 개별 앱 내부 의존성과 제공자별 업데이트는 추가 증적이 필요합니다. |
| 실행 중 소프트웨어 | 실행 파일 및 메모리 매핑의 경로·파일 식별 정보, 경로를 식별한 설치 패키지 | 프로세스와 수집기의 파일시스템 범위가 같은 경우에만 설치 패키지를 연결합니다. 교체가 확인되면 재시작 검토 근거를 남깁니다. |
| 호스트 식별 | machine-id, DMI product UUID·제품/보드 시리얼의 SHA-256, 운영자 `--asset-tag` | 호스트 `/` 수집만 해당. DMI 시리얼은 root 권한 필요. 공용 기본값은 기록하지 않음. 해시는 가명화이며 익명화가 아님 |
| 수신 대기 소켓 | 수집기 네트워크 네임스페이스의 `/proc/<pid>/net` LISTEN TCP·바인딩 UDP와 `/proc/<pid>/fd` 소유 프로세스 | 바인딩 주소만 확인하며 방화벽 노출은 확인하지 않음. 다른 네임스페이스의 소켓 미관측. 소유자 미확인 소켓은 `unattributedSockets` |
| 외부 연결 | 로컬 포트가 수신 포트가 아닌 ESTABLISHED TCP를 프로세스·원격 주소별로 집계. 최대 16,384개 | 고정 로컬 포트에서 상대의 임시 포트로 가는 연결은 수락된 연결로 봄. 수집 시점에 열려 있던 연결만 보임. 호스트 프로세스만 대상. 이 호스트가 수신 중인 포트로 가는 연결은 해당 수신 소켓과 소유 프로세스에 연결함 |
| 예약 작업 | `/etc/crontab`, `/etc/cron.d`, 사용자 crontab, `cron.{hourly,daily,weekly,monthly}` 스크립트, 활성화된 systemd 타이머의 `On*` 일정 | 실행 파일의 절대 경로만 기록하고 인자는 버림 |
| 방화벽 | iptables-save 파일(RHEL·Debian·ufw), firewalld 기본 zone과 서비스 정의, nftables input hook 체인과 리터럴 include | 파일에 선언된 내용이며 커널에 적재된 규칙은 읽지 않음. policy가 없는 base chain은 허용으로 보고, `ENABLED=no`인 ufw는 `disabled`로 기록. loopback 전용·연결 상태·부정 규칙은 열린 포트로 보지 않고, 프로토콜 전체 TCP/UDP 허용은 그 프로토콜의 모든 포트를 연 것으로 봄. 호스트 네트워크 네임스페이스의 loopback이 아닌 수신 소켓에 `firewall-declared`를 `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined`, 활성 선언을 읽지 못한 경우 `none-observed` 중 하나로 표시. 컨테이너 소켓은 자체 네트워크 네임스페이스에 있어 표시하지 않음. 컨테이너가 NAT로 게시한 포트는 FORWARD 규칙을 거치므로 평가하지 않음 |
| 보안 설정·재부팅 | SELinux 실행·설정 모드, AppArmor 활성화·프로필 모드 수, lockdown, FIPS, 허용 목록의 부팅 옵션, 커널 빌드 설정(`y`·`m` 옵션), `/run/reboot-required`, 실행 커널 모듈 트리 존재, 같은 계열의 더 새 설치 커널 | 관측값이며 준수 판정이 아닙니다. 재부팅 신호가 없다는 것은 재부팅 불필요의 증명이 아닙니다. 커널 계열 구분은 릴리스 문자열 기반 추정입니다. |
| SSH 서버 설정 | `sshd_config`·`sshd_config.d/*.conf`의 전역 구역 선언값 | 파일별 선언 관측이며 `Include` 순서에 따른 실제 적용값을 계산하지 않음. `Match` 구역 제외 |
| 커널 taint·모듈 | `kernel.tainted`, `/proc/modules`의 taint 플래그와 `/sys/module/<이름>/version`·`srcversion` | 모듈이 버전을 제공하지 않으면 이름과 플래그만 기록 |
| 식별되지 않은 실행 파일 | 수집기와 같은 root의 프로세스 중 패키지 소유·구성요소 위치·제품 설치 경로 어디에도 해당하지 않는 실행 파일 | 다른 mount namespace(컨테이너)의 프로세스는 제외. 목록에 있다는 것이 악성이라는 뜻은 아님 |
| 패키지 출처 | apt `Packages` 목록(평문·gz·lz4), dnf 이력 DB, yum `yumdb` | apt는 이름 기준이며 목록이 삭제됐으면 분류하지 않음. dnf5·apk는 미지원. 저장소 주소·파일 경로 미기록 |
| 부팅 시작 서비스 | systemd `*.wants`·`*.requires` 링크(서비스·소켓·타이머), 단위 파일·drop-in, cgroup v2·v1 실행 여부 | 첫 `ExecStart`만 사용. 상대 경로 실행 파일은 패키지와 연결하지 않음. 다른 slice의 서비스는 `stopped`로 보일 수 있음. SysV init 스크립트 미지원 |
| 하드웨어 CPE | Intel Xeon·Core, AMD EPYC·Ryzen, Dell PowerEdge(장치·BIOS), Lenovo ThinkSystem(장치) | NVD 사전 명명을 따른 형식. 사전에 없는 모델은 일치하지 않을 수 있음. HPE·BMC는 미생성 |
| 패키지 파일 무결성 | RPM·dpkg·apk DB에 해시가 있는 실행 파일·공유 라이브러리와 실제 파일의 비교 | 설정·ghost 파일 제외. 해시 예산(호스트 8 GiB, 컨테이너 1 GiB) 초과 시 부분 확인. prelink 바이너리는 오탐 가능. 불일치 원인은 별도 판단 |
| 인증서·CBOM | 수집 범위의 PEM·DER X.509 인증서, SSH 호스트 공개키, 서명·공개키 알고리즘. `crypto-policies`와 `openssl.cnf`의 MinProtocol·CipherString·Ciphersuites·Groups 선언 | 주체·발급자 이름 미기록. JKS v1/v2의 공개 인증서와 엔트리 메타데이터를 읽고 별칭은 SHA-256으로 기록합니다. 암호화된 키 내용은 건너뛰며 저장소 무결성은 미검증으로 표시합니다. 개인키·PKCS#12 내용은 수집하지 않음. 배포판 신뢰 저장소와 20개 초과 번들 제외 |
| 커널 | 현재 uname, 설치 커널 이미지·모듈, vermagic, RPM 버전 | 설치된 옛 커널과 실제 부팅 커널 구분. 모듈 미관측은 내장 기능 부재를 뜻하지 않음 |
| 라이브패치 | Linux livepatch sysfs, Oracle raw Ksplice stage, 선택 실행 helper의 Ksplice·Uptrack·Canonical 상태 보고 | 관측과 클라이언트 보고 구분. 부팅·커널·시간이 다른 증거는 적용 상태로 사용하지 않음. CVE 취약성 자동판정 없음 |
| Java | JDK/JRE release, JAR/WAR/EAR manifest·Maven 메타데이터 | 식별정보 제거·수정된 shaded archive는 부분 식별 가능 |
| PHP | PHP 패키지/인터프리터 증거, Composer installed.json, PEAR | Composer lock에만 적힌 미설치 패키지 제외. PHP 설정에 따른 악용 가능성은 별개 |
| snap·flatpak·conda | snap의 `current` 리비전 `meta/snap.yaml`과 내부 Debian 패키지, flatpak의 `active` 배포와 AppStream 릴리스, `conda-meta/*.json` | snap·flatpak은 공식 PURL 형식이 없어 `pkg:generic/snap`, `pkg:generic/flatpak`을 사용합니다. AppStream 정보가 없는 flatpak은 버전 없이 기록합니다. conda 채널은 이름만 남기고 URL은 남기지 않습니다. |
| Python | site-packages의 dist-info/egg-info, venv, `.pyz`·`.pex`의 실제 번들 메타데이터 | 메타데이터가 제거되거나 사용자 경로 접근 불가 시 누락 |
| Node.js와 정적 JavaScript | node_modules와 런타임 증거, 파일 시스템 및 EAR/WAR/ZIP·JAR 웹 리소스의 jQuery·jQuery UI·Fancytree 식별 근거 | 파일명만으로 패키지·버전을 확정하지 않음. 지원하는 라이브러리, 아카이브 구조와 검사 한도 밖의 구성은 부분 확인 |
| Go·Rust 바이너리 | Go 빌드 정보, ELF에 기록된 Rust 런타임 의존성(`cargo-auditable`) | 내장 정보가 없는 바이너리는 의존성 미확인. 손상되거나 검사 한도를 초과한 정보는 부분 수집으로 표시 |
| .NET | 게시된 `.deps.json`과 관리형 DLL, 단독 관리형 DLL의 버전 리소스 | DLL 단독 관측에는 NuGet PURL을 발급하지 않으며, 단일 실행 파일 배포의 내장 의존성은 별도 검증 필요 |
| Ruby | 설치 `specifications`와 실제 gem 파일, 기본 제공 gem의 `specifications/default` | `Gemfile.lock`만 있는 소스 트리와 표준 설치 메타데이터가 제거된 gem은 식별 근거 부족 |
| 네이티브 서버 | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB의 패키지·바이너리 증거 | 커스텀·strip 바이너리, 정적 포함 사본은 unknown 가능 |
| Tomcat | ServerInfo.properties, manifest, catalina.jar | 버전 은닉·상충 정보는 확인 불가로 남김 |
| WebLogic/JBoss/WildFly | 제품 manifest·설치 inventory·patch 메타데이터 | `.patch_storage` 존재만으로 현재 적용 패치로 판정하지 않음 |
| JEUS 등 상용 제품 | 확인 가능한 제품 descriptor, 일반 내부 JAR | 실제 제품 fixture로 검증되지 않은 버전·패치 식별은 미검증/미지원으로 표시 |
| 중지된 컨테이너·로컬 이미지 | Docker overlay2·containerd 이미지 저장소, containerd overlayfs 스냅샷(Kubernetes·nerdctl·k3s·RKE2), rootful Podman·CRI-O containers-storage overlay | 계층을 결과 폴더에 복사해 합친 뒤 수집하고 삭제. root filesystem당 16 GiB와 디스크 여유 공간 확인. 다른 저장 드라이버·rootless Podman 미지원. 수신 소켓 없음 |
| 실행 중인 컨테이너 | 호스트 `/` 수집에서 procfs로 찾은 컨테이너별 root filesystem. Docker·containerd(Kubernetes·nerdctl)·Podman·CRI-O 상태 파일의 이름·이미지 | 컨테이너마다 `containers/<이름>/`에 별도 SBOM을 만듭니다. 볼륨·bind mount는 포함하지 않습니다. 호스트 mount namespace에서 root filesystem이 보이지 않으면 사유만 남깁니다. Kubernetes pod sandbox는 제외합니다. 런타임 API·소켓에 연결하지 않습니다. 컨테이너 네트워크 네임스페이스의 수신 소켓은 해당 컨테이너 프로세스가 연 것만 연결합니다. |
| 이미지 archive | 명시적으로 지정한 Linux amd64 Docker/OCI tar와 해시, 지원되는 OCI manifest 다이제스트 | 이미지에 포함된 파일이 수집 범위입니다. 실행 컨테이너·호스트 커널은 별도 관측값입니다. |
| IBM AIX와 Oracle | `aix-import`의 fileset, 임시 패치, Oracle Home별 OPatch 및 선택 SQL 패치 이력 | 한 AIX 서버에서 최대 8개 Home의 조회 증적을 수집해 가져옴. 실행 상태는 별도 증적 필요 |

수동 설치본은 디렉터리·설치 인스턴스별로 남깁니다. 동일 이름·버전이어도 설치 위치나 패치 상태가 다르면 무조건 합치지 않습니다. CPE가 확정되지 않으면 임의로 만들지 않습니다. 확정된 패키지 식별정보와 증거만 후속 점검에 사용하세요.

기본 출력은 CycloneDX 1.6과 SPDX 2.3입니다. `--cyclonedx-17`로 같은 인벤토리의 CycloneDX 1.7 파일을 추가할 수 있습니다. 선택 명령 `assess`의 입력 규칙, 지원하는 OSV·CSAF 범위와 해석 방법은 [단일 파일 CLI 안내](asset-inventory.ko.md)에 있습니다.

## 최근 CVE를 바탕으로 요구한 근거

아래 CVE 번호는 검사 규칙이나 취약 판정 결과가 아닙니다. 어떤 식별 근거를 보존해야 하는지 확인하는 회귀 시나리오입니다.

- PHP CVE-2026-109618/109619: PHP-FPM/mod_php/CGI 자체와 Composer 라이브러리를 구분.
- Node.js CVE-2026-111497: node_modules 외 Node 런타임·확인 가능한 내장 라이브러리.
- Java CVE-2026-87294: 공급자·full build/update 식별. WebLogic CVE-2026-91502: 설치 홈과 패치 inventory.
- Tomcat CVE-2026-103119/101356: 수동 설치 제품과 JAR, AJP/HTTP2 선언 근거.
- Apache CVE-2026-57941: httpd와 mod_http2, 배포판 전체 패키지 릴리스.
- nginx CVE-2026-15176: 제품·설치 출처와 alias/rewrite 선언 존재 여부.
- OpenSSL CVE-2026-35189: CLI 외 libssl/libcrypto 및 별도 설치 사본.
- kernel CVE-2026-80844 등: 현재 실행 커널과 설치된 각 커널, UEK/RHCK·배포판 패치 식별.

공식 참고 자료: [PHP](https://www.php.net/archive/2026.php), [Node.js](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), [Oracle CPU](https://www.oracle.com/security-alerts/cpuoct2026.html), [Tomcat](https://tomcat.apache.org/security-11.html), [Apache](https://httpd.apache.org/security/vulnerabilities_24.html), [nginx](https://nginx.org/en/security_advisories.html), [OpenSSL](https://www.openssl-library.org/news/vulnerabilities/), [Red Hat](https://access.redhat.com/security/vulnerabilities/RHSB-2026-011).
