# 수집 범위와 확인 한계

이 목록은 식별 가능한 자료 종류를 설명합니다. 모든 버전의 모든 제품에 대한 완전 수집이나 취약점 판정을 보장하는 목록이 아닙니다. 실행 결과 `collection.json`의 상태와 근거를 함께 확인하세요.

| 계층 | 주요 증거 | 확인 한계 |
|---|---|---|
| OS | os-release, vendor release, RPM/DEB/APK 패키지 DB | 읽기 권한·DB 손상·source package/module stream 누락 가능 |
| 하드웨어·펌웨어 | Linux CPU·마이크로코드, DMI/BIOS, UEFI·ESRT, PCI/드라이버, NVMe/SCSI, USB, TPM에서 노출되는 식별 정보 | 모델과 구성에 따라 필드가 다릅니다. VM과 컨테이너 관측에는 물리 호스트 확인이 필요할 수 있습니다. |
| 외부 장비 | 로컬 파일로 내보낸 Redfish·fwupd·devlink 또는 공통 JSON | 장비가 보고한 버전과 상태를 보존합니다. 매칭되지 않은 장비와 미확인 필드는 수집 범위를 함께 확인합니다. |
| Windows·macOS | `platform-inventory`의 시스템·OS·펌웨어 및 설치 앱 메타데이터 | Windows는 교차 빌드 확인 범위입니다. 개별 앱 내부 의존성과 제공자별 업데이트는 추가 증적이 필요합니다. |
| 실행 중 소프트웨어 | 실행 파일 및 메모리 매핑의 경로·파일 식별 정보, 경로를 식별한 설치 패키지 | 프로세스와 수집기의 파일시스템 범위가 같은 경우에만 설치 패키지를 연결합니다. 교체가 확인되면 재시작 검토 근거를 남깁니다. |
| 호스트 식별 | machine-id, DMI product UUID·제품/보드 시리얼의 SHA-256, 운영자 `--asset-tag` | 호스트 `/` 수집만 해당. DMI 시리얼은 root 권한 필요. 공용 기본값은 기록하지 않음. 해시는 가명화이며 익명화가 아님 |
| 수신 대기 소켓 | 수집기 네트워크 네임스페이스의 `/proc/<pid>/net` LISTEN TCP·바인딩 UDP와 `/proc/<pid>/fd` 소유 프로세스 | 바인딩 주소만 확인하며 방화벽 노출은 확인하지 않음. 다른 네임스페이스의 소켓 미관측. 소유자 미확인 소켓은 `unattributedSockets` |
| 커널 | 현재 uname, 설치 커널 이미지·모듈, vermagic, RPM 버전 | 설치된 옛 커널과 실제 부팅 커널 구분. 모듈 미관측은 내장 기능 부재를 뜻하지 않음 |
| 라이브패치 | Linux livepatch sysfs, Oracle raw Ksplice stage, 선택 실행 helper의 Ksplice·Uptrack·Canonical 상태 보고 | 관측과 클라이언트 보고 구분. 부팅·커널·시간이 다른 증거는 적용 상태로 사용하지 않음. CVE 취약성 자동판정 없음 |
| Java | JDK/JRE release, JAR/WAR/EAR manifest·Maven 메타데이터 | 식별정보 제거·수정된 shaded archive는 부분 식별 가능 |
| PHP | PHP 패키지/인터프리터 증거, Composer installed.json, PEAR | Composer lock에만 적힌 미설치 패키지 제외. PHP 설정에 따른 악용 가능성은 별개 |
| Python | site-packages의 dist-info/egg-info, venv, `.pyz`·`.pex`의 실제 번들 메타데이터 | 메타데이터가 제거되거나 사용자 경로 접근 불가 시 누락 |
| Node.js와 정적 JavaScript | node_modules와 런타임 증거, 파일 시스템 및 EAR/WAR/ZIP·JAR 웹 리소스의 jQuery·jQuery UI·Fancytree 식별 근거 | 파일명만으로 패키지·버전을 확정하지 않음. 지원하는 라이브러리, 아카이브 구조와 검사 한도 밖의 구성은 부분 확인 |
| Go·Rust 바이너리 | Go 빌드 정보, ELF에 기록된 Rust 런타임 의존성(`cargo-auditable`) | 내장 정보가 없는 바이너리는 의존성 미확인. 손상되거나 검사 한도를 초과한 정보는 부분 수집으로 표시 |
| .NET | 게시된 `.deps.json`과 관리형 DLL, 단독 관리형 DLL의 버전 리소스 | DLL 단독 관측에는 NuGet PURL을 발급하지 않으며, 단일 실행 파일 배포의 내장 의존성은 별도 검증 필요 |
| Ruby | 설치 `specifications`와 실제 gem 파일, 기본 제공 gem의 `specifications/default` | `Gemfile.lock`만 있는 소스 트리와 표준 설치 메타데이터가 제거된 gem은 식별 근거 부족 |
| 네이티브 서버 | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB의 패키지·바이너리 증거 | 커스텀·strip 바이너리, 정적 포함 사본은 unknown 가능 |
| Tomcat | ServerInfo.properties, manifest, catalina.jar | 버전 은닉·상충 정보는 확인 불가로 남김 |
| WebLogic/JBoss/WildFly | 제품 manifest·설치 inventory·patch 메타데이터 | `.patch_storage` 존재만으로 현재 적용 패치로 판정하지 않음 |
| JEUS 등 상용 제품 | 확인 가능한 제품 descriptor, 일반 내부 JAR | 실제 제품 fixture로 검증되지 않은 버전·패치 식별은 미검증/미지원으로 표시 |
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
