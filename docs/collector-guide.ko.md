# KODA BOM Kit 수집 명령과 출력 파일

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="collector-guide.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

처음 실행할 때는 [폐쇄망 반입 및 결과 확인](air-gapped.ko.md)을 참고하세요. 아래 예시는 실행 파일 또는 소스 트리를 기준으로 합니다.

## 특정 디렉터리 하위만 수집

압축을 푼 폴더에서 다음을 실행합니다. 디렉터리와 그 하위의 읽을 수 있는 설치 메타데이터·라이브러리를 수집합니다.

```bash
sudo ./scan-directory.sh /opt/application /var/tmp/koda-sbom-results --max-files 0 --timeout 0

# 공백이 있는 경로는 따옴표로 감쌉니다.
sudo ./scan-directory.sh "/data/My Application" "/var/tmp/application results" --max-files 0 --timeout 0
```

첫 번째 인수는 수집할 디렉터리, 두 번째 인수는 결과를 저장할 부모 폴더입니다. 두 번째 인수를 생략하면 현재 작업 폴더의 `sbom-output`을 사용합니다. 매번 새 결과 하위 폴더를 만들고 마지막 줄에 그 경로를 표시합니다. `sbom.cdx.json`과 `sbom.spdx.json`이 표준 SBOM이며 `collection.json`에서 수집 상태와 누락 사유를 확인합니다.

이 스크립트는 `scan --target <디렉터리> --no-context`를 실행합니다. 서버 전체의 RPM/DEB 목록·실행 커널·프로세스·Ksplice/Livepatch 상태를 함께 수집하지 않습니다. 지정 디렉터리 밖으로 향하는 심볼릭 링크도 따라가지 않습니다. 시스템 전역에 설치된 런타임이나 라이브러리가 그 디렉터리 밖에 있으면 이 결과에 포함되지 않습니다. 설치되지 않은 의존성 선언이나 메타데이터가 없는 파일을 완전한 구성요소 목록으로 추정하지 않습니다.

디렉터리 전용 스크립트는 `/`를 거부합니다. 호스트 전체와 라이브패치 상태가 필요하면 아래 호스트 명령을 선택합니다. 수집 옵션을 생략하면 파일 1,000,000개·30분 기본 상한을 사용하며, 위 명령의 `0`은 각 상한 해제입니다.

특정 폴더 전체를 제외하려면 `--exclude-dir`를 반복해서 지정합니다. 상대 경로는
수집 대상 폴더 기준입니다. 수집 대상 아래의 절대 경로도 지정할 수 있습니다.

```bash
sudo ./scan-directory.sh /opt/application /var/tmp/koda-sbom-results \
  --exclude-dir 'logs' \
  --exclude-dir '/opt/application/archive [old]' \
  --exclude '**/*.bak'
```

`--exclude-dir`는 하위 폴더 이름을 그대로 처리하며, 패턴으로 제외할 때는 기존
`--exclude`를 사용합니다. 대상 밖이나 존재하지 않는 폴더, 심볼릭 링크를 지정하면
실행 전에 오류를 표시합니다. 수집 대상 자체의 경로에 glob 특수문자
(`*`, `?`, `[`, `]`, `{`, `}`, 역슬래시)가 있으면 현재 Syft의 경로 처리 한계 때문에
`--exclude-dir` 조합을 거부합니다. 적용한 폴더는 `collection.json`의
`excludedDirectories`에 대상 기준 상대 경로로 기록합니다.

## 여러 디렉터리를 SBOM 하나로 수집

`--target`을 반복해서 지정하면 디렉터리마다 수집한 구성요소를 하나의 결과에 담습니다.

```bash
./koda-bom scan --target '/opt/application' --target '/opt/runtime' \
  --exclude-dir '/opt/application/cache' --exclude-dir '/opt/runtime/logs' \
  --exclude '**/*.bak' --output-dir '/var/tmp/koda-sbom-results'
```

여러 대상을 지정할 때 `--exclude-dir`는 해당 대상 아래의 절대 경로로 지정합니다.
`--exclude` 패턴은 각 디렉터리의 루트를 기준으로 공통 적용합니다. 대상들은 서로
겹치지 않아야 하며 대상 경로에는 glob 특수문자를 사용할 수 없습니다. 파일 수와
시간 제한은 전체 실행에 적용합니다. 실행 커널과
라이브패치 같은 호스트 컨텍스트는 별도의 호스트 수집에서 확인합니다.

`--target` 순서대로 부여한 `target-1`, `target-2`가 SBOM의 발견 경로에 들어갑니다.
버전과 PURL이 같은 구성요소는 하나로 합치고 두 경로를 보존합니다. 설치 경로에 따라
의존 관계가 달라지는 npm 패키지와 pnpm 가상 저장소의 설치본은 개별 ID를 유지합니다.
PURL로 식별하기 어렵거나 버전이 다른 관측도 개별 항목으로 유지합니다.
`collection.json`의 `targets`에서 디렉터리별 수집 상태, 파일 수, 구성요소 수와
제외 경로를 확인합니다. 전체 구성요소 수는 합친 뒤의 수량입니다.
Tracker에는 `sbom.cdx.json` 또는 `sbom.spdx.json` 중 하나를 제출합니다.

## Ksplice·Ubuntu Livepatch 상태

기본 호스트 수집은 `/sys/kernel/livepatch`의 패치별 `enabled`·`transition`과, 존재할 때 Oracle raw Ksplice sysfs의 `stage`를 읽어 `context.json`의 `livepatch`에 기록합니다. 전환 중·비활성·읽기 실패·미관측을 구분합니다. sysfs가 없거나 패치가 관측되지 않았다는 사실은 라이브패치 미설치 또는 특정 CVE 미수정의 증명이 아닙니다. 현대 Ksplice 클라이언트 전체 상태나 패치별 CVE는 sysfs 이름만으로 추정하지 않습니다.

설치된 Ksplice/Canonical 클라이언트의 상세 적용 보고까지 함께 수집하려면 압축을 푼 폴더에서 다음을 실행합니다.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-sbom-results

# 큰 서버에서 SBOM 파일 수·시간 제한을 모두 해제
sudo ./collect-livepatch-status.sh /var/tmp/koda-sbom-results \
  --max-files 0 --timeout 0
```

위 명령은 기본 실행과 제한 해제 실행 중 하나를 선택합니다. helper는 결과 부모 폴더 뒤의 수집 옵션을 `scan`에 전달합니다. `--timeout 0`을 지정해도 helper의 클라이언트 상태 조회 시간 제한은 유지됩니다.

선택 실행 helper가 `canonical-livepatch status --verbose --format json`, `ksplice kernel show`, `uptrack-show`와 `uptrack-uname -r`을 조회합니다. 클라이언트 설치·활성화·새 패치 적용·업데이트는 수행하지 않습니다. 클라이언트가 없거나 조회 실패·시간 초과인 경우 그 사유를 남깁니다. 조회마다 30초(실효 커널 조회 10초), 원문 크기를 제한합니다. 이 helper에는 서버의 기존 클라이언트 및 표준 `sh`, `timeout`, `mktemp` 등이 필요하며 수집기 바이너리는 이 프로그램들에 의존하지 않습니다. 기존 클라이언트/daemon의 통신 동작까지 수집기의 무통신 검증에 포함하지 않습니다.

helper는 원문을 임시 파일로만 취급하고 정제된 증거 JSON을 만든 뒤 원문을 삭제합니다. 증거에는 실행 커널, 부팅 ID의 SHA-256, 캡처 시각 및 보고된 패치 상태를 연결합니다. 이어서 `--livepatch-evidence`로 증거를 가져와 호스트 전체를 수집합니다. 기본 수집기 자체는 외부 명령을 실행하지 않습니다.

정제된 보고서를 수동으로 다시 지정할 수도 있습니다.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-sbom-results \
  --livepatch-evidence /path/to/livepatch-evidence/canonical-livepatch.json
```

이 옵션은 실제 `/` 호스트 수집에서만 사용할 수 있으며 `--no-context`, 이미지 또는 앱 경로 수집과 함께 사용할 수 없습니다. 공급자별 최대 한 보고서, 합계 세 보고서를 허용합니다. 다른 커널·부팅의 보고서, 24시간을 넘은 증거 또는 허용 범위를 넘는 미래 시각은 현재 적용 근거로 사용하지 않습니다. Canonical의 마지막 서버 확인 `Last-Check`와 `CheckState`도 기록하며, 확인 실패·시각 미확인·24시간 초과 캐시는 보수적으로 unknown/stale로 표시합니다. 장기간 폐쇄망에서도 예전 보고 상태를 현재 새로 확인한 CVE 수정으로 승격하지 않습니다. Canonical은 실행 중인 커널의 항목과 실제 적용으로 보고된 수정만 취급합니다. Ksplice 목록의 탐지 기능·단순 CVE 언급을 CVE 수정 완료로 해석하지 않습니다. 클라이언트가 보고한 적용 상태이며 진위가 서명 검증된 증명이나 CVE 취약성 판정은 아닙니다. 실제 구독/패치가 적용된 운영 클라이언트의 검증 여부는 동봉 검증 보고서의 한계를 확인하세요.

## 호스트 운영 명세(OBOM)

호스트 `/`에서 컨텍스트를 켠 기본 `scan`은 소프트웨어·하드웨어·암호 자산을 담은 `sbom.cdx.json`과 실행 관계를 담은 `obom.cdx.json`을 같은 회차에 생성합니다. OBOM의 `metadata.lifecycles`는 `operations`입니다. 컨테이너, 프로세스, 해당 실행 파일과 매핑된 라이브러리의 설치 패키지를 구성요소로, 수신 소켓을 `services`로 기록합니다. 한 포트의 소유자를 확인하려면 그 서비스의 `bom-ref`로 `dependencies`를 따라 프로세스를 찾고, 프로세스의 `koda:obom:executable-package` 또는 근거가 있는 패키지 관계를 확인합니다. 수신 주소는 로컬 바인딩이며 패키지 버전은 설치 DB에서 확인한 버전입니다.

```sh
# 현재 Linux 호스트. 1.7 파일도 함께 생성
sudo ./koda-bom scan --output-dir ./reports --cyclonedx-17

# 이미 수집한 호스트 디렉터리. 원본 밖에 새 결과 폴더 생성
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
```

재생성 시 읽은 `collection.json`, `context.json` 및 사용한 컨테이너 파일은 각 디렉터리의 `SHA256SUMS`와 대조합니다. 이전 버전의 컨테이너 자료에는 포트를 연 실행 파일만 남아 있을 수 있습니다. 이 경우 실행 파일과 소켓에 대응하는 패키지가 하나씩 확인될 때만 연결합니다. 소유자 미확인 포트, 불완전한 관측, 중지된 컨테이너, 부팅 시 시작하도록 설정된 서비스는 상태를 구분합니다. 디렉터리·이미지 스캔, `--no-context`, `--format spdx`에서는 운영 명세를 새로 만들지 않습니다.

운영 환경 라벨은 `--environment prod --deployment-id RELEASE_ID`로 지정합니다. `--kubernetes-evidence FILE`은 같은 클러스터에서 내보낸 Kubernetes JSON 객체 또는 List를 받으며 여러 번 지정할 수 있습니다. Pod 상태의 컨테이너 전체 ID가 로컬 관측과 일치할 때만 연결합니다. 컨트롤러는 소유자 UID, Service는 같은 네임스페이스의 Pod 라벨 선택자, Ingress는 백엔드 Service 이름으로 연결합니다. 이 관계는 내보낸 설정 시점의 배포 구성입니다. 라벨과 Kubernetes 증적은 새 호스트 스캔과 기존 결과의 `obom` 재생성 양쪽에 지정할 수 있습니다.

### 개별 BOM 생성과 재병합

AI-BOM 파일명은 `aibom.cdx.json`이며, CycloneDX 1.7 동시 출력 파일은 `aibom.cdx-1.7.json`입니다. 이전에 생성한 `mlbom.cdx.json` 세트도 원래 파일명과 체크섬 그대로 재병합할 수 있습니다.

기본 호스트 스캔은 일곱 개별 BOM을 `boms/`에 쓰고 같은 회차의 병합본을 상위 폴더에 저장합니다. 디렉터리·이미지 스캔과 `--no-context`에서는 실행 관측이 필요한 OBOM을 생략합니다. `--separate-boms=false`로 자동 분리·병합을 끌 수 있습니다. `--format spdx`는 SPDX 전용 출력입니다.

```sh
sudo ./koda-bom --output-dir ./results --cyclonedx-17
./koda-bom bom-merge --set ./results/<수집폴더>/boms --output-dir ./merged --cyclonedx-17
```

`bom-merge`가 출력한 폴더에 `bom.cdx.json`이 생깁니다. 원래의 구성요소 식별자와 의존 관계를 복원하고, 운영 그래프가 있으면 호스트와 실행 관계도 포함합니다. 다른 폴더나 장비로 옮길 때는 **`bom-set.json`, 관계 파일(`relationships*.jsonl.gz`), `SHA256SUMS`를 포함한 `boms/` 폴더 전체**를 복사합니다. 병합하려는 파일 하나라도 누락되거나 같은 회차의 매니페스트와 해시가 다르면 오류를 반환합니다.

이미 수집한 디렉터리는 원본 밖에 새 세트를 만들 수 있습니다. 예전 호스트 수집본에 OBOM 파일이 없으면 체크섬이 확인된 운영 컨텍스트로 재생성합니다. 1.7 출력에는 원본 인벤토리의 1.7 파일이 필요합니다. 과거 파일에서 하나의 구성요소 ID에 서로 다른 레코드가 있으면 각각 고유 ID를 부여하고 원래 ID와 레코드 해시를 남깁니다. 관계의 대상이 어느 레코드인지 구별할 수 없는 경우 이를 모호한 참조로 표시합니다.

```sh
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set ./separated/<출력된-세트폴더> --output-dir ./merged
```

### 서비스·모델·제조 공정 자료

`domain-bom`은 OpenAPI 또는 서비스 명세, 로컬 모델 파일과 모델 명세, 소프트웨어 빌드 또는 물리 제조 증적을 받아 `saasbom.cdx.json`, `aibom.cdx.json`, `mbom.cdx.json` 중 입력에 해당하는 파일을 생성합니다. 같은 증적 옵션을 `scan`에 주면 해당 수집 폴더에 함께 기록합니다. 명시적으로 지정한 모델·제품 파일과 외부 증적의 범위는 설치 인벤토리와 구분됩니다. [증적 형식과 실행 예시](additional-bom.ko.md)

실제 접속 시험 결과를 호스트 OBOM의 소켓에 표시하려면 `scan` 또는 `obom`에 `--network-evidence FILE`을 지정합니다. 보고서의 호스트 식별자와 소켓의 네임스페이스·바인딩 주소·포트가 한 곳에 대응할 때 관측 지점·대상 주소·시각·결과와 원본 해시를 붙입니다. 모호한 관측은 OBOM 메타데이터의 미연결 건수에서 확인합니다. [접속 관측 형식](asset-inventory.ko.md#tcp-접속-관측)

### 소프트웨어·하드웨어·암호 자산 보강

| 범위 | 수집 방법 |
|---|---|
| 빌드 시점 SBOM | `scan --build-sbom supplier.json --build-artifact /opt/app/product.bin`에 평소의 `--output-dir`를 함께 지정합니다. 대상 산출물은 스캔에 포함된 파일 또는 선택한 이미지 아카이브여야 합니다. 공급사 CycloneDX/SPDX 문서의 대상 SHA-256이 실물과 일치할 때 구성요소와 확인 가능한 의존관계를 `build-sbom.cdx.json`에 기록합니다. 빌드 선언과 현장 설치 목록은 각각 조회할 수 있습니다. |
| 물리 부품 | Linux가 노출한 EDAC DIMM 용량·위치, 식별 가능한 전원공급장치, 팬 속도 센서를 읽습니다. 교체 부품 번호·제조사·부품 계층은 Redfish Memory, PowerSupply, Fan 등 개별 객체나 확장 목록을 `--asset-evidence FILE`로 반입합니다. 센서 채널과 물리 팬의 수량은 별개입니다. |
| 암호 사용처 | 허용된 Nginx·Apache·sshd 설정에서 TLS/SSH 선언을 읽습니다. 확인 가능한 인증서 경로와 서명 검증을 통과한 발급자 인증서를 연결합니다. JKS에서는 공개 인증서·체인과 엔트리 메타데이터를 읽습니다. 실제 협상된 TLS 세션, 보호된 PKCS#12·HSM·KMS의 키 메타데이터는 관리자가 내보낸 증적을 반입합니다. [외부 자산 증적](asset-inventory.ko.md#암호-자산과-tls-세션-증적) |

## 서버 보안 관리 정보

호스트 `/` 수집은 소프트웨어 구성요소 외에 취약점 우선순위와 공격 가능성 판단에 쓰는 정보를 함께 기록합니다. 모두 파일·procfs·sysfs 읽기와 읽기 전용 ioctl로 얻으며 외부 명령을 실행하거나 런타임 API에 연결하지 않습니다. 상세 해석은 [단일 파일 CLI 안내](asset-inventory.ko.md)에 있습니다.

| 항목 | 기록 위치 | 내용 |
|---|---|---|
| 호스트 식별 | `collection.json`의 `host`, SBOM `koda:host:*` | machine-id·DMI UUID·시리얼의 SHA-256, 운영자 라벨 `--asset-tag`. 원문 식별자는 남기지 않음 |
| 수신 대기 포트 | `context.json`의 `processLinks[].listeningSockets`, SBOM `koda:runtime:*` | 포트 → 프로세스 → 패키지. 바인딩 범위(`all-interfaces`·`loopback`·`address`)이며 방화벽 노출 판정은 아님 |
| 실행 중인 컨테이너 | `containers/<이름>/` | 컨테이너마다 별도 SBOM·`collection.json`·체크섬. 컨테이너 네트워크 네임스페이스의 포트 연결 포함. `--no-containers`로 끔 |
| 중지된 컨테이너·로컬 이미지 | `containers/<이름>/`(`state: stopped`), `images/<이름>/` | 디스크에 저장된 이미지 계층과 쓰기 계층을 합쳐 SBOM 생성. Docker(overlay2·containerd 이미지 저장소), containerd(Kubernetes·nerdctl·k3s), Podman·CRI-O. 어느 컨테이너도 쓰지 않는 이미지만 `images/`에 만듦. `--no-images`로 끔 |
| 펌웨어 | `assets.json`, SBOM 장치·펌웨어 구성요소 | RAID/HBA, RDMA, GPU VBIOS, NIC(`ethtool -i`와 같은 ioctl), BMC(IPMI `Get Device ID`) |
| snap·flatpak·conda | SBOM 구성요소 | 활성 snap 리비전·flatpak 배포, conda 패키지 PURL |
| CPU 식별 | `assets.json`의 CPU `properties` | x86 `cpuidSignature`(예: `00050657`)·`familyModelStepping`(예: `06-55-07`)으로 마이크로코드 권고 대조, 소켓·코어 번호, ARM 제조사·코어 이름(`lscpu`와 같은 표) |
| 보안 설정 | `context.json`의 `settings` | SELinux·AppArmor·lockdown·FIPS, 보안 관련 부팅 옵션(`cmdline.*`), `sshd_config` 노출 설정, 재부팅 필요 신호 |
| 커널 빌드 설정 | `context.json`의 `kernelConfig` | 실행 커널에 내장(`y`)·모듈(`m`)로 포함된 `CONFIG_` 옵션. 커널 CVE 해당 여부 판단용 |
| 배포판 밖 커널 모듈 | `context.json`의 `taintedModules` | out-of-tree·서명 없음·독점 모듈과 버전 |
| 식별되지 않은 실행 프로그램 | `context.json`의 `unidentifiedExecutables` | 패키지·수집기·제품 설치 경로 어디에도 속하지 않는 실행 파일 |
| 패키지 파일 무결성 | `collection.json`의 `integrity`, SBOM `koda:integrity:*` | 패키지 DB 해시와 다른 실행 파일·라이브러리(`rpm -V`와 같은 방식) |
| 패키지 출처 | `collection.json`의 `packageOrigin`, SBOM `koda:package:origin`·`koda:package:repository` | 저장소(`repository`)·로컬 파일 설치(`local-file`)·기록 없음(`not-recorded`). apt 목록과 dnf·yum 이력 기준. 저장소 주소와 로컬 파일 경로는 남기지 않음 |
| 부팅 시 시작 서비스 | `context.json`의 `enabledServices`, SBOM `koda:runtime:enabled-service` | 활성화된 systemd 서비스·소켓, 실행 파일과 패키지, 소켓의 Listen 값, 현재 실행 여부. 지금은 멈춰 있어도 재부팅하면 열리는 서비스를 확인 |
| 하드웨어 CPE | `assets.json`, SBOM 장치·펌웨어 `cpe` | Intel Xeon·Core, AMD EPYC·Ryzen CPU, Dell PowerEdge(장치·BIOS 버전), Lenovo ThinkSystem(장치). NVD 사전 명명과 대조한 형식만 생성 |
| 인증서·암호 인벤토리 | SBOM `cryptographic-asset`(CBOM), `assets.json` | 인증서 만료·서명 알고리즘·키 길이와 약한 설정. 주체·발급자 이름과 개인키는 기록하지 않음 |

## 수집 범위 선택

```bash
# 기본: 호스트 / 전체, 두 표준 형식, 제한된 호스트 컨텍스트
sudo ./koda-bom scan --output-dir /var/tmp/sbom-output

# 파일 수·시간 제한 해제. Ctrl+C로 중단 가능
sudo ./koda-bom scan --output-dir /var/tmp/sbom-output --max-files 0 --timeout 0

# 실제 제외할 경로를 확인한 뒤 지정. /data/docker는 예시
sudo ./collect-livepatch-status.sh /var/tmp/sbom-output \
  --max-files 0 --timeout 0 --exclude /data/docker

# 자산 라벨을 붙여 수집. 컨테이너·이미지별 SBOM을 모두 빼려면 --no-containers,
# 중지된 컨테이너와 로컬 이미지만 빼려면 --no-images
sudo ./koda-bom scan --output-dir /var/tmp/sbom-output --asset-tag 'web-01' --no-containers

# 특정 애플리케이션 / 가상환경의 설치 파일
./koda-bom scan --target /opt/application --no-context --output-dir ./application-sbom

# 별도로 반출한 로컬 Docker/OCI 이미지 tar — Docker 소켓에 연결하지 않음
./koda-bom scan --image-archive ./application-image.tar --output-dir ./image-sbom

# 한 형식, 시간 제한, 특정 경로 제외
./koda-bom scan --target /opt/application --format spdx --timeout 10m \
  --exclude '**/cache/**' --no-context --output-dir ./application-sbom
```

`--target`과 `--image-archive`는 함께 사용할 수 없습니다. 기본 상한은 수집 대상으로 채택하는 일반 파일 **1,000,000개**와 **30분**이며 수집 병렬도는 2입니다. `--max-files N`의 `0`은 파일 수 무제한, `--timeout D`의 `0` 또는 `0s`는 시간 제한 해제입니다. 제한을 해제해도 Ctrl+C로 중단할 수 있습니다. 출력 경로와 임시 경로는 수집 대상에서 제외합니다. 기존 결과는 덮어쓰지 않고 실행별 새 하위 디렉터리에 저장합니다. 정상 출력(stdout)에는 최종 결과 디렉터리 경로가 표시됩니다.

파일 수·시간 해제는 권한, 읽기 범위, 네트워크/가상 파일시스템 경계, 심볼릭 링크 처리, 파일 하나당 2 GiB 상한과 이미지 압축 해제 경계를 변경하지 않습니다. 수집기의 파일 파서는 Java·Python ZIP의 내부 목록과 중첩 구조에 별도 상한을 적용합니다. 일반 파일 한도를 해제해도 사전 탐색 시 심볼릭 링크와 특수 항목을 합해 100만 개까지 기록합니다. 운영자가 일반 파일 한도를 100만 개보다 높게 지정하면 이 상한도 함께 높아집니다. 수집 제한이나 권한 문제는 `collection.json`의 상태 및 사유를 확인하세요.

## IBM AIX와 Oracle 설치 증적

AIX에서는 `collect-aix-evidence.sh`로 OS 레벨, 설치 fileset과 임시 패치 증적을 수집합니다.
Oracle DB 또는 Grid Home을 점검할 때는 해당 Home 소유자가 저장한
`$ORACLE_HOME/OPatch/opatch lsinventory` 출력을 함께 지정합니다.
AIX 명령의 조회 권한이 필요하며 수집기는 Listener나 Oracle 설치 프로그램을 실행하지 않습니다.

```sh
# IBM AIX에서 실행. 새 결과 폴더, 실제 Oracle Home과 기존 OPatch 조회 결과 지정.
./collect-aix-evidence.sh ./aix-evidence /actual/oracle/home ./opatch-report.txt

# 폐쇄망 Linux x86_64 분석 호스트에서 실행.
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./sbom-output
```

Oracle 없이 AIX OS만 수집할 때는 첫 번째 인수만 지정합니다. DBA가 내보낸 SQL 패치 이력도
선택적으로 마지막 인수로 지정할 수 있습니다. CSV 헤더는
`database_id,patch_id,action,status,action_time`이며, 시각은
`YYYY-MM-DDTHH:MM:SS` 또는 RFC 3339 형식입니다. 같은 AIX 서버에서 DB Home과 Grid Home을
수집할 때는 `--oracle-home`을 반복합니다. 최대 8개의 서로 다른 Home을 한 번에 수집할 수
있습니다. 실제 실행 Home은 운영 증적으로 확인합니다.

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
```

확인한 Oracle Database 및 Listener의 제품명·버전·CPE는 표준 SBOM에 기록합니다.
Listener 구성요소는 같은 Home의 실행 파일 헤더 관측, OPatch 인벤토리, 버전 추정에 사용한
RU의 종류와 패치 ID를 연결합니다. SHA-256은 수집한 증적 파일의 해시입니다.
실행 파일이 관측됐는데 RU가 없거나 상충하면 해당 Listener의 Home과 파일 관측만 남깁니다.

Tracker에 `sbom.cdx.json` 또는 `sbom.spdx.json`을 제출하면 지원하는 Tracker에서
같은 제품·버전·CVE라도 Home별 결과와 증적을 확인할 수 있습니다. CVE 조건 일치와
패치 적용 여부는 각각 표시합니다. 설치 패치의 ID를 특정 CVE의 수정 근거로 사용하려면
해당 플랫폼과 릴리스에 맞는 Oracle 공지 또는 패치 문서를 대조해야 합니다.

`collection.json`은 Home별 OPatch 인벤토리와 DBA가 제공한 SQL 패치 이력을 보존합니다.
표준 SBOM에는 패치 ID 목록마다 최대 2,048개를 담고, 생략된 항목이 있으면 표시합니다.
실행 중인 Listener를 확인할 때는 해당 리스너의 운영 증적을 별도로 확보합니다.
원시 AIX·Oracle 자료에는 경로와 DB 식별자가 포함될 수 있으므로 폐쇄망의 접근 제한
위치에 보관합니다.

## 설치된 npm·pnpm 패키지 관계

디렉터리 또는 이미지에서 읽은 `package.json`의 런타임·선택 의존성과 peer 의존성을
수집된 npm 패키지에 연결합니다. 상대 패키지의 `node_modules` 위치, 이름,
설치 버전이 선언과 일치할 때 CycloneDX와 SPDX에 관계를 기록합니다. 중첩된
`node_modules`를 먼저 확인합니다. pnpm은 `.pnpm` 저장소와 워크스페이스 링크를
실제 설치 경로로 해석합니다. 가까운 설치본이 다른 버전이거나 링크가 수집 범위를
벗어나면 상위의 동명 패키지로 대체 연결하지 않습니다.

기본 `.pnpm` 및 사용자 지정 `virtualStoreDir`에서는 각 설치본 옆에 제공된 peer의
버전과 경로를 확인합니다. `nodeLinker: hoisted`에서는 `.modules.yaml`이 설치 위치에
기록한 peer와 실제로 해석되는 패키지를 대조합니다. 미설치 optional peer와 더 상위에만
있는 공용 사본은 해당 설치본에 연결하지 않습니다. 잠금 파일, 개발 의존성 선언,
정적 JS 파일은 설치 관계의 근거로 사용하지 않습니다. 일반 SemVer와 pnpm의
`workspace:*`, `workspace:^`, `workspace:~`, `workspace:<버전 또는 범위>`를 확인합니다.
`pnpm deploy`가 원본 경로를 `이름@file:///…`로 기록한 경우에는 배포본 안의 설치
기록과 그 패키지의 매니페스트를 확인합니다.
일반 SemVer 범위에서 프리릴리스는 정확히 선언한 버전만 연결합니다. 별칭, 원격 주소,
그 밖의 파일 경로, 태그는 관계를 보류합니다.

`collection.json`의 `npm_dependency_*` 항목에서 의존성을 선언한 매니페스트 경로와
관계를 기록하지 못한 이유를 확인합니다. 필수 제공 패키지 미발견, 버전 불일치,
범위 차단, 매니페스트 읽기 실패에 각각 코드가 있습니다. 정상적으로 미설치된
optional peer는 진단에서 생략합니다. 관측되지 않은 관계는 수집 결과에 표시하고,
실제 매니페스트 읽기 실패는 부분 수집에 반영합니다.
[Node.js 모듈 탐색](https://nodejs.org/api/modules.html#all-together) · [pnpm 워크스페이스](https://pnpm.io/workspaces) · [pnpm peer 해석](https://pnpm.io/how-peers-are-resolved)

## 정적 JavaScript 식별

수집 범위의 정적 JS와 WAR/ZIP/EAR 내부에서 jQuery, jQuery UI, Fancytree의 버전 근거를
확인합니다. 확인한 패키지는 npm PURL과 발견 경로를 출력합니다. 파일명만 있는 후보,
상충하는 근거, 검사 한도 등은 `collection.json`에 남깁니다. JS는 처음 512 KiB를
확인합니다. EAR 내부 WAR와 JAR의 `META-INF/resources`, Spring Boot의 정적 리소스 등
지원하는 중첩 구조를 검사합니다. 정적 JS 검사 한도는 아카이브 3단계, 중첩 파일당 64 MiB입니다.
예를 들어 `app.ear!/ui.war!/static/jquery.min.js`처럼 배포 경로를 보존합니다.
`--exclude`는 바깥 파일의 경로에 적용됩니다. 지원 구조·한도를 벗어난 아카이브나
지원 목록 밖의 라이브러리는 별도 분석이 필요합니다.
부분 수집은 CycloneDX에서도 `compositions.aggregate=incomplete`로 표시합니다.

Fancytree는 내장한 공식 배포 파일 목록으로 전체 파일의 SHA-256도 대조합니다.
512 KiB 이하로 끝까지 읽은 스크립트에서 파일명이 달라도 원본과 같은 바이트를 식별합니다.
확인한 버전은 `pkg:npm/jquery.fancytree@버전`으로 기록합니다. 같은 파일이 여러 검증된
릴리스에 있거나 해시와 본문이 서로 다른 버전을 가리키면 그 파일의 버전 판정을 보류합니다.
일치한 파일의 경로·PURL·SHA-256과 사용한 목록의 해시는 `collection.json`에 남깁니다.

검증한 목록에는 공식 npm 배포 자료와 초기 GitHub 릴리스의 `dist`에 포함된 Fancytree
본체 및 개별 모듈이 들어 있습니다. `childcounter.js`는 포함되며, 확인한 공식 자료에는
`childcounter.min.js`가 없었습니다. 직접 압축·수정한 파일은 공식 해시와 같을 때만
해시로 식별되고, 그 외 파일은 본문의 버전 근거를 확인합니다. [공식 릴리스](https://github.com/mar10/fancytree/releases)

## Go·Rust 배포 바이너리 수집

기존 `scan` 명령으로 수집 범위에 들어온 바이너리의 내장 의존성 정보를 읽습니다. Go는
빌드 정보에서 포함된 모듈과 표준 라이브러리 버전을 확인합니다. Rust ELF는 `cargo-auditable`
정보에서 런타임 크레이트와 의존성 관계를 읽습니다. 알려진 Go 모듈 버전과 `crates.io`의
Rust 패키지에는 PURL을 쓰고, 두 SBOM 형식에 발견한 파일 경로를 남깁니다.
버전이 없는 Go 모듈과 공개 레지스트리로 확인되지 않은 Rust 크레이트는 해당 PURL을 생략합니다.

파일과 빌드 도구는 실행하지 않습니다. `go.mod`와 `Cargo.lock`에만 선언된 항목은 이 수집에서
제외합니다. 내장 정보가 있는 바이너리를 대상으로 하며, 손상이나 검사 한도로 읽을 수 없는
정보는 `collection.json`의 `binary_metadata_unreadable`에 남기고 부분 수집으로 표시합니다.

## .NET 배포 파일과 Ruby 설치 gem 수집

기존 `scan`으로 .NET 게시 폴더를 수집하면 `.deps.json`의 패키지 정보와 배포된 관리형 DLL을
대조합니다. 두 근거가 연결된 NuGet 항목에는 PURL과 발견 경로를 기록하고, 확인 가능한
의존성 관계도 남깁니다. 단독 DLL에는 확인 가능한 이름·버전·경로를 기록합니다. DLL의
제품 버전만으로는 NuGet 패키지 버전을 확정할 수 없어 PURL은 비워 둡니다.

Ruby는 `specifications`의 설치 gemspec과 `gems` 디렉터리에 있는 해당 gem 파일을 대조합니다.
Ruby에 기본 제공되는 gem은 `specifications/default`의 gemspec이 근거입니다. `Gemfile.lock`과
`packages.lock.json`에만 남은 항목, 별도 DLL이 없는 단일 실행 파일 배포는 이 수집 범위에서
제외됩니다. 자체 DLL이 없는 NuGet 메타패키지와 관리형 DLL과 연결되지 않은 네이티브
의존성도 이 수집에서는 식별하지 않습니다. 스캔 중 DLL과 gemspec을 실행하지 않습니다.
읽지 못한 배포 메타데이터는 `collection.json`에서 `deployment_metadata_unreadable`로 확인할 수 있습니다.

## Java WAR·EAR·Spring Boot 배포 파일 수집

`scan --target`은 WAR의 `WEB-INF/lib`, Spring Boot JAR의 `BOOT-INF/lib`,
EAR의 WAR와 공유 라이브러리 디렉터리를 확인합니다. 실행형 WAR의
`WEB-INF/lib-provided`도 실제 포함 경로를 보존합니다.
CycloneDX의 위치 증거와 SPDX의 패키지 주석에서
`suite.ear!/apps/web.war!/WEB-INF/lib/dependency.jar` 같은 경로를 확인할 수 있습니다.

수집기는 내장 Maven 메타데이터나 일치하는 공식 JAR SHA-256을 우선합니다.
메타데이터가 빠진 JAR도 파일명과 경로로 남기며, 버전과 Maven 좌표를 알 수
없으면 해당 필드를 비웁니다. 포함된 라이브러리는 배포 관계로 연결하고,
내장 POM의 리터럴 버전, 같은 POM에서 값이 확정되는 `${...}`, 숫자로 된 Maven 버전 범위를
확인합니다. 같은 배포 범위의 실제 JAR 하나와 일치하면 JAR 간 의존 관계를 기록합니다.
외부 부모 POM·BOM이나 빌드 환경이 필요한 조건, 후보가 여러 개인 범위, 수식어가 들어간
범위는 관계를 보류합니다. 수집 중 JAR을 실행하거나 Maven 저장소에 접속하지 않습니다.

[검증 결과와 재현 명령](verification.ko.md)

## 배포 WAR·EAR와 공급사 SBOM 비교

`reconcile`을 지원하는 수집기에서 실제 배포 파일 한 개와 그 파일에 대응하는 공급사 SBOM을 지정합니다.

```bash
./koda-bom reconcile --artifact '/opt/app/app.war' \
  --supplier-sbom '/path/to/supplier.cdx.json' --output-dir '/var/tmp/koda-sbom-results'
```

CycloneDX 1.4–1.7 JSON의 `metadata.component.hashes` 또는 SPDX 2.3 JSON에서 문서가
설명하는 단일 패키지의 `checksums`에 **배포 WAR·EAR 자체의 SHA-256**이 있어야 합니다.
하위 라이브러리 해시로 대신할 수 없습니다. 해시가 없거나 상충하거나 배포 파일과 다르면
비교 결과를 생성하지 않습니다. 해시 일치는 같은 배포 파일을 가리킨다는 증거이며 공급사
서명, 구성요소 목록의 정확성, 취약점 유무는 별도로 판단합니다.

해시가 일치하면 격리된 사본에서만 수집합니다. 배포 파일과 공급사 문서의 해시를
`reconcile.json`에 남기고, 구체적인 버전이 포함된 PURL을 기준으로 `common`(양쪽 일치),
`observedOnly`(직접 수집에만 있음), `supplierOnly`(공급사 SBOM에만 있음),
`unresolved`(식별 보류)를 구분합니다. 예를 들어 `jquery.fancytree.childcounter.min.js`처럼
파일명이 패키지 버전으로 들어간 항목은 식별을 보류합니다. 공급사에만 있는 항목은
수집기가 확인하지 못한 것이므로 `collection.json`의 수집 범위와 제한을 함께 확인합니다.

Tracker에는 직접 관측한 `sbom.cdx.json` 또는 `sbom.spdx.json`을 제출합니다.
`reconcile.json`은 검토용이며 공급사 표기를 직접 수집 SBOM에 자동 추가하지 않습니다.
종료 코드 `0`은 수집과 비교 완료, `3`은 결과가 있으나 부분 수집 또는 식별 보류가 있음,
`2`는 실패로 새 결과가 발행되지 않음을 뜻합니다. 양쪽 목록의 차이 자체는 실패가 아닙니다.
배포 파일은 최대 512 MiB(압축본), 공급사 SBOM은 최대 32 MiB입니다. 기본 제한 시간은
30분이며 `--timeout 0`으로 해제할 수 있습니다.

## 수집 누락 자동 검증

동일한 배포 디렉터리에서 `koda-bom`, Syft, Trivy `fs`를 실행해 구성요소·버전·방향이 있는 패키지 간 의존 관계를 비교합니다. Python 3.11 이상과 로컬 수집기 실행 파일 3개가 필요합니다. 배포본은 읽기 전용으로 마운트하거나 변경되지 않는 복사본을 지정합니다. 검증기는 수집할 때마다 파일 목록과 내용을 해시로 확인합니다. 이번 검증은 `koda-sbom 0.1.4`, Syft 1.57.1, Trivy 0.76.2를 사용했습니다.

```bash
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

`--expected`에는 배포 파일·설치 메타데이터로 확인한 구성요소 `components`, 의존 관계 `dependencies`와 배포에 포함되지 않아야 할 `absentComponents`를 기록합니다. 관계의 첫째 항목은 의존하는 쪽, 둘째는 대상입니다. 검증기의 `componentIdentities`에 나온 식별자를 사용합니다. 이 값은 PURL의 패키지 좌표와 버전을 사용하며, PURL 없는 항목에는 구성요소 유형·그룹·이름·버전을 사용합니다.

```json
{
  "components": ["pkg:npm/app@1.0.0", "pkg:npm/helper@2.0.0"],
  "dependencies": [["pkg:npm/app@1.0.0", "pkg:npm/helper@2.0.0"]],
  "absentComponents": ["pkg:npm/lockfile-only@3.0.0"]
}
```

`comparison.json`은 도구별 식별자와 버전, 쌍별 차이, 같은 이름·버전을 다르게 식별한 후보, 기대값과 비교한 누락을 담습니다. 파일·문서·Trivy의 언어별 매니페스트 노드와 그 연결은 패키지 집계에서 분리해 기록합니다. 비교용 PURL에서 qualifier·subpath를 생략하며, `--baseline /data/qa/inventory-01/comparison.json`을 사용하면 같은 배포본을 대상으로 qualifier·subpath가 붙은 구성요소 행 수와 관계도 회귀 검사합니다. Trivy가 오프라인 Java 인덱스를 요구하면 `--trivy-cache-dir`로 검증된 로컬 캐시를 지정합니다.

`occurrences`와 `absentOccurrences`는 `[PURL, 상대 설치 경로]` 행을 받습니다.
`occurrenceDependencies`와 `absentOccurrenceDependencies`에는 그런 두 행을
`[의존하는 쪽, 제공하는 쪽]` 순서로 넣습니다. `kodaPathComparison`에서 두 SBOM 형식의
경로별 관계와 기대값을 확인할 수 있습니다. 한 참조에서 경로를 하나로 결정할 수 없으면
해당 관계는 미확인으로 남깁니다. `schemaVersion: 3` 기준 파일은 경로별 회귀 검사에도 사용합니다.

종료 코드 `0`은 지정한 검증 통과, `1`은 회귀나 연동 검사 실패, `2`는 입력·수집 실행 오류입니다. Syft나 Trivy 단독 항목은 검토 대상으로 출력하며, 기대값과 기준 결과로 KODA의 실패를 판정합니다. 비교만 실행하고 `--expected`나 `--baseline`을 지정하지 않으면 발견한 차이를 조사할 수 있습니다.

### Tracker 등록 결과 확인

시험 Tracker의 로그인 정보를 `KODA_TRACKER_URL`, `KODA_TRACKER_USERNAME`, `KODA_TRACKER_PASSWORD` 환경 변수로 주입합니다. 루프백 밖에서는 HTTPS를 사용합니다. 위 비교 명령에 `--tracker --create-test-service`를 붙이면 시험 서비스에 KODA CycloneDX·SPDX 문서를 올려 원본 해시, 구성요소 행, 수집 범위를 확인합니다. 기존 시험 서비스에는 `--create-test-service` 대신 `--service-id ID --environment-id ID`를 사용합니다. `--upload-peers`를 붙이면 Syft·Trivy CycloneDX도 비교합니다. 등록한 시험 회차는 Tracker에 남습니다.

Tracker 내부의 관계 저장까지 검증하려면 `--normalized-bom-command /path/to/export-normalized-bom`을 지정합니다. 지정한 실행 파일은 회차 ID 하나를 받아 DB에 저장된 `normalized_bom` JSON만 표준 출력으로 반환해야 합니다. 격리 Tracker의 PostgreSQL에서 읽기 전용 쿼리로 조회한 검증 예시와 결과는 `reports/inventory-parity/`에 있습니다. 내보내기 명령 없이 실행하면 결과에 관계 검증이 미실행으로 표시됩니다. 이미 스캔했다면 `scripts/verify-tracker-inventory.py --cyclonedx FILE --spdx FILE --create-test-service --output tracker.json`으로 등록 검증만 다시 실행할 수 있습니다.

## 저장 결과

CycloneDX 1.6과 1.7을 함께 만들려면 같은 실행에 `--cyclonedx-17`을 추가합니다.

```sh
./koda-bom scan --output-dir ./reports --cyclonedx-17
```

두 버전은 같은 인벤토리에서 생성되며 각 파일의 SHA-256을 결과에 기록합니다.
`--cyclonedx-17`은 기본 형식 또는 `--format cyclonedx`에서 사용할 수 있습니다.
Tracker에 등록할 때는 수집 회차당 필요한 버전 하나를 선택합니다.

| 파일 | 내용 |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 JSON (`--format spdx`이면 생략) |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 JSON (`--cyclonedx-17`을 지정할 때 함께 저장) |
| `obom.cdx.json`, `obom.cdx-1.7.json` | 호스트·컨테이너·실행 패키지·수신 포트 관계. 1.7은 선택 출력 |
| `build-sbom.cdx.json`, `build-sbom.cdx-1.7.json` | 산출물 해시로 연결된 공급사 빌드 선언을 반입했을 때 생성 |
| `sbom.spdx.json` | SPDX 2.3 JSON (`--format cyclonedx`이면 생략) |
| `inventory.syft.json` | 패키지 릴리스·설치 메타데이터를 보존하는 개인정보 정제 Syft JSON |
| `context.json` | 실행 파일·라이브러리와 수신 대기 포트, 실행 커널·로드 모듈·taint 모듈, 라이브패치, 보안 설정·재부팅 신호, 식별되지 않은 실행 프로그램과 한계 |
| `assets.json` | 호스트에서 관측하거나 파일로 반입한 장치·펌웨어·드라이버·인증서 증거 |
| `collection.json` | 도구 버전, 범위, 수량, 누락, 오류, 제품 식별 근거, 호스트 식별(`host`), 패키지 파일 무결성(`integrity`), 컨테이너 목록(`containers`) |
| `containers/<이름>/` | 실행 중이거나 중지된 컨테이너별 `sbom.cdx.json`·`sbom.spdx.json`·`collection.json`·`SHA256SUMS` (호스트 `/` 수집 시) |
| `images/<이름>/` | 어느 컨테이너도 쓰지 않는 로컬 이미지별 SBOM과 `collection.json`·`SHA256SUMS` (호스트 `/` 수집 시) |
| `reconcile.json` | 배포 파일·공급사 SBOM 해시와 PURL 대조 결과 (`reconcile` 실행 시) |
| `SHA256SUMS` | 결과 파일의 SHA-256 |

표준 SBOM은 동일한 수집 결과에서 생성합니다. `inventory.syft.json`도 원문 복제본은 아닙니다. 개인 작성자·이메일, URL의 인증정보·쿼리·fragment, Java manifest의 임의 필드는 정제하며 버전·공급자·source RPM·라이선스·관계 등 식별 근거를 보존합니다. 실행 종료 코드는 `0` 정상, `3` 부분 수집, `2` 실패입니다. 권한 부족·손상·시간 초과·미지원 영역이 있으면 내용을 읽고 후속 조치하세요. 패키지 0개 또는 모듈 미관측은 “취약점 없음”, “미설치” 또는 “안전”을 뜻하지 않습니다.

CycloneDX와 SPDX에는 수집 대상 유형, 구성요소 수, 사용자가 설정한 제외 항목 수와
확인이 필요한 사유별 건수를 함께 담습니다. Tracker의 회차 상세에서 이 수집 요약을
볼 수 있습니다. 제외 경로와 상세 오류는 로컬 `collection.json`에서 확인합니다.

`collection.json`의 `limits.maxFiles`, `limits.timeoutSeconds`는 이번 실행의 상한이며 `0`은 해당 제한 해제입니다. `filesystemFileCount`는 사전 순회에서 수집 대상으로 채택한 일반 파일 수로, 구성요소 수 `packageCount`와 다릅니다. 파일 수 상한 초과는 `issues`의 `code=file_limit_exceeded`, `limit`, `observed`를 확인합니다. Linux 스캔의 `phaseSeconds`에서 파일 탐색, 정적 JS 확인, 인증서 확인, 패키지 수집, 패키지 파일 무결성 확인, SBOM 출력, 컨테이너 수집에 걸린 시간을 비교할 수 있습니다. 컨테이너별 결과는 각 폴더의 `SHA256SUMS`로 따로 검증합니다.

## 수집과 보안 경계

- OS의 RPM/DEB/APK 정보, Java/JDK/JRE, PHP/Composer, Python 설치·가상환경, Node.js 설치 패키지를 수집합니다. 미설치 의존성 선언과 실제 설치 정보를 혼합하지 않습니다.
- 알려진 서버 제품과 수동 설치 구성요소는 읽을 수 있는 manifest·release·설치 inventory·바이너리 증거로 식별합니다. 파일명만으로 제품 버전이나 CPE를 확정하지 않습니다.
- 실행 중인 커널과 설치된 커널은 별개입니다. Oracle/Red Hat의 백포트 검토를 위해 epoch/version/release/architecture와 source package 정보를 유지해야 합니다.
- 호스트 컨텍스트는 실행 파일·공유 라이브러리 연결, 로드 모듈, 허용된 설정만 수집합니다. 전체 `/proc`, 원문 명령줄, 환경변수, 설정 원문, 비밀번호·개인키·인증서 본문은 저장하지 않습니다. 인증서의 지문·유효기간·알고리즘, 공개키 식별 정보, 서명으로 확인한 발급 관계를 기록합니다.
- 설정 파일에 선언된 값은 실제 적용값이나 네트워크 노출의 증명이 아닙니다. PHP `ini_set()` 같은 실행 중 변경까지 확인하지 않습니다.
- 생성 결과에는 소프트웨어 이름·버전·설치 경로가 포함됩니다. 경로 자체에 사용자 이름이나 내부 프로젝트명이 있을 수 있으므로 결과를 외부에 공유하기 전 검토하세요.
- 장치와 펌웨어의 수집 범위는 커널이 노출하는 속성, 읽기 전용 ioctl(NIC `ETHTOOL_GDRVINFO`, BMC IPMI `Get Device ID`)과 관리자가 제공한 증적에 따릅니다. megaraid_sas처럼 커널이 펌웨어 버전을 노출하지 않거나 정확한 빌드 대조가 필요하면 Redfish·fwupd·devlink 등에서 내보낸 파일을 반입합니다.
- 패키지 파일 무결성은 패키지 DB에 해시가 있는 실행 파일·공유 라이브러리만 대상으로 하며 설정 파일은 제외합니다. 불일치는 수동 교체·변조의 단서이며 원인 판정은 별도 확인이 필요합니다. 식별정보가 제거된 바이너리와 소스코드 논리 결함의 검토에는 별도 근거가 필요합니다.

자세한 [지원 범위와 한계](support-matrix.ko.md), [빌드·검증 방법](verification.ko.md)을 참고하세요. 기본 수집은 인벤토리와 증적을 생성합니다. 같은 파일의 선택 기능인 `assess`는 로컬 권고를 생성된 SBOM과 비교합니다. 표준 SBOM을 KODA/Tracker에 반입해 관리할 수도 있습니다.

## 외부 빌드 PC

```bash
# 현재 소스의 Linux x86_64 배포용 압축파일 생성
VERSION=0.1.8 ./scripts/build-release.sh

# 별도로 검증한 Go 설치본과 미리 반입한 모듈 캐시로 빌드
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"

# Linux ARM64용 단일 바이너리 빌드
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

빌드 PC에는 Go 1.26.11 이상(검증 버전 1.26.11)과 Python 3이 필요합니다. 기본 빌드는 시스템 설치 경로의 Go를 사용합니다. 다른 Go 설치본은 `--go`에 신뢰하는 절대 경로를, `--go-sha256`에 검증된 실행 파일 SHA-256을 지정합니다. 기존 자동화에서 `GO_BIN`도 넘긴다면 `--go`의 경로와 일치해야 합니다. `GOMODCACHE`의 다운로드 캐시와 `GOPROXY`의 사내 미러를 사용할 수 있습니다. `GOPROXY=off`는 미리 받은 모듈 아카이브만 사용합니다. 빌드에 필요한 모듈이 캐시와 미러에 없으면 빌드가 중단됩니다.

배포용 압축 스크립트는 모듈을 임시 작업 공간에서 검증하고 `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`로 빌드합니다. Syft 라이브러리는 `v1.57.1`에 고정합니다. `release.json`에는 Go와 Syft 버전, Go 실행 파일과 모듈 입력의 SHA-256, 빌드 명령과 모듈 그래프를 기록합니다. 대상 서버에서는 기존 단일 실행 파일을 사용합니다. 라이선스 파일이 없는 연결 모듈은 누락 목록을 남기고 배포 포장을 중단합니다.

새 프로젝트에 Git 커밋이 아직 없으면 Git 해시를 꾸미지 않고 `src<소스SHA-256앞12자리>`를 사용합니다. 변경된 Git 작업 폴더는 `git해시-dirty-src해시`로 구분합니다. 같은 배포 경로를 덮어쓰지 않습니다. GitHub 게시와 운영 서버 설치는 자동 수행하지 않습니다.

배포 압축파일의 소유자 정보는 root/0으로 정규화해 빌드 PC 계정명을 포함하지 않습니다.

실제 실행 증거와 미검증 범위는 [검증 결과 기록](검증결과.ko.md)에 구분했습니다. 라이브 파일시스템 수집은 원자적 스냅샷이 아니므로 수집 중 설치·업데이트가 있으면 정합성이 제한됩니다.

Oracle 커널 VM 검증의 재현 절차는 [검증 안내](verification.ko.md)에 있습니다. Python·Docker·QEMU와 검증용 Go PID 1은 외부 빌드 PC의 시험 도구이며 배포 실행 파일의 의존성이 아닙니다. VM은 공식 Oracle RPM의 해시·서명을 확인한 커널과 Oracle Linux 8.2 사용자 공간을 custom initramfs로 직접 부팅합니다. GRUB·UEFI·systemd 전체 설치 또는 운영 서버의 SELinux·서비스 구성 검증과는 범위가 다릅니다.
