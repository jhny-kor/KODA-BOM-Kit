# 빌드·검증과 증거 구분

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## 0.1.8 현재 검증 범위

KODA BOM Kit의 현재 소스 버전은 `0.1.8`입니다. Linux amd64 폐쇄망 배포본의 압축파일과 SHA-256
체크섬은 [공식 릴리스](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)에서
받습니다. 반입·압축 해제·실행 명령은 [폐쇄망 실행 안내](air-gapped.ko.md)에 있습니다.
각 배포본의 실행 파일 SHA-256과 실행 환경은 해당 릴리스 설명에서 확인합니다.
[검증 결과 기록](검증결과.ko.md)과 아래 0.1.5 이하 배포·VM 절차는 해당 버전의 이력입니다.

Linux 전체 수집은 x86_64와 ARM64를 대상으로 합니다. Docker/OCI 이미지 수집은
linux/amd64 이미지가 대상입니다. macOS·Windows의 `platform-inventory`는 OS가 제공하는
고정된 읽기 전용 명령으로 기본 자산을 수집하므로, Linux `scan`의 추가 명령 비실행
검증과 별도로 확인합니다. Windows는 현재 교차 빌드만 확인했습니다.

### CycloneDX 1.6·1.7 동시 출력 검증

`--cyclonedx-17`을 지정하면 한 번 수집한 같은 인벤토리에서 1.6과 1.7을 함께 만듭니다.
기본 출력은 CycloneDX 1.6과 SPDX 2.3입니다.

| 선택 | 확인할 표준 파일 |
|---|---|
| 기본 또는 `--format both` | `sbom.cdx.json`(1.6), `sbom.spdx.json`(2.3) |
| `--format both --cyclonedx-17` | 위 두 파일과 `sbom.cdx-1.7.json`(1.7) |
| `--format cyclonedx --cyclonedx-17` | `sbom.cdx.json`, `sbom.cdx-1.7.json` |
| `--format spdx --cyclonedx-17` | 출력 생성 전 거부 |

이 옵션은 `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile`에서
지원하며 `scan-directory.sh`와 `collect-livepatch-status.sh`도 전달합니다. Linux 대상
디렉터리 수집의 재현 명령은 다음과 같습니다. 출력 부모 경로는 수집 대상 밖으로 지정합니다.

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
# 수집기가 출력한 실제 결과 디렉터리를 지정합니다.
python3 tests/validate_outputs.py /path/to/scan-result
```

종료 코드 `3`은 부분 수집입니다. 스키마 통과와 별도로 `collection.json`의 상태와
미수집 사유를 확인합니다. `tests/validate_outputs.py`는 존재하는 표준 파일의 로컬
스키마, 1.6·1.7 구성요소 식별정보·근거·속성·라이선스 의미·의존성 관계·수집 범위,
`SHA256SUMS`의 누락·중복·해시를 검사합니다. 기대한 파일이 모두 생성됐는지도 위 표와
대조합니다. 검증 중 외부 스키마를 다운로드하지 않습니다.

1.7 스키마 묶음은 공식 `1.7.1` 수정 릴리스의 커밋
`b29bae660048e0ad2fbc5f2972927b442ce951c4`로 고정했습니다. BOM의 `specVersion`은
`1.7`입니다. 출처와 SHA-256은 `tests/schemas/provenance.json`에 기록합니다.
1.6과 1.7의 SPDX 라이선스 정의를 각각 사용하며, 1.7에서 추가된 107개 ID를 확인합니다.
1.6에서 지원하지 않는 ID를 `license.name`으로 보존하고 1.7에서는 `license.id`로
출력하는 경우도 같은 라이선스로 비교합니다. 1.7 출력만으로 새로운 수집 범위가
생기거나 하드웨어 취약점 판정이 추가되는 것은 아닙니다.

### 확장 수집 fixture와 실제 환경 구분

기존 `go test ./...`와 `go vet ./...`에 다음 회귀 범위를 포함합니다.

| 대상 | 확인 내용 |
|---|---|
| 하드웨어·외부 증적 | `internal/hardware`, `internal/assetimport`: 로컬 속성 파싱, Redfish·fwupd·devlink·일반 JSON, 잘못된 입력과 관측 한계 |
| 실행 중 파일 | `internal/hostcontext`, `internal/collect`: 삭제·교체 파일, 비교 가능한 파일시스템과 패키지 소유 관계, 재시작 검토 근거 |
| Python·이미지 | `.pyz`·`.pex`의 실제 METADATA, 손상된 항목의 부분 수집, archive SHA-256과 이미지 digest |
| 플랫폼 | `internal/platforminventory`: macOS·Windows 자료 파싱과 수집 범위 표시 |
| 오프라인 상관분석 | `internal/assessment`: 정확한 버전 규칙, 지원 OSV·CSAF 부분집합, 선택 KEV, SBOM과 컨텍스트 체크섬 연결 |
| 형식 호환성 | `internal/collect/output_test.go`: 고정 라이선스 목록, 1.6 대체 표현과 1.7 표현, 표준 출력 보존 |
| 호스트 식별·포트 | `internal/hardware/identity_test.go`, `internal/hostcontext/sockets*_test.go`, `internal/collect/host_annotations_test.go`: 해시·공용 기본값 제외, `/proc/net` 파싱, 실제 소켓의 프로세스 연결, SBOM 속성 |
| 컨테이너 | `internal/containers`: 가짜 procfs로 Docker·containerd(Kubernetes)·sandbox 제외·mountinfo 대조·안전한 폴더 이름. `internal/localfs/rootfs_links_test.go`: 컨테이너 root의 절대 링크 해석 |
| 펌웨어·BMC | `internal/hardware/adapters_test.go`, `ipmi*_test.go`: 커널 소스로 확인한 RAID/HBA·RDMA·GPU 속성, IPMI 응답 해석과 구조체 크기·ioctl 번호 |
| 앱 번들 | `internal/collect/app_bundles_test.go`: snap `current`·flatpak `active`만 기록, conda PURL |
| 보안 설정 | `internal/hostcontext/posture*_test.go`, `collect_test.go`: SELinux·AppArmor·lockdown·재부팅 신호, 부팅 옵션 허용 목록, 커널 빌드 설정 출처·제외 경로, 커널 계열 비교, `sshd_config`, taint 모듈, 제외 경로 준수 |
| 저장된 컨테이너·이미지 | `internal/containers/storage_test.go`: Docker overlay2 chain ID·`cache-id`·쓰기 계층, 사용 중 이미지 제외, containers-storage 계층 체인, whiteout·opaque·하위 계층 심볼릭 링크 탈출 차단·set-ID 제거·복사 예산. `storage_containerd_test.go`: 직접 만든 bolt 파일(branch·leaf·inline bucket)로 containerd 이미지·스냅샷·컨테이너와 플랫폼 선택, 손상 파일 거부. `whiteout_linux_test.go`: 0/0 문자 장치 whiteout(privileged, tmpfs) |
| 출처·서비스·CPE | `internal/collect/origin_test.go`: apt 평문·gz·lz4 목록, dnf 이력(완료·실패 트랜잭션, `@commandline`), yumdb 로컬 경로 미기록, 서비스 → 패키지 연결. `internal/hostcontext/services_test.go`: drop-in `ExecStart` 재설정, 템플릿 인스턴스, 소켓 활성화, 마스크, cgroup 실행 여부, 스캔 범위 밖 단위 파일 미열람. `internal/hardware/cpuid_test.go`: NVD 명명과 대조한 CPU·Dell·Lenovo CPE |
| 무결성·CBOM | `internal/collect/integrity_test.go`: md5·sha256·apk Q1, 설정 파일 제외, 누락·제외·usr-merge·예산. `internal/certs`: 만료·약한 키·개인키 미기록·신뢰 저장소 제외 |

Linux 전용 테스트(`*_linux_test.go`)는 Linux에서 실행해야 합니다. macOS 빌드 PC에서는 테스트 바이너리를 교차 빌드한 뒤 Linux 컨테이너에서 실행합니다.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm -v "$PWD":/repo:ro -w /repo/internal/hostcontext debian:bookworm-slim /repo/hostcontext.test
```

실행 중인 컨테이너 수집은 Docker VM의 프로세스와 저장소를 볼 수 있는 권한 컨테이너에서 재현할 수 있습니다. 실제 서버에서는 호스트에서 직접 실행합니다.

```bash
docker run --rm --privileged --pid=host -v /var/lib/docker:/var/lib/docker:ro,rslave \
  -v "$PWD/bin":/b:ro -v "$PWD/out":/out debian:bookworm-slim /b/koda-bom scan --output-dir /out --exclude '/b/**'
```

fixture 통과는 실제 BMC·펌웨어·OT 장비, Windows 실행 또는 모든 공급사 advisory 형식의
지원 증거가 아닙니다. Linux 컨테이너의 장비 속성도 컨테이너에서 관측 가능한 범위로
기록합니다. `assess`는 사용자가 제공한 로컬 규칙과 관측값의 상관분석이며 자동 패치나
취약점 조치 완료 확인을 수행하지 않습니다.

## .NET·Ruby 배포본 비교

```bash
python3 tests/dotnet_ruby_integration.py --stage /path/to/linux-build --cache /path/to/upstream-cache
```

.NET 10 SDK와 Docker를 사용합니다. 공식 패키지와 비교 도구의 배포 파일은 SHA-256으로
검증하고, Ruby 설치와 세 도구의 SBOM 수집은 네트워크를 차단한 Linux x86-64에서
수행합니다. 같은 배포물을 읽기 전용으로 마운트해 알려진 패키지 버전의 PURL, 단독 DLL의
관측 여부, 설치되지 않은 항목과 선언만 남은 항목을 비교합니다. `--koda-only`로 KODA의
두 SBOM 형식, 발견 경로, 디렉터리 제외 및 부분 수집 표시만 확인할 수 있습니다.
`--tracker-root /path/to/tracker`를 지정하면 Tracker가 두 형식에서 PURL과 부분 수집 사유를
같게 읽는지 확인합니다.

## Go·Rust 배포 바이너리 검증

```bash
python3 tests/go_rust_binary_integration.py --stage /path/to/linux-build --go /path/to/go
```

Go 모듈이 로컬 캐시에 있어야 하며, 시험 준비 과정에서 SHA-256을 고정한 Alpine `ripgrep`
패키지를 받습니다. 이미 확보한 동일 ELF는 `--rust-binary`로 지정할 수 있습니다.
네트워크를 차단한 Linux x86_64 컨테이너에서 두 표준 SBOM의 PURL·파일 경로·의존성 관계,
디렉터리 제외, 손상된 Rust 정보의 부분 수집 표시, 원본 파일과 빌드 도구를 실행하지 않는지
확인합니다.
`--tracker-root /path/to/tracker`를 지정하면 실제 로컬 Tracker 파서로 두 SBOM을 읽고
Go·Rust PURL과 부분 수집 사유가 보존되는지 비교합니다.

## Fancytree 파일 해시와 출처 검증

외부 빌드 PC에서 공식 배포 자료를 받아, 목록에 고정한 npm SHA-512 또는 GitHub
아카이브 SHA-256을 검증하고 파일 해시 목록을 다시 계산합니다. 기존 목록 검증에는
`--check`를 사용합니다. npm의 신규 릴리스를 추가할 때는 `--refresh-npm`으로
목록을 갱신한 뒤, 기존의 단일 버전 해시가 여러 버전에 해당하게 된 경우도 검토합니다.

```bash
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
# 검증이 끝난 공식 배포 자료 캐시와 Linux x86_64 바이너리를 사용합니다.
python3 tests/fancytree_fingerprint_integration.py --stage /path/to/linux-build --cache /path/to/upstream-cache
```

## 여러 디렉터리 수집 검증

```bash
python3 tests/multi_directory_integration.py --stage /path/to/linux-build
python3 tests/multi_directory_integration.py --stage /path/to/linux-build --tracker-root /path/to/tracker
```

네트워크를 차단한 Linux x86_64 컨테이너에서 디렉터리별 제외, 공통 제외 패턴, 공유
파일 수 제한, SBOM 형식별 발견 경로와 의존성 관계를 확인합니다. Tracker 옵션은 두 형식의
구성요소와 수집 상태를 실제 Tracker 파서로 읽어 비교합니다.

## 배포 파일과 공급사 SBOM 대조 검증

```bash
python3 tests/supplier_reconcile_integration.py --stage /path/to/linux-build
```

테스트는 네트워크가 차단되고 루트 파일시스템이 읽기 전용인 Linux x86_64 컨테이너에서
WAR와 EAR를 각각 CycloneDX 및 SPDX 공급사 문서와 대조합니다. 해시 불일치·누락·충돌,
깨진 아카이브, 시간 초과 시 결과가 발행되지 않는지 확인합니다. 해시가 일치할 때는
직접 수집과 공급사 기록의 차이, 파일명 기반 항목의 식별 보류, 아카이브 밖 파일의 제외,
출력 스키마와 체크섬을 검증합니다. 합성 자료를 사용하며 운영 배포본은 별도 확인이 필요합니다.

## 중첩 웹 아카이브와 AIX 증적 검증

Linux x86_64 실행 파일을 준비한 후 다음 통합 테스트를 실행합니다.
검증 환경은 네트워크를 차단한 Linux 컨테이너와 로컬 스키마를 사용합니다.

```bash
python3 tests/detailed_sbom_integration.py --stage /path/to/linux-build
# 로컬 Tracker 체크아웃과 해당 저장소의 .venv가 준비된 경우
python3 tests/detailed_sbom_integration.py --stage /path/to/linux-build --tracker-root /path/to/tracker
```

테스트는 EAR 안의 WAR·JAR과 Spring Boot JAR의 JS 식별과 발견 경로, 두 표준 SBOM의
스키마 및 체크섬, 같은 버전의 Oracle Listener를 Home별로 분리하는지 확인합니다.
OPatch의 RU 패치 ID와 설치 패치 전체 목록, 증적 파일 해시를 대조합니다. 버전 근거가
누락된 Home은 Listener 파일 관측이 남고 버전·CPE가 비어 있는지 확인합니다.
Tracker 옵션은 생성한 SBOM을 실제 파서에 넣고 테스트용 NVD 조건과 매칭해 Home별 발견과
패치 적용의 미확인 상태가 보존되는지 확인합니다.
AIX 증적은 테스트 자료를 사용하며 실제 IBM AIX의 수집 명령이나 운영 Tracker 데이터에
대한 검증은 별도로 수행합니다.

## 0.1.4 디렉터리 전용 실행 검증

최종 패키지의 실행파일과 `scan-directory.sh`를 함께 검증합니다.

```bash
python3 tests/directory_integration.py --stage /path/to/final-stage
```

지정 디렉터리 안의 구성요소는 발견하고, 형제 디렉터리·범위 밖 링크의 구성요소는 표준 SBOM에서 제외하며 호스트 컨텍스트가 비활성인지 확인합니다. 공백 경로·두 표준 스키마·체크섬·잘못된 옵션의 부작용 없는 거부와 파일 수·시간 해제도 검사합니다. 실제 실행 결과와 최종 바이너리 해시는 동봉 검증 보고서를 기준으로 합니다.

## 0.1.3 파일 수·시간 옵션 검증 절차

`scan --max-files N`은 기본 1,000,000개이며 `0`은 수집 대상으로 채택하는 일반 파일 수 상한을 해제합니다. `--timeout D`는 기본 30분이며 `0` 또는 `0s`는 수집 시간 제한을 해제합니다. 옵션은 서로 독립적이고 두 제한을 모두 해제해도 Ctrl+C에 의한 취소를 처리해야 합니다. 음수와 잘못된 옵션, 작은 파일 상한 초과, `--max-files 0` 및 `--timeout 0` 실행을 회귀 시나리오로 확인합니다.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-sbom-results --max-files 0 --timeout 0
sudo ./collect-livepatch-status.sh /var/tmp/koda-sbom-results --max-files 0 --timeout 0
```

위 두 명령은 수집기 단독과 선택 helper의 각각 다른 실행 예시입니다. helper는 부모 출력 경로 뒤의 수집 옵션을 전달하고 기존 클라이언트 상태 조회 자체의 30초/10초 제한은 유지해야 합니다. `/data/docker` 같은 경로를 `--exclude`하는 시험에서는 실제 대상 경로와 제외 결과를 확인합니다. 예시 경로를 회사 경로로 전제하지 않습니다.

검사할 출력은 `collection.json`의 `limits.maxFiles`, `limits.timeoutSeconds`, `filesystemFileCount`와 `issues`의 `code=file_limit_exceeded`, `limit`, `observed`입니다. 파일 수는 소프트웨어 구성요소 수와 구분합니다. 상한 초과는 중간 결과를 완성 SBOM으로 표시하지 않아야 하며 일반 오류 메시지에 민감한 경로를 추가하지 않습니다.

기존 읽기 범위, 무통신·추가 명령 비실행, symlink, 파일 하나당 2 GiB 및 이미지 압축 해제 경계의 회귀도 유지합니다. 최종 통과 여부는 동봉 `VERIFICATION.json`과 `dist/evidence/v0.1.4/final-verification.json`의 **동일 바이너리 SHA-256**으로 식별합니다. 아래 절차나 과거 0.1.2 결과만으로 새 빌드가 검증됐다고 주장하지 않습니다.

## Ubuntu·라이브패치 검증

Ubuntu 24.04.1/`6.8.0-47-generic` 실제 커널 검증 절차는
[`tests/ubuntu-vm/README.ko.md`](../tests/ubuntu-vm/README.ko.md)에 있습니다.
Ubuntu CD 서명키로 인증한 Base rootfs와 서명된 Ubuntu Snapshot 인덱스의 커널 DEB를 사용하며,
원본 DEB를 unpack한 시험용 사용자 공간을 custom initramfs로 부팅합니다.
독립 uname·proc release·실제 `dummy` 모듈 로드와 수집 결과를 비교하고,
DEB 버전/source/PURL·설치 커널·모듈·두 SBOM 공식 스키마와 체크섬을 검사합니다.
일반 systemd 설치·GRUB·물리 서버 또는 구독 라이브패치 적용 시험과 구분합니다.

라이브패치 단위 테스트는 적용/비활성/전환, 변경 중 속성, 읽기 제한·권한·symlink,
타 부팅/커널·오래된 보고서·Canonical의 Last-Check와 CheckState,
실행하지 않는 커널의 항목, Ksplice 탐지 기능과 available 목록, 원문 비밀값 정제를 확인합니다.
선택 실행 helper의 통합 시험은 **합성 클라이언트**를 Linux 컨테이너에서 실행합니다.

```bash
python3 tests/livepatch_integration.py --stage /path/to/extracted-release
```

기본 수집기 syscall 시험은 외부 명령/통신 시도를 추적합니다. 선택 helper가 실행하는
서버의 기존 공급자 클라이언트나 그 daemon의 동작은 이 검증에 포함하지 않습니다.
실제 구독이 활성화된 Oracle Ksplice/Canonical 클라이언트에 보안 패치를 적용하는 시험은 별도이며,
합성 보고서 파싱 성공을 그 시험의 완료로 표현하지 않습니다.

최종 포장은 `scripts/finalize-release.py`로 수행합니다. 동일 바이너리 SHA-256의
Go·fixture·helper·syscall 시험 및 Ubuntu·Oracle RHCK·UEK VM 검증이 모두 통과해야 하며,
실제 보고서와 한계를 압축 안의 `VERIFICATION.json`에 담습니다.
압축 후 전체 파일을 다시 읽어 SHA-256을 대조합니다. 원본 VM 실행 로그와 반출 결과는
`dist/evidence/v0.1.4/system-vms`에 보존합니다.

구현 참고: [Linux sysfs ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-kernel-livepatch),
[Oracle 상태 조회](https://docs.oracle.com/en/operating-systems/oracle-linux/ksplice-user/ksplice-UsingthekspliceCommandtoManagetheKspliceEnhancedClient.html),
[Canonical 상태 조회](https://ubuntu.com/security/livepatch/docs/client/how-to-guides/operations/check-client-status/).

## 빌드 PC 검사

Daybreak 조치 이후의 검증은 같은 배포 실행 파일로 진행합니다. 아래 검사로
소프트웨어와 장치·펌웨어 증적의 동시 수집, CycloneDX 1.6·1.7의 결과 동등성,
이미지 아카이브 수집과 파일 수·권한·취소 진단을 확인할 수 있습니다.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install "jsonschema>=4,<5"  # 외부 빌드 PC의 검증 환경에서만
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

`docker_integration.py`는 미리 받은 Linux amd64 `debian:bookworm-slim` 이미지를
사용하고 실행 중 네트워크를 차단합니다. 이미지 준비에는 `--pull`을 사용할 수 있습니다.
macOS에서는 체크섬을 `shasum -a 256 -c SHA256SUMS`로 확인할 수 있습니다.
Linux amd64 빌드 호스트에서 직접 확인하려면 `python3 tests/integration.py --binary "$stage/koda-bom"`을 실행합니다.
Oracle 컨테이너 검증은 `docker pull --platform linux/amd64 oraclelinux:8.2`로
이미지를 준비한 뒤 `python3 tests/oracle82.py --binary "$stage/koda-bom"`으로 실행합니다.

검증용 Python·Docker·jsonschema는 빌드 PC에서만 사용합니다. 배포 실행 파일은 이 프로그램들에 의존하지 않습니다. 표준 스키마는 `tests/schemas`에 버전 고정해 두며 검증 시 외부 참조를 다운로드하지 않습니다.

`trusted_go_sha256`에는 검증된 Go 설치본의 실행 파일 SHA-256을 지정합니다. 캐시만으로 빌드하려면 모듈 아카이브를 미리 준비하고 `GOPROXY=off`를 설정합니다. 배포 QA와 최종 포장은 `python3 -O` 또는 `PYTHONOPTIMIZE`로 검사를 끄는 실행을 거부합니다.

## 확인 항목

- Linux ELF x86_64, 동적 interpreter/공유 라이브러리 의존 없음, GOAMD64 v1.
- 읽기 전용 rootfs, `--network none`, `--cap-drop ALL`, 비루트 환경에서 fixture 수집.
- trace 가능한 격리 컨테이너에서 실제 네트워크 syscall 시도와 추가 execve 유무 확인.
- CycloneDX 1.6·SPDX 2.3 전체 스키마, 구성요소 이름/버전/PURL, SHA256SUMS 확인.
- Java/PHP/Python/Node/DEB/APK fixture, 원본 메타데이터·위치 보존, 사용자 비밀 canary가 결과에 노출되지 않음.
- Docker/OCI archive에 host kernel/프로세스 데이터 혼입 없음. 경로 탈출·symlink·압축 과다 입력 거부.
- root/nonroot·권한 부족·시간 초과·손상·중복 설치·서버 메타데이터 충돌.

## Oracle Linux 8.2 검증 수준

Oracle Linux 8.2 container image는 OS release/RPM DB 데이터와 사용자 공간 실행 호환성을 검증하는 데 사용합니다. **Docker는 호스트 커널을 공유하므로 RHCK 4.18·UEK 5.4에서의 실제 실행 증거가 아닙니다.** 실제 Oracle 게스트 커널 실행은 별도의 QEMU 시스템 VM으로 확인합니다.

검증용 VM에는 공식 Oracle Linux 8.2 사용자 공간과 다음 x86_64 GA 커널을 함께 배치하고, 각 커널 이미지로 따로 부팅합니다.

| 커널 | 정확한 실행 버전 | 설치 자료 |
|---|---|---|
| RHCK | `4.18.0-193.el8.x86_64` | 같은 버전의 `kernel-core`, `kernel-modules`, `kernel` RPM |
| UEK R6 | `5.4.17-2011.1.2.el8uek.x86_64` | `kernel-uek` RPM |

RPM URL·SHA-256·크기와 Oracle 서명키 지문은 `tests/oracle-vm/kernels.json`에 고정했습니다. 준비 스크립트는 SHA-256과 키 지문을 대조하고 격리된 RPM DB에서 패키지 서명을 확인합니다. 검증할 두 커널 RPM은 그 시험 파일시스템에만 `--noscripts --notriggers`로 설치하며 기존 KODA·Tracker DB나 호스트 커널을 변경하지 않습니다.

현재 runner는 macOS ARM64 빌드 호스트의 Linux ARM64 Docker 안에서 `qemu-system-x86_64 -accel tcg,thread=single`을 실행합니다. 게스트 메모리는 4 GiB, 가상 CPU는 2개이며 가상 디스크·네트워크 인터페이스를 제공하지 않습니다. QEMU 컨테이너도 network none·읽기 전용 rootfs·capability 제거 상태입니다. 사용자 공간은 Oracle Linux 8.2지만 PID 1은 검증 전용 정적 Go 프로그램입니다. 실제 커널의 uname·proc release·로드 모듈 baseline을 수집 결과와 독립적으로 기록합니다.

### VM 재현

아래 도구와 다운로드는 외부 빌드 PC에서만 필요합니다. Python 3·Go·Docker·jsonschema를 준비하고 Docker에 최소 6 GiB 메모리 여유를 둡니다. `/path/to/koda-bom`에는 검증할 **최종 배포 파일에서 추출한 바이너리**를 지정합니다.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# run.py가 출력한 각 실행 디렉터리를 사용합니다. 두 명령은 각각 따로 실행합니다.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

`input-provenance.json`, `rpm-signature-install.log`, QEMU `command.json`·`serial.log`, `boot-report.json`, baseline·검증 결과와 두 SBOM을 보존합니다. 같은 작업 디렉터리에서 바이너리만 바꿔 `prepare.py`를 다시 실행하면 입력 initramfs를 새 바이너리로 다시 만듭니다. 새 release의 검증은 이전 실행 파일의 결과와 SHA-256을 혼용하지 않아야 합니다. 공개 태그는 바뀔 수 있으므로 실제 사용한 Oracle·QEMU 이미지 ID도 provenance로 식별합니다.

이 VM 검증은 실제 RHCK·UEK 게스트 커널에서의 실행, 설치된 두 커널과 현재 실행 중인 커널의 구분, 실제 `loop` 모듈 로드와 관측, RPM 원래 릴리스·source RPM 보존을 검사합니다. GRUB 부트로더 설치, UEFI/Secure Boot, systemd 서비스 부팅, SELinux enforcing 정책 및 물리 장비의 드라이버·디스크·성능은 별도 검증 범위입니다. VM 수집 종료 `3`은 오류를 감춘 성공 코드가 아니라 출력에 사유가 남은 **부분 수집**입니다. VM 자체의 부팅·기능 검증 통과와 모든 파일의 완전 수집을 구분합니다.

실제 서버에서는 아래 명령으로 권한·SELinux·noexec·파일시스템 조건을 추가 검증합니다.

```bash
./koda-bom doctor
sudo ./koda-bom scan --output-dir ./oracle82-verification
```

실제 서버에서 실행 중 커널과 설치된 다른 커널이 구분되는지 확인하고 실행 조건을 함께 기록합니다. 커널 3.2 이상은 Go 실행 최소 조건이며 모든 해당 커널/제품 조합을 검증했다는 의미가 아닙니다.

## Tracker 연계 검증

기존 운영 Tracker DB를 쓰지 않고 임시 격리 DB에서 두 표준 파일을 각각 업로드합니다. 구성요소·버전·PURL·관계 보존을 비교합니다. `context.json`, 패치 근거, 배포판 필드의 후속 자동 활용 여부는 별도로 확인하며, 표준 업로드 성공을 해당 기능의 완료로 해석하지 않습니다.

## 메모리·시간

시간 제한은 `--timeout`(기본 30분, `0`/`0s`는 무제한), 파일 수 상한은 `--max-files`(기본 1,000,000, `0`은 무제한)로 제어합니다. Ctrl+C 취소와 각 제한의 실패 상태도 검증합니다. 실제 파일 수·archive 크기·권한·CPU·메모리에 따라 달라지므로 실행 파일 크기, wall time, peak RSS를 실제 테스트 결과에 기록합니다. 수집 병렬도 2는 hard memory cap이 아니며 제한 해제도 자원 사용 상한을 보장하지 않습니다. 운영 서버의 자원 한도는 관리자의 실행 환경 정책과 함께 적용해야 합니다.

## syscall 추적용 격리 이미지

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
```

이 디버그 이미지는 빌드 PC 검증에만 사용하며 대상 서버 배포물에 포함하지 않습니다. amd64 에뮬레이션에서 ptrace가 지원되지 않으면 시도 0회라고 주장하지 않고, 네이티브 x86_64 Linux에서 별도 추적해야 합니다.

ARM64 빌드 PC에서 ptrace 레지스터 해석이 깨지는 경우 `trace-network.sh`는 exit 77로 미지원 상태를 반환합니다. 다음 대안은 동일한 amd64 실행 파일의 **QEMU guest syscall**을 기록하며 실제 x86_64 커널에서의 ptrace 검증과 구분합니다.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
# 기본 호스트 수집과 새 livepatch sysfs 읽기도 추적
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```
