# Oracle Linux 8.2 커널 직접 부팅 검증 harness

`init.go`는 배포 대상 실행 파일이 아니라 **검증 전용 VM PID 1**입니다.
Go 루트 테스트가 이 파일을 패키지로 취급하지 않도록 `//go:build ignore`를 사용합니다.
명시적으로 다음처럼 빌드합니다.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python·Go·Docker·QEMU는 **빌드 PC의 검증 도구**입니다. 대상 폐쇄망 서버에는 `koda-bom`
하나만 전달합니다. 이 harness나 Python 인터프리터를 배포 실행 파일의 의존성으로 포함하지 않습니다.

## 재현 순서

현재 runner는 ARM64 빌드 호스트용 QEMU 컨테이너에서 x86_64 시스템을 TCG로 에뮬레이션합니다.
검증 게스트는 메모리 4 GiB와 vCPU 2개를 사용하며, 컨테이너 메모리 제한은 6 GiB입니다.
외부 빌드 PC에서 소스 프로젝트 루트를 기준으로 다음을 실행합니다.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# run.py가 표시한 실제 경로로 <ID>를 바꿉니다. 기존 검증 보고서는 덮어쓰지 않습니다.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

검증 호스트에는 `jsonschema`가 필요하며 `tests/schemas`에 고정한 공식 스키마로 오프라인 검사합니다.
준비 단계의 다운로드에는 네트워크가 필요하지만 커널 VM 실행에는 외부 연결이 없습니다.
태그가 같은 이미지라도 바뀔 수 있으므로 실행 당시 image ID를 보존합니다.

`prepare.py`는 [`kernels.json`](kernels.json)에 고정한 RPM 4개(합계 120,245,036바이트)의
SHA-256·크기와 Oracle Linux 8 서명키 지문을 확인합니다. 새 시험용 Oracle 컨테이너의 RPM DB에
공개키를 가져온 뒤 `rpm -Kv`로 서명을 확인하고 커널을 `--nodeps --noscripts --notriggers`로
설치합니다. 이 방식은 커널 이미지·모듈·RPM 메타데이터 검증을 위한 파일시스템을 만들며,
일반 설치 프로그램·dracut·GRUB 설정까지 정상 수행했다고 의미하지 않습니다.

기존 작업 디렉터리에서 최종 배포 바이너리로 `prepare.py`를 다시 실행하면 캐시된 커널/RPM
파일시스템을 바탕으로 collector·검증 PID 1·initramfs를 다시 만듭니다. 이어서 두 커널 VM을 다시
실행해 **최종 바이너리 SHA-256**과 baseline의 일치를 확인합니다. 이전 빌드의 VM 결과로 새
릴리스를 검증했다고 주장하지 않습니다.

보존할 증거는 `input-provenance.json`, `rpm-signature-install.log`, 각 실행의 `command.json`,
`serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json` 및 두 SBOM과 체크섬입니다.
provenance에는 RPM·커널·initramfs·PID 1·collector 해시와 Oracle/QEMU 이미지 ID가 남습니다.
별도 배포 검증 보고서로 이 자료와 배포 압축파일의 SHA-256을 연결합니다.

## 게스트 준비 계약

검증용 initramfs에는 Oracle Linux 8.2 파일시스템, 실제 설치된 두 커널의 RPM DB,
`/boot` 커널 이미지, `/lib/modules` 두 트리, 검증할 `/koda-bom`, 이 harness의 `/init`를 넣습니다.
RHCK와 UEK는 **각각 자신의 커널 이미지로 직접 부팅**해야 합니다.
컨테이너 또는 QEMU user-mode만 실행한 결과는 이 커널 검증의 대체가 아닙니다.

선택적으로 공식 커널 RPM에서 추출한 일치 버전의 모듈을 다음 위치에 둡니다.

```text
/vm-test/modules/<정확한 uname -r>/loop.ko
```

harness는 모듈 SHA-256을 기록한 뒤 `init_module` 시스템 호출로 로드를 시도합니다.
모듈이 없거나 이미 로드됐거나 서명/의존성 문제로 실패한 경우 상태와 오류를 별도로 기록합니다.
실제 로드 확인은 `loadedModulesAfter`와 수집기의 `loadedModules`를 대조합니다.
모듈 미관측을 기능 부재로 판단하지 않습니다.

QEMU에는 외부 네트워크 인터페이스나 가상 디스크를 제공하지 않습니다. 현재 runner는
`-accel tcg,thread=single -cpu max -smp 2 -m 4096`을 사용합니다. 조기 부팅 `getrandom` 대기를
피하려고 시험용 게스트에 `random.trust_cpu=on`을 지정합니다. 이 커널 인수는 운영 서버 설정
권고가 아닙니다. 실제 CPU/가속 모드와 커널·RPM·initramfs·collector 체크섬은 호스트 측 검증
기록으로 별도 보존합니다.

## 실행과 수집

harness는 `/proc`, `/sys`, `/dev`, `/tmp`, `/results`를 마운트하고 합성 hostname을 설정합니다.
별도 baseline으로 uname, `/proc/sys/kernel/osrelease`, OS release, 모듈 전후 목록,
VM 커널 명령줄, collector 체크섬을 기록합니다. 호스트 이름·커널 명령줄은 이 **합성 VM
검증 증거**에만 포함되며 제품의 일반 수집 결과 정책을 바꾸지 않습니다.

collector를 한 번 실행합니다.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

collector가 기본 live-host 모드로 실행되도록 `--target /payload`를 사용하지 않습니다.
0.1.3 검증에서는 수집기의 파일 개수·시간 제한을 0으로 해제합니다. 검증용 PID 1의
별도 11분 watchdog과 호스트 QEMU runner 제한은 시험 자원을 정리하기 위해 유지합니다.
stdout/stderr는 각각 1 MiB로 제한해 별도 파일로 기록하고 종료 코드·시간·오류를
`/results/baseline.json`에 저장합니다. 종료 3은 부분 수집이며 0으로 바꾸지 않습니다.

결과는 serial 출력에서 다음 두 marker 사이의 **base64(gzip(tar))**로 받습니다.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

무압축 합계 256 MiB/10,000 파일을 넘으면 전체 archive 대신 실패 이유를 담은 baseline만
내보냅니다. export 후에는 sync와 poweroff를 시도하며 실패해도 PID 1을 종료해 커널 panic을
유발하지 않고 대기합니다. 게스트 실행 시간이 초과될 경우 호스트 runner가 QEMU를 종료해야 합니다.

## 필수 판정

- baseline uname와 proc release가 일치하며 RHCK/UEK 각각 의도한 버전으로 부팅됐는가.
- `context.json.mode=live-host`와 `runningKernel`이 독립 baseline과 정확히 일치하는가.
- UEK는 `kernelFlavor=UEK`, RHCK는 현재 출력 계약인 `RHCK-compatible`인가.
- native inventory에 두 설치 커널과 각 RPM epoch/version/release/arch/source package가 남았는가.
- 설치 커널 모두를 실행 중으로 취급하지 않고 오직 context의 현재 커널과 구분하는가.
- 모듈 inventory의 `metadata.kernelVersion`/`versionMagic`은 각 설치 트리에 맞고,
  실제 로드 목록은 active 커널의 baseline과 일치하는가.
- 두 SBOM schema·체크섬이 통과하고 수집 실패/부분 상태를 그대로 보고하는가.

## 검증 범위의 한계

- 실제 Oracle RHCK/UEK 게스트 커널을 부팅하지만 물리 x86_64 서버 검증은 아닙니다.
- Oracle Linux 8.2 사용자 공간과 공식 커널을 custom initramfs로 사용합니다. systemd 전체 부팅,
  GRUB 설치, UEFI/Secure Boot, SELinux enforcing 또는 운영 서비스 통합을 검증하지 않습니다.
- `loop` 로드는 단일 실제 모듈의 로드·관측을 확인하는 시험입니다. 모든 드라이버 또는 모든
  하드웨어 구성을 검증하지 않습니다. 비활성 커널의 설치 모듈을 로드된 모듈로 해석하지 않습니다.
- collector 종료 `3`과 `collection.status=partial`을 허용하되 사유를 그대로 보존합니다.
  커널 구분·표준 출력·무결성 검증 통과를 전체 파일의 완전 수집으로 바꾸어 표현하지 않습니다.
