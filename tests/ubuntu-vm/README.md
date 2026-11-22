# Ubuntu 24.04.1 실제 커널 VM 검증

시험용 도구이며 폐쇄망 배포 실행 파일의 의존성이 아닙니다. Ubuntu Base **24.04.1 amd64**와
공식 Ubuntu **6.8.0-47-generic / 패키지 6.8.0-47.47**를 custom initramfs로 직접 부팅합니다.
QEMU user-mode 또는 디렉터리 fixture를 실제 커널 부팅 증거로 사용하지 않습니다.

Ubuntu Base 원본은 보존된 Ubuntu 배포 미러에서 받으며 SHA256SUMS.gpg를 Ubuntu CD Image
Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092`로 검증합니다.
그 인증된 rootfs에 들어 있는 Ubuntu archive keyring으로 공식 Snapshot 서비스의
2024-10-18 noble-updates InRelease를 검증하고, 서명된 Release → Packages.xz → 두 DEB의
SHA-256·크기를 연결합니다. 모든 입력 URL, 체크섬, 서명 로그 및 Docker 이미지 ID를 보존합니다.

빌드 호스트에는 Go, Python 3/jsonschema, Docker, GnuPG(gpg/gpgv)가 필요합니다.
기존 Oracle VM 도구 이미지를 재사용합니다. 대상 서버에는 이 도구들을 설치하지 않습니다.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go`는 Oracle 하네스의 같은 bounded export/독립 baseline 방식을 재사용하며, Ubuntu는
loop 드라이버가 built-in이므로 실제 `dummy.ko`를 로드하여 모듈 관측을 검증합니다.
실행 중인 uname와 proc release, OS, collector SHA, 로드 모듈을 독립 기록하고 두 SBOM의
공식 고정 스키마·체크섬·DEB 원본 버전/source/PURL·설치 커널/모듈을 대조합니다.
새 최종 바이너리를 전달할 때 prepare/run/validate를 다시 실행해야 합니다.

시험용 rootfs는 `dpkg --unpack`으로 원본 DEB를 풀고 실제 dpkg DB를 생성합니다. 강제 의존성
허용 후 unpack 상태로 남기며 일반 apt 설치·설정 완료를 주장하지 않습니다. 전체 systemd,
GRUB, UEFI/Secure Boot, 운영 서비스 및 실제 하드웨어 검증은 별도입니다. QEMU에 NIC/디스크를
연결하지 않으며 Docker도 `--network none`, 읽기 전용 rootfs, capability 제거 상태입니다.
실제 상용/구독 라이브패치를 설치하는 시험은 포함하지 않습니다.

0.1.3은 수집기에 `--max-files 0 --timeout 0`을 전달하여 두 제한을 해제한 상태로
검증합니다. 시험용 PID 1의 별도 11분 watchdog과 호스트 QEMU runner 제한은 유지합니다.

provenance, 서명 로그, dpkg 로그, command.json, serial.log, boot-report.json, baseline.json,
두 SBOM 및 validation.json을 함께 보존합니다. 부분 수집 exit 3을 정상 완전 수집 0으로 바꾸지 않습니다.
