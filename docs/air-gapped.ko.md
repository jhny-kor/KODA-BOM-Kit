# 폐쇄망 실행과 결과 확인

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="air-gapped.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 폐쇄망 배포본은 Linux x86_64(amd64), 커널 3.2 이상용입니다. 공식 릴리스의 압축파일과 짝이 맞는 `.tar.gz.sha256`을 반입합니다. 대상 서버에 Go·Python·Docker·jq를 추가 설치할 필요가 없습니다. NOTICE에는 원저자 jhny-kor와 공식 저장소가 기록됩니다.

[릴리스 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 검증과 압축 해제

같은 버전 압축파일 한 개와 체크섬을 실행 가능한 서버 로컬 폴더에 둡니다. 압축 해제 전에 아카이브를, 해제 후 내부 파일을 확인합니다. 체크섬은 전달된 바이트를 검증하므로 신뢰한 공식 릴리스에서 받습니다. USB가 noexec라면 실행 가능한 로컬 파일시스템으로 복사합니다.

```bash
set -- koda-bom-linux-amd64-0.1.8-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.8 archive.' >&2
fi
```

## 서버 환경 확인

아키텍처, 실행 중 커널과 `doctor`를 확인합니다. `supported=true`는 실행 전제조건을 통과했다는 뜻입니다. `doctor.kernel`과 `context.json.runningKernel`이 관측한 커널 버전입니다. `kernelFlavor=unknown/unconfirmed`여도 버전은 기록될 수 있습니다. root 권한은 DMI·BMC·프로세스·컨테이너의 관측 범위를 넓힙니다.

```bash
uname -m
uname -r
./koda-bom doctor
```

## 수집 범위 선택

인수 없이 `koda-bom`을 실행하면 `bom-output/`의 새 폴더에 병합본 `bom.cdx.json`과 `boms/`의 개별 문서 7종을 생성합니다. AI-BOM 이름은 `aibom.cdx.json`입니다. 실제 내용과 완전성은 읽을 수 있는 로컬 증적에 따라 달라집니다. Qwen은 실제 모델 경로를 지정합니다. H100 정보는 HBOM에서 확인합니다. 모델 설정·헤더·설치 패키지로 현재 GPU 할당이나 실제 서빙 설정을 확정할 수 없습니다.

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

디렉터리 수집은 `--no-context`를 적용합니다. 결과 부모 폴더는 입력 범위 밖에 둡니다. 스크립트는 `/`를 거부하며 단일 대상의 `--exclude-dir`는 상대 경로를 지원합니다. 여러 대상은 서로 겹치지 않아야 하고 제외 디렉터리는 절대 경로로 지정합니다. 파일 수·시간 제한은 전체 대상이 공유합니다. 범위 밖 의존성은 미관측일 수 있습니다.

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## 라이브패치 수집

선택 helper는 기존 Ksplice·Uptrack·Canonical 클라이언트를 조회하고 증적을 정제한 뒤 scan을 실행합니다. 정제된 증적은 결과 폴더 옆에 보존합니다. 종료 직후 `$?`를 저장합니다. 클라이언트 조회는 30초, 실효 커널 조회는 10초로 제한하며 scan 제한을 해제해도 유지됩니다. 기존 클라이언트·daemon의 통신은 별도 동작입니다.

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## 제한과 종료 코드

기본은 채택한 일반 파일 1,000,000개, 30분입니다. `--max-files 0 --timeout 0`으로 두 제한을 해제하고 Ctrl+C로 중단할 수 있습니다. 권한·제외·링크 경계·파일당 2 GiB·이미지 해제 제한은 적용됩니다. `--no-containers`는 컨테이너와 미사용 이미지를, `--no-images`는 중지 컨테이너와 미사용 이미지를 제외합니다. 0은 완료, 3은 결과가 있는 부분 수집, 2는 실패입니다. 다른 비정상 종료 코드도 원인을 확인합니다.

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## 실제 결과와 무결성 확인

명령이 출력한 실제 결과 폴더를 사용합니다. helper는 doctor와 증적 출력 뒤 마지막 줄에 결과 경로를 표시합니다. `result`를 이 경로로 설정합니다. root가 만든 파일은 확인에도 sudo가 필요할 수 있습니다. 루트와 컨테이너·이미지별 체크섬을 검사하고 부분 수집 사유를 함께 보관합니다.

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## 수집·패치 상태 읽기

`collection.json`은 `status`, `packageCount`, `packageTypes`, `limits`, `filesystemFileCount`, `issues`, 호스트 식별·출처·무결성·컨테이너 상태를 기록합니다. 파일 수는 사전 탐색에서 채택한 일반 파일 수입니다. `file_limit_exceeded`에는 `limit`와 `observed`가 있습니다. `context.json`은 커널·프로세스·소켓·서비스·설정·라이브패치를, `assets.json`은 장치·펌웨어·인증서 증적을 담습니다.

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied`는 커널 직접 관측, `reported-applied`는 클라이언트 보고입니다. `disabled`·`transitioning`은 해당 상태를 유지합니다. `stale`·`identity_mismatch`·`unknown`은 추가 증거가 필요합니다. `reportedState`에 과거 보고가 남을 수 있으므로 현재 상태와 `patches[].state`를 함께 봅니다. 24시간 초과, 다른 부팅·커널, 허용 범위를 넘는 미래 시각은 현재 적용 근거가 될 수 없습니다. Canonical Last-Check/CheckState도 검사합니다. 미관측과 `not-reported-patched`는 커널·공급자 증적과 함께 해석합니다.

`integrity.findings[].state=modified`·`missing`은 내용 불일치·누락입니다. `bindScope=all-interfaces`는 바인딩 주소이며 방화벽 외부 노출은 별도 확인합니다. `unidentifiedExecutables`는 패키지 연결을 찾지 못한 항목입니다. `reboot.recommended=not_observed`는 재부팅 신호 미관측입니다. 식별정보·컨텍스트·한계를 함께 검토합니다.

## 공급사 대조와 보관

WAR·EAR 공급사 SBOM에는 실제 산출물 SHA-256이 필요합니다. 해시 누락·불일치는 종료 2입니다. `reconcile.json`과 부분 수집 사유를 확인합니다. 정제 라이브패치 증적을 포함한 부모 폴더 전체를 보관하고 반출 압축파일 체크섬을 계산합니다.

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## 업로드와 후속 분석

호환 Tracker에는 `sbom.cdx.json` 또는 `sbom.spdx.json`을 제출합니다. 컨테이너·이미지는 각각의 표준 SBOM이 있습니다. collection·context·Syft 인벤토리는 부가 증적으로 보관합니다. 업로드 시간 제한은 별도 설정입니다. 수집 결과는 권고와 후속 대조할 입력이며 현재 패치 효과·특정 CVE 조치 완료는 별도 증거로 확인합니다. 각 릴리스와 과거 VM 시험 범위는 검증 기록을 참고합니다.

## 관련 문서

[폐쇄망 실행과 결과 확인](air-gapped.ko.md) · [빌드·검증과 증거 구분](verification.ko.md) · [검증 결과 기록](검증결과.ko.md)
