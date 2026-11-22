# 네이티브 플랫폼 관측

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../docs/badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit의 `Collect(ctx)`는 대상에 이미 설치된 도구로 제한된 범위의 관측값을 수집합니다. 고정 명령 인수를 사용하며 명령당 제한 시간은 60초, 출력 제한은 32 MiB입니다. SBOM에 쓰기 전에 필드를 선택합니다. 일련번호, UUID, 사용자 이름, 애플리케이션 전체 경로는 제외합니다. 로컬 경로는 해시된 구성 요소 식별자에만 반영합니다.

macOS에서는 `/usr/sbin/system_profiler`로 하드웨어·소프트웨어·애플리케이션 메타데이터를 얻습니다. 시스템 펌웨어, OS 로더, CPU, 애플리케이션을 출력하며 OS 버전 문자열에 빌드 번호를 보존합니다. 일부 애플리케이션의 버전이나 메타데이터는 없을 수 있습니다.

Windows에서는 프로필을 로드하지 않는 시스템 PowerShell로 CIM computer·BIOS·OS·QuickFixEngineering 레코드와 컴퓨터 전체 및 현재 사용자 uninstall 레지스트리를 읽습니다. OS 빌드와 아키텍처를 보존합니다. QuickFixEngineering은 자체 보고 업데이트만 다룹니다. 레지스트리 인벤토리는 모든 사용자 프로필, Store 앱, 내장 의존성을 열거하지 않습니다. 이러한 제한은 수집 범위 이슈로 기록합니다.

네이티브 macOS 검증은 `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory`로 실행합니다. Windows 파싱 fixture와 교차 컴파일은 소스 구조를 검증합니다. 실제 Windows 실행 검증에는 Windows 대상이 필요합니다.
