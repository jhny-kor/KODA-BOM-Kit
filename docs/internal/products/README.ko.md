# 제품 증거 수집기

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <strong>한국어</strong>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit의 `Collect(context.Context, root string, paths []string)`는 사전 점검된 상대 경로 일반 파일 목록을 받습니다. 파일 탐색, 설치 프로그램 실행, 아카이브 추출, 서버 접속, 환경·설정 비밀 읽기를 수행하지 않습니다. `os.OpenRoot`로 경로 해석을 제한하고 절대 경로나 상위 디렉터리 이동 요소가 있는 입력을 거부합니다. 파일 내용과 아카이브 메타데이터 읽기에 상한이 있습니다. 빈 경로 목록은 파일 탐색을 수행하지 않습니다.

## 인정하는 정적 증거

- JDK/JRE `release` 파일의 허용된 version·runtime·build·vendor·architecture 필드.
- Tomcat `catalina.jar`의 `ServerInfo.properties`와 `MANIFEST` 버전 교차 확인.
- WebLogic `weblogic.jar`의 제품 매니페스트와 현재 설치 홈의 `inventory/ContentsXML/comps.xml` 구성 요소 식별 정보. 패치 ID는 관측값으로 보존합니다. 일반 XML이나 `.patch_storage` 항목은 CPU/PSU 패치 적용을 입증하지 못하므로 `patchState`는 `unknown`입니다.
- 설치된 제품 모듈 아래에 있는 JBoss EAP/WildFly 제품 릴리스 매니페스트.
- 제품별 내장 버전 시그니처가 있는 OpenSSH, OpenSSL, PHP, Node.js ELF 파일. Syft를 보완하는 분류이며 모든 stripped·사용자 정의 바이너리의 식별을 보장하지 않습니다. 네이티브 스캔 입력 상한은 32 MiB이며 초과 후보는 명시적으로 불완전 처리합니다.

Tomcat, JDK 또는 같은 설치 홈의 WebLogic 메타데이터가 모순되면 충돌로 표시하고 버전을 단정하지 않습니다. 서로 다른 설치 홈은 병합하지 않습니다. 네이티브 라이브러리·클라이언트·서버 아티팩트는 같은 디렉터리의 동일 버전이어도 별도 ID를 유지합니다. CPE 추론이나 CVE 판정은 생성하지 않습니다.

JEUS 제품 및 패치 메타데이터는 **미지원**입니다. 별도 일반 Java 카탈로거가 JAR 라이브러리를 수집할 수 있지만 JEUS 제품 식별이나 적용된 패치 수준을 입증하지는 않습니다.

테스트는 대표 메타데이터 구조를 생성하며 라이선스 제품 이미지를 사용하지 않습니다. 상용 설치 검증에는 대상 공급업체 fixture가 필요합니다.
