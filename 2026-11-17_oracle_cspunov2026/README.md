# Oracle Critical Security Patch Update Advisory - November 2026

| 항목 | 내용 |
|---|---|
| 취약점 ID | 2026-11-17_oracle_cspunov2026 (취약점 세트) |
| 원문 | https://www.oracle.com/security-alerts/cspunov2026.html |
| 발표 | 2026-11-17 (Rev 1) |
| 종류 | CSPU (Critical Security Patch Update). 분기 누적 CPU를 보완하는 월간 보안 패치 |
| 규모 | 신규 보안 패치 655건, Risk Matrix 21개 |
| 기준표 | [criteria.toml](criteria.toml) |
| 기준표 작성 | 2026-11-18, Rev 1 기준 |

## 요약

- 원문 기준으로 Oracle은 매월 셋째 화요일에 보안 패치를 냅니다. 원문 일정표에서 1월은 분기 누적 CPU이고, 12월, 2월, 3월은 CSPU입니다.
- 서버 인프라 점검에서 주로 해당되는 제품은 Java SE, MySQL, Database Server, WebLogic Server입니다.
- Java SE는 11건 모두 인증 없이 원격 공격이 가능합니다. 서버 환경에도 해당하는 최고 점수는 Java 17 이상 8.1(CVE-2026-114938, Compiler), Java 8과 11은 7.4(CVE-2026-114940, JSSE)입니다.
- WebLogic Server(CVE-2026-91569, TopLink Integration)와 Oracle Platform Security for Java(CVE-2026-114824)는 CVSS 10.0이고 인증 없이 원격 공격이 가능합니다.
- 원문 기준으로 실제 악용 보고는 없습니다.

## 제품별 영향 버전

| 제품 | 영향 버전 | 최고 CVSS |
|---|---|---|
| Oracle Java SE | 8u511b33, 8u511b33-perf, 11.0.33.0.3, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 | 8.1 |
| Oracle GraalVM for JDK | 17.0.21.0.3, 21.0.13.0.3 | 8.1 |
| MySQL Server | 8.4.0-8.4.13, 9.7.0-9.7.4, 26.10 | 9.1 |
| MySQL Cluster | 8.0.0-8.0.50, 8.4.0-8.4.13, 9.7.0-9.7.4, 26.10 | 9.1 |
| Oracle Database Server | 19.3-19.33, 21.3-21.24, 23.4.0-23.26.4 | 9.9 |
| Oracle WebLogic Server | 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0 | 10.0 |
| Oracle HTTP Server | 12.2.1.4.0, 14.1.2.0.0 | 7.5 |

나머지 제품군(E-Business Suite, PeopleSoft, Hyperion, Communications 등)은 원문을 봅니다. 이 기준표에는 서버 인프라 점검에 쓰는 제품만 옮겼습니다.

## Java SE CVE의 적용 환경 (원문 Note)

| Note | 의미 | 해당 CVE |
|---|---|---|
| 1 | 웹 서비스처럼 API로 데이터를 넘기는 경로로만 악용. 서버에 해당 | 114938, 114941, 114942 |
| 2 | 샌드박스 애플릿, Web Start처럼 신뢰할 수 없는 코드를 실행하는 클라이언트 전용 | 86144, 114939, 114947 |
| 3 | 서버와 클라이언트 모두 해당 | 114940, 114943, 114944, 114945, 114946 |

## 판정할 때 주의할 점

- 원문은 지원 중인 버전 가운데 최신 영향 버전만 나열합니다. 같은 계열에서 그 이하 버전은 모두 영향 범위입니다.
- Oracle 버전은 다섯 자리입니다(예: 21.0.13.0.3). 비교도 다섯 자리로 해야 합니다.
  - Corretto의 CSPU 빌드는 네 번째 자리를 올립니다(예: 21.0.13.1, 2026-11-17 빌드). 2026-11-18 현장 점검에서 확인했습니다.
- Java 8은 Oracle(8u511)과 OpenJDK 계열(8u512)의 업데이트 번호가 1 다릅니다.
- 2차 보도에서는 CVE-2026-114938을 Java4Shell이라고 부르고, AVX-512 VBMI를 지원하는 x86 CPU(Ice Lake 이후, Zen 4 이후)에서 악용된다고 설명합니다.
  - Oracle 원문에는 CPU 조건이 없습니다. 판정에는 쓰지 않고 우선순위 참고로만 씁니다.
- MySQL 8.0 Server는 영향 목록에 없습니다(지원 종료). Cluster 8.0은 목록에 있습니다.

## 원문 확인 방법

- WebFetch와 curl은 403이 나옵니다. 사용자 브라우저(Claude in Chrome)로 열어 JavaScript로 표를 추출했습니다.
- 표 구조는 다음과 같습니다.
  - 첫 표가 "Affected Products and Versions"입니다.
  - 그 뒤 첫 행에 `CVE ID`가 들어간 표가 Risk Matrix입니다. 표 바로 앞의 h3/h4 제목이 제품군 이름입니다.
  - 열 순서는 표마다 다릅니다. Product 열이나 Package and/or Privilege Required 열이 있는 표가 있으므로, 헤더를 보고 열 위치를 계산해야 합니다.
- 브라우저 확장의 출력 필터가 `key=`, `auth` 같은 문자열을 가립니다. 추출 결과의 키 이름에 이런 단어를 쓰지 않습니다.

## 이 취약점 점검하기

수집기 변경: 없음. 기본 수집기가 Java(컨테이너 포함), MySQL, Oracle Home(DB, Client, WebLogic)을 모두 잡습니다.

```bash
V=2026-11-17_oracle_cspunov2026; C=<고객>
_core/sweep init $C                         # 처음 한 번, config.env 채우기
_core/sweep inventory $C $V
_core/sweep ssm $C $V linux <시범 1대>      # 시범 결과 확인 후 전체
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep judge $C $V
_core/sweep notes $C $V                     # notes.toml 작성
_core/sweep export $C $V
```

추가 확인 사항
- RDS 엔진이 oracle-* 또는 mysql이면 엔진 버전을 영향 버전과 대조합니다. AWS가 패치 버전을 제공하는지도 확인합니다(api/<리전>/rds.json).
- Aurora MySQL은 AWS 자체 버전 체계라 Oracle 공지 버전과 바로 비교하지 않습니다. AWS 보안 공지를 따로 봅니다.
- Oracle JDK 8 영향 서버는 보고서 권고에 라이선스 조건을 적습니다. 8u202 이후 업데이트는 상용 구독이 필요하므로 OpenJDK 계열 전환을 검토 사항으로 둡니다.

## 다음 일정 (원문 기준)

| 날짜 | 종류 |
|---|---|
| 2026-12-15 | CSPU |
| 2027-01-19 | CPU |
| 2027-02-16 | CSPU |
| 2027-03-16 | CSPU |
