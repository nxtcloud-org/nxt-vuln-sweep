# AGENTS.md (2026-11-17_oracle_cspunov2026)

이 폴더의 취약점을 다루는 에이전트 지침입니다. 리포 루트 [AGENTS.md](../AGENTS.md)의 절대 규칙이 항상 먼저이고, 이 문서는 이 취약점에만 해당하는 내용을 더합니다. 둘이 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.

- 사람용 요약: [README.md](README.md)
- 판정 기준표: [criteria.toml](criteria.toml)
- 작업 브랜치: `set/2026-11-17_oracle_cspunov2026`

## 이 취약점

- Oracle Critical Security Patch Update Advisory - November 2026 (CSPU, Rev 1, 2026-11-17). 신규 보안 패치 655건
- 판정기가 다루는 제품
  - Java SE와 GraalVM: Corretto, Temurin, OS 패키지 OpenJDK 같은 파생 빌드 포함
  - MySQL Server, Cluster
  - Oracle Home: Database, Client, WebLogic/FMW
- 그 밖의 제품군(E-Business Suite, PeopleSoft, Hyperion 등)은 기준표에 없습니다. 고객이 쓰고 있다고 하면 사용자에게 알리고 원문으로 따로 봅니다.
- 수집기: 기본 수집기로 충분합니다(변경 없음).

## 점검 절차

```bash
V=2026-11-17_oracle_cspunov2026; C=<고객>
_core/sweep init $C
_core/sweep inventory $C $V
_core/sweep ssm $C $V linux <시범 1대>
_core/sweep ssm $C $V windows <시범 1대>
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep judge $C $V
_core/sweep notes $C $V
_core/sweep export $C $V
```

### 단계별 추가 확인

자산 조회 후 (`api/<리전>/` 파일)
- RDS 엔진이 `oracle-*`이면 엔진 버전을 확인합니다(형식 예: `19.0.0.0.ru-YYYY-MM.rur-YYYY-MM.r1`).
  - 기준표의 Database 영향 버전(19.3-19.33 등)과 대조합니다. RU 번호와 AWS 엔진 버전 표기의 대응은 AWS 문서로 확인합니다.
  - AWS가 패치된 엔진 버전을 내놨는지는 `aws rds describe-db-engine-versions --engine <엔진> --query 'DBEngineVersions[].EngineVersion'`(읽기 전용)으로 봅니다.
- RDS 엔진이 `mysql`이면 기준표 [mysql] 범위와 대조합니다.
- `aurora-mysql`은 AWS 자체 버전 체계라 Oracle 공지 버전과 바로 비교하지 않습니다. AWS 보안 공지를 따로 확인하고, 보고서에는 "AWS 공지 확인 필요"로 적습니다.
- `AutoMinorVersionUpgrade`가 켜져 있다는 것만으로 패치됐다고 판단하지 않습니다.
- Lambda 런타임이 `java*`이면 AWS 관리형 런타임이라 AWS가 패치합니다.
  - 런타임 업데이트 모드는 `aws lambda get-runtime-management-config`(읽기 전용)로 확인합니다.
  - 컨테이너 이미지 Lambda는 이미지의 JDK를 확인해야 하므로 미점검 대상에 적습니다.
- ECR에만 있고 서버에서 실행되지 않는 이미지는 수집기가 보지 못합니다. notes.toml `[[extra_unscanned]]`에 적습니다.

수집 후
- Windows 서버는 프로세스 이름이 java.exe가 아니어도 JVM이 돌 수 있습니다(Tomcat, Elasticsearch 서비스). PROC, PROCRUN 줄이 있는지 확인합니다.
- 서버에 WebLogic Home(OREG 줄)이 있으면 아래 "판정 검토 포인트"의 WebLogic 항목을 따릅니다.

## 판정 검토 포인트

`_core/sweep judge` 다음에 findings.csv에서 확인합니다.

- Java 버전은 다섯 자리로 비교합니다.
  - Oracle JDK 21.0.13.0.3은 최신 영향 버전 그 자체라 영향입니다. 10월 배포본을 받아 둔 것이므로 패치된 것으로 보지 않습니다.
  - Corretto 21.0.13.1, 17.0.21.1처럼 네 번째 자리가 오른 빌드는 11월 패치 빌드라 범위 밖입니다. 정상 판정입니다.
- Java 8은 Oracle 8u511, 파생 빌드 8u512가 최신 영향 버전입니다. criteria의 `derivative_latest_affected`가 처리합니다.
- vendor가 `IBM Java`인 행(Cognos, DB2 번들 등)은 해당 없음으로 분류됩니다. 보고서에는 "IBM 보안 공지로 별도 확인"으로 남깁니다.
- vendor가 `미상`인 행은 경로와 버전 출력을 직접 봅니다.
  - 경로에 jdk118, jre1.2.2처럼 1.x 버전이 보이면 EOL로 분류됩니다.
  - 버전을 못 읽은 행은 `확인 필요`입니다.
- detail에 `deleted`가 있는 행은 JDK 교체 후 재기동하지 않은 JVM입니다. 실제 실행 버전은 디스크 버전보다 낮을 수 있으니 보고서 권고에 재기동을 적습니다.
- Oracle Home
  - Client, Database 11.x, 12.x, 18.x는 EOL로 분류됩니다.
  - WebLogic/FMW Home은 판정기가 `확인 필요`로 남깁니다. OREG의 distribution version을 기준표 WebLogic 영향 버전과 대조합니다.
  - OPATCH 목록은 원문 "Affected Products and Patch Information" 표의 Patch Availability Document(My Oracle Support)에서 이번 패치 번호를 찾아 대조합니다.
  - 이 공지의 WebLogic 최고 점수는 CVSS 10.0입니다. 실행 중인 영향 버전이 있으면 P1로 따로 보고합니다.
- MySQL 8.0 Server는 영향 목록에 없는 지원 종료 버전이라 EOL로 표시됩니다. MySQL Cluster 8.0이면 영향입니다(수집 결과에 Cluster 구성 요소가 보이면 확인). MariaDB는 해당 없음입니다.

## 보고 문안 가이드 (notes.toml)

key_findings에 넣을 것
- P1 서버: 서버명, Oracle JDK 버전, 실행 중인 서비스(Tomcat 경로, 서비스명)
- P2 요약: 파생 빌드 종류와 버전
- 공지 대상인데 발견되지 않은 제품: Database Server, WebLogic, MySQL 8.4/9.7 등
- RDS, Lambda 확인 결과
- P1, P2 서버의 인터넷용 LB 대상 등록 사실. 등록 포트가 해당 서비스 포트인지는 확인하지 않았다고 밝힙니다.

recommendations에 넣을 것
- P1 패치 일정 검토
  - Oracle JDK 8 영향 서버는 라이선스 조건을 함께 적습니다. 8u202 이후 업데이트는 상용 구독이 필요하므로 OpenJDK 계열(예: Amazon Corretto) 전환을 검토 사항으로 둡니다.
- P2 서버는 배포판별 11월 패치 빌드 출시를 확인한 뒤 적용합니다.
  - 보고서 작성 시점에 Adoptium, Debian, Red Hat 등의 공개 릴리스 페이지에서 출시 여부를 확인해 적습니다.
  - 확인하지 못했으면 미확인이라고 씁니다.
- CentOS 7처럼 지원이 끝난 OS는 OS 패키지 업데이트가 불가능하다는 점을 적습니다.
- 재기동이 필요한 서버(deleted JVM)와 미사용 EOL JDK 정리를 적습니다.
- 미점검 서버의 후속 점검 계획을 적습니다.

쓰지 말아야 할 표현
- CVE-2026-114938을 Java4Shell이라고 부르거나, AVX-512 VBMI CPU 조건을 판정 근거처럼 쓰지 않습니다. 둘 다 2차 보도 내용입니다.
- 꼭 언급해야 하면 Java 17 이상 P1, P2 서버의 CPU 정보와 함께 "일부 보도에 따르면, Oracle 원문에는 조건 없음"이라고 밝힙니다.

## 기준표 갱신 (원문이 개정될 때)

- 원문 맨 아래 Modification History에서 개정 번호(Rev)를 확인합니다.
- Rev가 올라갔으면 이 브랜치에서 고칩니다.
  - 바뀐 영향 버전, CVE를 criteria.toml에 반영하고 `revision`을 올립니다.
  - README.md의 기준표 작성일을 고칩니다.
  - `_core/sweep index`로 색인을 갱신합니다.
- 원문 읽는 방법
  - WebFetch와 curl은 403입니다. User-Agent 위장으로 우회하지 않습니다. Claude in Chrome으로 페이지를 열고 JavaScript로 표를 추출합니다.
  - 첫 표가 Affected Products and Versions입니다(제품, 버전, Patch Availability Document).
  - 첫 행에 `CVE ID`가 들어간 표가 Risk Matrix입니다. 표 앞의 가장 가까운 h3/h4가 제품군 이름입니다.
  - 열 위치는 표마다 다릅니다. Product 열, Package and/or Privilege Required 열이 있는지 헤더를 보고 계산합니다. 열 번호는 0부터 셉니다.
    - Remote Exploit without Auth 열 = 3 + (Product 열 있음) + (Package 열 있음)
    - Base Score는 그 다음 열입니다.
    - Supported Versions Affected는 Base Score에서 9칸 뒤, Notes는 그 다음 열입니다.
  - 아래 문제를 피합니다.
    - 확장의 출력 필터가 `key=`, `auth`가 들어간 문자열을 가립니다. 결과 객체의 키 이름과 구분자에 이런 단어를 쓰지 않습니다.
    - 긴 문자열 하나로 돌려주면 잘립니다. 행마다 배열 원소로 돌려줍니다.
  - 각 Risk Matrix 아래 Notes 문단에서 Java SE의 Note 1-3 의미를 확인해 criteria의 `scope`(server, client, both)를 정합니다.

## 다음 Oracle 공지를 등록할 때

- 다음 일정(원문 기준): 2026-12-15 CSPU, 2027-01-19 CPU
- URL 형식: CPU는 `cpu<월3자><연도>.html`(예: cpujan2027)입니다.
  - CSPU는 이번 공지(cspunov2026)를 보고 `cspu<월3자><연도>.html`로 추정한 것입니다.
  - 실제 주소는 Oracle Security Alerts 목록 페이지에서 확인합니다.
- `_core/sweep new 2026-12-15_oracle_cspudec2026`로 폴더를 만듭니다. 이 폴더의 criteria.toml 구조와 AGENTS.md의 원문 읽는 방법을 출발점으로 씁니다.
- 값은 전부 새 원문으로 다시 확인합니다. 특히 아래 값은 매번 바뀝니다.
  - Java 계열별 최신 영향 버전
  - Java 8 파생 빌드 번호
  - MySQL 범위
  - Database RU 범위
  - CVE 목록

## 하지 말 것

- 2차 보도(뉴스, 블로그)의 값을 criteria.toml에 넣지 않습니다.
  - 예: 대체 빌드 번호, CVE와 패치의 연결, CPU 조건
- MariaDB, IBM Java를 이 공지의 영향으로 보고하지 않습니다.
- RDS 자동 마이너 업그레이드 설정만 보고 패치됐다고 보고하지 않습니다.
- 이 폴더 파일에 고객명, 서버명, 점검 결과 수치를 쓰지 않습니다. 현장에서 알게 된 내용은 일반화해서 적습니다.
