# AGENTS.md (2026-11-12_postgresql_18-7)

이 폴더의 취약점을 다루는 에이전트 지침입니다. 리포 루트 [AGENTS.md](../AGENTS.md)의 절대 규칙이 항상 먼저이고, 이 문서는 이 취약점에만 해당하는 내용을 더합니다. 둘이 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.

- 사람용 요약: [README.md](README.md)
- 판정 기준표: [criteria.toml](criteria.toml)
- 작업 브랜치: `set/2026-11-12_postgresql_18-7`

## 이 취약점

- PostgreSQL 정기 업데이트 릴리스(2026-11-12, 18.7, 17.12, 16.16, 15.20, 14.25)로 고친 CVE 52건입니다.
  - KISA 보안공지(2026-11-17)는 25건만 인용합니다. 기준표는 릴리스 공지의 52건 전체입니다.
- 판정기가 다루는 제품: criteria `[software.postgresql]`(서버), `[software.postgresql-client]`(pg_dump, psql)
- 수집기: SW 레코드(2026.11.3, `core/sw-collector`). criteria의 `min_collector = "2026.11.3"` 때문에 이전 수집기로 받은 결과는 judge가 재수집 대상으로 알립니다.

## 점검 절차

```bash
V=2026-11-12_postgresql_18-7; C=<고객>
_core/sweep init $C
_core/sweep inventory $C $V
_core/sweep ssm $C $V linux <시범 1대>
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep judge $C $V
_core/sweep notes $C $V
_core/sweep export $C $V
```

### 단계별 추가 확인

자산 조회 후 (`api/<리전>/` 파일)
- `rds.json`, `rds_clusters.json`에서 엔진이 postgres, aurora-postgresql인 것을 골라 엔진 버전을 README의 계열별 표와 대조합니다.
  - RDS 마이너 버전 출시는 AWS 문서로 확인합니다: https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-versions.html
  - 2026-11-19 기준 이 문서에 18.7, 17.12, 16.16, 15.20, 14.25가 없습니다. 아직 없으면 보고서에 "AWS 출시 대기"로 씁니다.
  - rds.json의 `autoMinor`(자동 마이너 버전 업그레이드)와 `public`(퍼블릭 접근) 값을 함께 적습니다. Aurora 클러스터(rds_clusters.json)에는 이 값이 없으므로 쓰지 않습니다.
  - RDS, Aurora 결과는 notes.toml `[[extra_unscanned]]` 또는 key_findings에 적습니다(서버별 현황 시트에는 나오지 않음).
- ECS(Fargate), ECR 이미지 안의 PostgreSQL은 수집기가 보지 못합니다. `[[extra_unscanned]]`에 적습니다.

수집 후 (`hosts/<id>.tsv`)
- `SW postgresql` 줄의 버전이 비어 있으면 바이너리 문자열을 못 읽은 것입니다. 경로와 PKG 줄로 버전을 사람이 확인해 비고에 적습니다.
- 실행 중 줄(`pid N`)의 플래그가 `libdir=unknown`이면 실행 파일 경로를 못 읽은 것입니다(권한). 디스크 줄의 플래그를 봅니다.

## 판정 검토 포인트

`_core/sweep judge` 다음에 findings.csv에서 확인합니다.

- 지원 종료 계열
  - 소스 빌드나 컨테이너의 13 이하는 `eol`(실행 중이면 P1)입니다.
  - 배포판 패키지의 13 이하는 P2입니다. 배포판이 그 계열을 아직 지원하는지(RHEL 8 postgresql:12, :13 모듈 등) Red Hat 상태로 확인해 비고에 적습니다.
  - 14는 수정 버전(14.25)이 있지만 마지막 릴리스라 비고에 업그레이드 계획을 적습니다(기준표 `branch_notes`).
- 조건 판단
  - 확장 CVE의 `조건 해당`은 라이브러리 파일이 있다는 뜻입니다. 확장을 DB에 만들었는지는 모릅니다. 보고서에는 "확장 설치됨(사용 여부는 DB 확인 필요)"으로 씁니다.
  - 확장 조건이 없어도 조건 없는 CVE가 30건 이상이라, 영향 버전 서버는 대부분 P1입니다.
- 클라이언트 도구
  - P3로 나옵니다. 백업 서버처럼 pg_dump, pg_restore를 정기적으로 쓰는 서버는 고객 확인 후 비고에 적습니다.
  - DB 서버와 같은 패키지 계열이면 서버 업데이트 때 함께 바뀝니다.
- 컨테이너 안 PostgreSQL은 이미지 태그를 바꿔야 고쳐집니다. 컨테이너 패키지(`dpkg:16.4-1.pgdg120+1` 등)는 비고에 나옵니다.

## 보고 문안 가이드 (notes.toml)

key_findings에 넣을 것
- P1 서버: 서버명, PostgreSQL 버전, 설치 방식(패키지, 컨테이너), 인터넷용 LB 대상 여부
- RDS, Aurora 인스턴스와 엔진 버전, AWS 출시 상태
- 지원 종료 계열(13 이하, 14) 서버
- PostgreSQL이 없는 고객이면 "PostgreSQL 미사용"을 한 줄로

recommendations에 넣을 것
- 같은 계열의 수정 버전(18.7, 17.12, 16.16, 15.20, 14.25)으로 마이너 업데이트하고 재시작합니다. pg_upgrade는 필요 없습니다.
- 업데이트 후 공식 공지의 추가 조치(README "업데이트 시 공식 공지의 추가 조치")를 확인합니다.
- 13 이하와 14는 지원 계열(15 이상)로 메이저 업그레이드 계획을 세웁니다.
- 배포판 패키지가 아직 나오지 않은 경우(Amazon Linux, RHEL, Ubuntu) 배포판 공지를 기다리거나 PGDG 저장소 사용을 검토합니다. 저장소 변경은 고객이 결정합니다.
- DB 계정 권한 점검(불필요한 CREATE 권한, superuser 소유 구독)을 권고합니다. 대부분의 취약점이 DB 계정을 전제로 합니다.

쓰지 말아야 할 표현
- "인증 없이 원격 코드 실행" 같은 표현은 쓰지 않습니다. 서버 RCE 항목은 모두 DB 계정이 필요합니다.
- 확장 `조건 해당`을 "확장 사용 중"으로 쓰지 않습니다.

## 기준표 갱신 (원문이 바뀔 때)

- 원문 읽는 방법
  - 보안 페이지(https://www.postgresql.org/support/security/)는 curl 기본 요청으로 받아집니다. 표의 열은 Reference, Affected, Fixed, Component와 CVSS, Description입니다.
  - 릴리스 공지의 Security Issues 절에 이번 릴리스의 CVE 목록이 있습니다.
  - CVE 레코드(CNA PostgreSQL)의 affected 값도 같은 수정 버전을 씁니다.
- 기준표 값과 원문이 다르면 [[cves]]의 range, fixed, sw(서버, 클라이언트)를 고치고 `revision`을 확인 날짜로 바꿉니다.
- 배포판 상태가 바뀌어도 기준표는 고치지 않아도 됩니다(버전 번호로 판정). README의 배포판 표만 갱신합니다.
- `_core/sweep index`로 색인을 갱신합니다.

## 다음 PostgreSQL 릴리스를 등록할 때

- 정기 릴리스는 2, 5, 8, 11월 둘째 목요일입니다(https://www.postgresql.org/developer/roadmap/).
- 폴더 이름은 `YYYY-MM-DD_postgresql_<최신 계열 수정 버전>`입니다(예: `2027-02-11_postgresql_18-8`). 이 폴더의 criteria.toml을 출발점으로 쓰고, supported_branches와 CVE 값은 새 원문으로 전부 다시 확인합니다.

## 하지 말 것

- 데이터베이스에 접속하지 않습니다(계정 정보를 다루지 않음). `psql`로 확장 목록을 조회하는 일도 하지 않습니다.
- postgres, pg_dump 바이너리를 실행하지 않습니다(버전은 문자열로 읽음).
- RDS 마이너 버전 업그레이드를 직접 하지 않습니다. 권고로만 씁니다.
- 이 폴더 파일에 고객명, 서버명, 점검 결과 수치를 쓰지 않습니다.
