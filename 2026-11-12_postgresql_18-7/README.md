# PostgreSQL 18.7, 17.12, 16.16, 15.20, 14.25 업데이트 릴리스 (2026-11-12)

| 항목 | 내용 |
|---|---|
| 취약점 ID | 2026-11-12_postgresql_18-7 |
| 원문 | https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/ (릴리스 공지), https://www.postgresql.org/support/security/ (CVE별 영향 계열, 수정 버전) |
| 발표 | 2026-11-12 |
| 종류 | 취약점 세트 (PostgreSQL 정기 업데이트 릴리스) |
| 규모 | CVE 52건 (서버 46, 클라이언트 도구 6) |
| 기준표 | [criteria.toml](criteria.toml) |
| 기준표 작성 | 2026-11-19, PostgreSQL 보안 페이지 기준 |
| 에이전트 지침 | [AGENTS.md](AGENTS.md) (점검 절차, 판정 검토, 기준표 갱신) |
| 후보 Issue | KISA 보안공지 PostgreSQL 제품 보안 업데이트 권고 (2026-11-17, CVE 25건 인용) |

## 요약

- PostgreSQL 개발 그룹이 지원 중인 모든 계열의 업데이트(18.7, 17.12, 16.16, 15.20, 14.25)를 내고 보안 취약점 52건을 고쳤습니다.
  - KISA 공지는 이 중 CVSS 8.8인 25건을 인용합니다. 기준표는 릴리스 공지의 52건 전체를 담았습니다.
- 서버 취약점 대부분(CVSS 8.8 29건)은 데이터베이스 계정이 있어야 공격할 수 있습니다(PR:L).
  - 성공하면 데이터베이스를 실행하는 OS 계정 권한으로 임의 코드가 실행됩니다.
  - 공격자가 객체 생성 권한(object creator)이나 일반 DB 사용자 권한만 가져도 되는 항목이 많습니다. 여러 사용자가 쓰는 DB, 애플리케이션 계정이 탈취된 경우를 우선 봅니다.
- 인증 없이 공격할 수 있는 항목(PR:N)은 5건입니다.
  - 서버 2건
    - CVE-2026-116322: 18 계열, 인증 전 취소 요청으로 서버 재시작(CVSS 5.3)
    - CVE-2026-120145: 공격자가 장악한 발행 서버가 superuser 소유 구독으로 코드 실행(사용자 동작 필요, CVSS 8.8)
  - 클라이언트 도구 3건: 조작된 덤프 파일이나 서버 응답(CVE-2026-116314 pg_restore, CVE-2026-116330 pg_dump와 psql, CVE-2026-16240 pg_basebackup)
- 실제 악용: 릴리스 공지와 보안 페이지에 언급이 없습니다.
- PostgreSQL 14는 이번 14.25가 마지막 릴리스입니다(지원 종료). 13 이하는 이미 지원이 끝나 수정 버전이 없습니다.

## 계열별 영향 버전

| 계열 | 영향 버전 | 수정 버전 | 비고 |
|---|---|---|---|
| 18 | 18.6 이하 | 18.7 | 52건 모두 해당 |
| 17 | 17.11 이하 | 17.12 | |
| 16 | 16.15 이하 | 16.16 | |
| 15 | 15.19 이하 | 15.20 | |
| 14 | 14.24 이하 | 14.25 | 마지막 릴리스(지원 종료) |
| 13 이하 | 전체 | 없음 | 지원 종료. 지원 계열로 업그레이드 |

CVE마다 해당 계열이 다릅니다(예: CVE-2026-116329는 18만, CVE-2026-116328은 18, 17, 16). 기준표의 [[cves]]가 보안 페이지의 Affected 값을 그대로 담고 있습니다.

## 사용 조건이 있는 CVE

| CVE | 조건 |
|---|---|
| CVE-2026-116307, 116309, 116319, 116320, 116326 | PL/Perl(plperl) 사용 |
| CVE-2026-116323 | PL/Tcl(pltcl) 사용 |
| CVE-2026-120147 | dblink 확장 사용 |
| CVE-2026-116308 | dict_int 확장 사용 |
| CVE-2026-120145 | superuser가 소유한 논리 복제 구독 |
| 클라이언트 도구 6건 | pg_dump, pg_restore, psql, pg_basebackup, vacuumdb, reindexdb 사용 |

## 배포판과 AWS 상태 (2026-11-19 확인)

| 대상 | 상태 | 근거 |
|---|---|---|
| Debian 12 (bookworm) | postgresql-15 15.20-0+deb12u1 수정 | DLA-4905-1 |
| Debian 13 (trixie) | postgresql-17 17.12-0+deb13u1 수정 | DSA-6625-1 |
| Amazon Linux 2023 (postgresql15-18), Amazon Linux 2 (postgresql, postgresql14 extras) | Pending Fix | explore.alas.aws.amazon.com |
| RHEL 7-10 | Affected (수정 패키지 없음) | Red Hat Security Data API |
| Ubuntu | needs-triage (수정 패키지 없음) | ubuntu.com/security |
| PGDG 저장소 (apt.postgresql.org, yum.postgresql.org) | 업스트림 버전 그대로 | |
| RDS for PostgreSQL | AWS RDS PostgreSQL 릴리스 노트에 18.7, 17.12, 16.16, 15.20, 14.25가 아직 없음 | docs.aws.amazon.com |
| Aurora PostgreSQL | 확인하지 못함 | |

## 판정할 때 주의할 점

- 배포판 패키지도 PostgreSQL 마이너 버전을 그대로 따라갑니다(예: Debian 15.20-0+deb12u1).
  - 그래서 nginx, httpd와 달리 버전 번호로 판정합니다(`distro_backport = false`).
  - 다만 지원 종료 계열(13 이하)을 배포판이 계속 지원하는 경우(RHEL 8의 postgresql:12, :13 모듈 등)는 배포판이 백포트할 수 있어 P2로 둡니다.
- 확장 관련 CVE는 확장 라이브러리 파일(plperl.so 등)이 설치돼 있으면 조건 해당으로 봅니다. DB 안에서 `CREATE EXTENSION`을 했는지는 접속하지 않아 모릅니다.
- 공식 컨테이너 이미지 postgres:16-alpine에는 plperl, pltcl, dblink, dict_int 라이브러리가 모두 들어 있어 조건 해당으로 나왔습니다(2026-11-19 시험).
- 클라이언트 도구는 DB 서버가 없는 서버(배치, 백업 서버)에도 있습니다. 실행 여부를 보지 않으므로 P3입니다. 백업 자동화에 pg_dump, pg_restore를 쓰는 서버는 보고서에 따로 적습니다.

## 업데이트 시 공식 공지의 추가 조치

- 마이너 업데이트라 덤프와 복원, pg_upgrade 없이 바이너리만 바꾸고 재시작하면 됩니다.
- 공지가 업데이트 후 확인을 권고하는 경우
  - GIN 인덱스 손상이 의심되면 REINDEX
  - pg_trgm의 gist_trgm_ops GiST 인덱스는 REINDEX
  - `missing chunk number` 오류가 보이면 해당 테이블 REINDEX
  - 증분 백업을 쓰면 새 전체 백업
  - 파티션 테이블의 NOT NULL NO INHERIT 제약 확인
  - 길이 없는 bpchar 열의 B-tree 인덱스 REINDEX
- 건너뛴 이전 업데이트가 있으면 그 릴리스 노트의 추가 조치도 해야 합니다.

## 점검

점검 명령과 단계별 추가 확인 사항은 [AGENTS.md](AGENTS.md)에 있습니다. 이 공지는 수집기 2026.11.3 이상이 필요합니다.
