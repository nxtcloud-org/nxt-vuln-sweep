# AGENTS.md (2026-11-11_apache_httpd-2-4-71)

이 폴더의 취약점을 다루는 에이전트 지침입니다. 리포 루트 [AGENTS.md](../AGENTS.md)의 절대 규칙이 항상 먼저이고, 이 문서는 이 취약점에만 해당하는 내용을 더합니다. 둘이 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.

- 사람용 요약: [README.md](README.md)
- 판정 기준표: [criteria.toml](criteria.toml)
- 작업 브랜치: `set/2026-11-11_apache_httpd-2-4-71`

## 이 취약점

- Apache httpd 2.4.71(2026-11-11)로 고친 CVE 3건입니다(mod_http2, mod_md, mod_vhost_alias).
- 판정기가 다루는 제품: criteria `[software.httpd]`(httpd, apache2 바이너리, 컨테이너 포함)
- 수집기: SW 레코드(2026.11.3). `min_collector = "2026.11.3"`
- 2.4.69에서 고친 CVE 20건(2026-10-01)은 이 폴더 범위가 아닙니다. 고객이 2.4.68 이하를 쓰면 보고서 권고에 그 사실만 적습니다.

## 점검 절차

```bash
V=2026-11-11_apache_httpd-2-4-71; C=<고객>
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
- 인터넷용 ALB/NLB 대상으로 등록된 서버를 먼저 봅니다.
  - ALB는 클라이언트와 HTTP/2로 통신해도 대상(httpd)에는 대상 그룹 프로토콜 버전(기본 HTTP1)으로 보냅니다. 대상 그룹이 HTTP2, GRPC일 때만 httpd가 h2를 받습니다(`aws elbv2 describe-target-groups`, 읽기 전용).
  - NLB(TCP 통과)는 클라이언트 연결이 그대로 옵니다.
  - 확인하지 않았으면 보고서에 등록 사실만 씁니다.
- Elastic Beanstalk 환경 중 Apache를 프록시로 쓰는 플랫폼은 플랫폼 버전 갱신으로 고칩니다. AWS 공지로 확인합니다.
- ECS(Fargate), ECR 이미지 안의 httpd는 수집기가 보지 못합니다. `[[extra_unscanned]]`에 적습니다.

수집 후 (`hosts/<id>.tsv`)
- `SW httpd` 실행 중 줄의 플래그에서 `files=0`이면 설정 파일을 못 찾은 것입니다(비표준 경로, `-d` 옵션). 모듈 목록(mods)은 그래도 유효합니다. h2, md_conf, vhost_alias_conf가 0으로 나오므로, 모듈이 있는데 files=0이면 조건 판정을 사람이 확인합니다.
- `mods=none`은 공유 모듈이 하나도 안 보인 것입니다(정적 빌드 가능성). 조건 판정을 믿지 말고 비고에 적습니다.

## 판정 검토 포인트

- 배포판 패키지
  - 배포판 공지(distro_fixed)에 수정 패키지가 있는데 설치 버전이 낮으면 P1(`배포판 수정 패키지 미적용`)입니다.
  - 공지 자료가 없는 CVE가 남으면 P2입니다. RHEL의 CVE-2026-106023, 109163이 여기에 해당합니다(2026-11-19 Red Hat 자료 없음).
  - os_id가 기준표에 없는 배포판(Rocky, Alma, Oracle Linux, CentOS Stream 등)은 모두 P2로 나옵니다. 해당 배포판 공지를 확인해 비고에 적고, 반복해서 나오면 distro_fixed에 추가합니다.
- RHEL은 mod_http2 패키지 버전으로 CVE-2026-119618을 판단합니다. PKG 줄에 mod_http2가 없으면 판단하지 못해 P2입니다(모듈이 올라와 있다면 패키지 이름이 다른 경우).
- 실행 파일 교체 후 미재기동(`EXE_DELETED`)은 패키지 버전과 무관하게 P2 이상입니다. 권고에 재시작을 적습니다.
- 공식 httpd 이미지와 소스 빌드는 버전 번호로 판정합니다(2.4.71 이상이면 범위 밖).

## 보고 문안 가이드 (notes.toml)

key_findings에 넣을 것
- P1 서버: 서버명, httpd 버전과 패키지, 해당 CVE와 모듈, 인터넷용 LB 대상 여부
- mod_http2와 h2를 켠 서버는 따로 적습니다(critical, RCE)
- P2 서버: 배포판과 확인하지 못한 CVE
- httpd가 없는 고객이면 "Apache httpd 미사용"을 한 줄로

recommendations에 넣을 것
- 배포판 수정 패키지를 적용하고 httpd를 재시작합니다. RHEL은 mod_http2 패키지도 함께 올립니다.
- 소스 빌드와 컨테이너는 2.4.71 이상으로 올립니다.
- 쓰지 않는 모듈(mod_http2, mod_md, mod_vhost_alias)은 정리를 검토합니다. 결정은 고객이 합니다.
- 2.4.68 이하를 쓰면 2.4.69에서 고친 CVE 20건도 함께 해당한다는 점을 적습니다.

쓰지 말아야 할 표현
- `조건 해당`을 "공격 가능 확정"으로 쓰지 않습니다. "해당 모듈 사용 중"으로 씁니다.
- "실제 악용 중"이라고 쓰지 않습니다. 공식 출처에 악용 보고가 없습니다(2026-11-19).

## 기준표 갱신 (원문이 바뀔 때)

- Apache 페이지(https://httpd.apache.org/security/vulnerabilities_24.html)는 curl 기본 요청으로 받아집니다. 릴리스별 절(Fixed in Apache HTTP Server 2.4.x) 안에 CVE, 심각도, Affects가 있습니다.
- CVE 레코드(CNA apache)에는 CVSS가 없고 CISA ADP 점수가 있습니다(`containers.adp[].metrics`).
- 배포판 상태
  - Amazon Linux: https://alas.aws.amazon.com/AL2/alas.rss , https://alas.aws.amazon.com/AL2023/alas.rss 에서 httpd 공지를 찾고, 공지 페이지에서 패키지 NVR을 읽습니다. CVE별 Not Affected는 https://explore.alas.aws.amazon.com/<CVE>.html 표
  - Ubuntu: https://ubuntu.com/security/notices/USN-9090-1.json 의 release_packages
  - Debian: https://security-tracker.debian.org/tracker/<CVE> (bookworm은 LTS라 DLA 번호)
  - Red Hat: https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json 의 affected_release(수정 패키지)와 package_state
- 새 배포판 공지가 나오면 `[[software.httpd.distro_fixed]]`에 항목을 추가하고 `revision`을 확인 날짜로 바꿉니다. README 배포판 표도 고칩니다.
- `_core/sweep index`로 색인을 갱신합니다.

## 하지 말 것

- httpd 바이너리를 실행하지 않습니다(`httpd -M`, `apachectl -t -D DUMP_MODULES` 포함). 모듈은 프로세스 메모리 맵으로 봅니다.
- 설정 파일 내용(가상 호스트 이름, 경로)을 출력하거나 결과 폴더에 복사하지 않습니다.
- 모듈 비활성화, 재시작을 직접 하지 않습니다. 권고로만 씁니다.
- 이 폴더 파일에 고객명, 서버명, 점검 결과 수치를 쓰지 않습니다.
