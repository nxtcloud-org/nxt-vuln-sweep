# AGENTS.md (2026-11-18_nginx_1-31-9)

이 폴더의 취약점을 다루는 에이전트 지침입니다. 리포 루트 [AGENTS.md](../AGENTS.md)의 절대 규칙이 항상 먼저이고, 이 문서는 이 취약점에만 해당하는 내용을 더합니다. 둘이 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.

- 사람용 요약: [README.md](README.md)
- 판정 기준표: [criteria.toml](criteria.toml)
- 작업 브랜치: `set/2026-11-18_nginx_1-31-9`

## 이 취약점

- nginx.org 보안 릴리스(2026-11-18, 1.31.9 mainline과 1.30.7 stable)로 고친 CVE 10건입니다.
  - nginx.org 공지 목록에는 개정 번호가 없습니다. 기준표의 `revision`은 확인한 날짜로 씁니다.
  - Xint.io의 nginx2root 글은 이 중 5건을 다룹니다. 사용자가 nginx2root라고 부르면 이 폴더입니다.
- 판정기가 다루는 제품: criteria `[nginx]`
  - nginx.org 패키지, 소스 빌드, 배포판 패키지, 컨테이너 안 nginx, 이미지 레이어
  - OpenResty, Tengine, Angie, freenginx, NGINX Plus는 `확인 필요`로 남습니다.
- 수집기: `core/nginx-collector`에서 확장했습니다(scan_linux.sh, scan_windows.ps1 2026.11.2).
  - 새 레코드: NGINX(바이너리), NGXCONF(설정의 지시어 사용 여부), NGXCTL(ingress 컨트롤러), META os_id, META sctp
  - criteria의 `min_collector = "2026.11.2"` 때문에, 이전 수집기로 받은 결과는 judge가 재수집 대상으로 알립니다. Oracle 점검 때 받은 결과로는 판정할 수 없습니다.
- criteria에 `[java]`, `[mysql]`, `[oracle_home]`가 없으므로 JDK, MySQL, Oracle 수집 결과는 이 보고서에 들어가지 않습니다.

## 점검 절차

```bash
V=2026-11-18_nginx_1-31-9; C=<고객>
_core/sweep init $C
_core/sweep inventory $C $V
_core/sweep ssm $C $V linux <시범 1대>
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep judge $C $V
_core/sweep notes $C $V
_core/sweep export $C $V
```

- 같은 고객의 다른 공지 결과(RUN_DIR)가 있어도 hosts/*.tsv를 복사해 쓰지 않습니다. 이 공지 폴더로 다시 수집합니다.

### 단계별 추가 확인

자산 조회 후 (`api/<리전>/` 파일)
- 인터넷용 ALB/NLB의 대상으로 등록된 서버를 먼저 봅니다.
  - NLB(TCP 통과)는 클라이언트의 HTTP/2, HTTP/3 연결이 nginx까지 그대로 옵니다.
  - ALB는 대상 그룹의 프로토콜 버전(ProtocolVersion: HTTP1, HTTP2, GRPC)에 따라 nginx가 받는 프로토콜이 다릅니다. `aws elbv2 describe-target-groups`(읽기 전용)로 확인합니다.
  - 보고서에는 확인한 사실만 씁니다. 대상 그룹 설정을 보지 않았으면 등록 사실만 씁니다.
- EKS 클러스터가 있으면 ingress 컨트롤러를 확인합니다.
  - SSM이 되는 노드는 수집 결과의 NGXCTL 줄로 ingress-nginx 컨테이너가 보입니다.
  - SSM이 없는 노드와 Fargate 파드는 보이지 않습니다. notes.toml `[[extra_unscanned]]`에 적고 고객 확인을 요청합니다. kubectl 조회는 이 리포의 범위가 아닙니다.
- ECS(Fargate)와 ECR 이미지 안의 nginx는 수집기가 보지 못합니다. `[[extra_unscanned]]`에 적습니다.
- Elastic Beanstalk 환경의 EC2는 플랫폼이 nginx를 프록시로 쓰므로 수집 결과에 나옵니다. 플랫폼 버전 갱신은 AWS 공지로 확인합니다.
- CloudFront, ALB 자체는 AWS 관리 서비스라 이 공지와 무관합니다.

수집 후 (`hosts/<id>.tsv`)
- NGXCONF 줄의 `files=0`은 설정 파일을 못 읽은 것입니다. 판정은 `설정 미확인`이 됩니다.
  - master 명령행의 `-c`가 상대 경로이거나 `-p`로 prefix를 바꾼 경우가 많습니다. NGINX 줄 경로와 함께 보고 원인을 비고에 적습니다.
- NGINX 줄의 `EXE_DELETED`는 패키지를 갱신하고 재기동하지 않은 것입니다. 권고에 재기동을 적습니다.
- META sctp는 참고 정보입니다(2차 출처의 연계 시나리오와 관련). 보고서에 쓰려면 아래 "쓰지 말아야 할 표현"을 따릅니다.

## 판정 검토 포인트

`_core/sweep judge` 다음에 findings.csv에서 확인합니다.

- P2(배포판 패키지)는 보고서를 쓰기 직전에 배포판 공지를 다시 확인합니다.
  - Ubuntu: https://ubuntu.com/security/CVE-2026-123007 (릴리스별 상태, USN 번호, 수정 버전)
  - Debian: https://security-tracker.debian.org/tracker/CVE-2026-123007
  - Amazon Linux: https://explore.alas.aws.amazon.com/CVE-2026-123007.html 에서 ALAS 번호를 찾고, ALAS 페이지에서 패키지 NVR을 읽습니다. AL2023은 ALAS2023-2026-3494, AL2(nginx1)는 ALAS2NGINX1-2026-018로 반영했습니다.
  - Red Hat: https://access.redhat.com/security/cve/cve-2026-123007 (상태표는 WebFetch로 안 보이므로 Claude in Chrome)
  - 수정 버전이 나왔으면 criteria `[nginx.distro_fixed."<os_id>"]`에 넣고 `revision`을 확인 날짜로 바꾼 뒤 재판정합니다.
    - 키는 hosts/*.tsv의 META os_id 값입니다(예: `ubuntu-24.04`, `debian-12`, `amzn-2`, `rhel-9`). rhel 계열은 주 버전만 써도 됩니다.
    - `kind`는 Ubuntu, Debian이 `deb`, 나머지는 `rpm`입니다.
  - 배포판 공지가 이 공지의 CVE 중 일부만 고쳤으면(1.31 전용인 CVE-2026-120993 제외) 넣지 말고 사용자에게 알립니다.
- 버전은 세 자리로 비교합니다. Amazon Linux 2023의 수정 패키지는 업스트림 1.30.7 그대로라 버전만으로도 범위 밖입니다.
- 출처 분류
  - nginx.org 패키지: 데비안 계열은 버전 끝에 배포판 코드명이 붙고(예: `1.30.7-1~bookworm`), rpm은 릴리스에 `ngx`가 들어갑니다. P1 대상입니다.
  - 컨테이너 안 nginx는 컨테이너의 dpkg, apk 기록으로 분류합니다. 공식 nginx:alpine 이미지도 apk라 `nginx (Alpine 패키지)`, P2로 나옵니다. 버전이 영향 범위면 이미지를 바꿔야 하는 것은 같습니다.
  - 패키지가 없는 호스트 바이너리는 `소스 빌드 또는 수동 설치`입니다. 1.29 이하면 지원 종료 계열이라 1.30.7 이상으로 올려야 합니다.
- 조건 판단의 한계
  - 지시어가 같은 블록에 있는지 보지 않습니다. alias와 try_files가 서로 다른 location에 있어도 `조건 해당`입니다.
  - CVE-2026-123634는 resolver, 변수 proxy_pass, mirror 또는 SSI가 모두 있을 때 `조건 해당`입니다. 실제로 같은 이름을 해석하는지는 모릅니다.
  - CVE-2026-120967은 stream 블록과 ssl_verify_client가 함께 있으면 해당입니다. 기본 서버인지는 보지 않습니다.
  - CVE-2026-118899는 ssl_protocols가 있으면 TLSv1.3 포함 여부로, 없으면 버전으로 봅니다(1.23.4 이상은 기본값에 TLSv1.3 포함).
  - P1 서버의 조건을 더 확인하려면 고객에게 설정 검토를 요청합니다. 서버에서 `nginx -T`를 실행하거나 설정 파일 내용을 출력하지 않습니다.
- `확인 필요` 처리
  - OpenResty: openresty.org 공지, Tengine, Angie, freenginx: 각 프로젝트 공지
  - NGINX Plus: F5 K000163925-K000163935 (my.f5.com은 WebFetch로 빈 화면이 나오므로 Claude in Chrome)
- NGXCTL `ingress-nginx`가 붙은 행은 프로젝트가 보관된 상태라 이미지 갱신으로 고쳐지지 않을 수 있습니다. 권고에 컨트롤러 교체 검토를 적습니다.
- Windows nginx는 설정을 읽지 않으므로 `설정 미확인`입니다.

## 보고 문안 가이드 (notes.toml)

key_findings에 넣을 것
- P1 서버: 서버명, nginx 버전과 출처, 조건 해당 CVE(특히 major인 HTTP/2 CVE-2026-123007, mail 프록시 CVE-2026-113425), 인터넷용 LB 대상 등록 여부
- P2 요약: 배포판과 패키지 버전, 배포판 수정 상태와 확인 날짜
- ingress-nginx, NGINX Plus, 포크 제품을 발견했으면 따로 한 항목
- nginx가 발견되지 않은 서버는 개별로 쓰지 않습니다(서버별 현황에 "공지 대상 제품 없음"으로 나옴)

recommendations에 넣을 것
- nginx.org 패키지와 소스 빌드는 1.30.7 또는 1.31.9 이상으로 올립니다. 1.29 이하는 지원 종료 계열입니다.
- 배포판 패키지는 배포판 수정 패키지 출시를 확인한 뒤 적용합니다. Amazon Linux 2023은 ALAS2023-2026-3494입니다.
- 업그레이드 전 완화는 공식 출처의 것만 씁니다(README "업그레이드 전 완화").
- 실행 파일을 바꾼 뒤 재기동합니다. reload로는 실행 파일이 바뀌지 않습니다. EXE_DELETED 서버는 지금도 이전 바이너리입니다.
- ingress-nginx는 다른 ingress 컨트롤러로 바꾸는 것을 검토합니다.
- 미점검 대상(EKS, Fargate, ECR)의 확인 방법을 적습니다.

쓰지 말아야 할 표현
- nginx2root 블로그의 공격 단계, SCTP 커널 취약점을 판정 근거로 쓰지 않습니다.
  - 꼭 언급해야 하면 "보안 연구자 블로그에 따르면"으로 시작하고 "공식 공지에는 없는 내용"이라고 밝힙니다.
- "실제 악용 중" 같은 표현을 쓰지 않습니다. 공식 출처 기준 악용 보고가 없습니다(2026-11-18).
- `조건 해당`을 "공격 가능 확정"으로 쓰지 않습니다. "설정상 해당 가능"으로 씁니다.

## 기준표 갱신 (원문이 바뀔 때)

- nginx.org 공지 목록은 개정 이력을 남기지 않습니다. 다시 읽어 이 폴더의 [[cves]] 값(range, fixed)과 비교합니다.
- 원문 읽는 방법
  - nginx.org(공지 목록, CHANGES, CHANGES-1.30)는 WebFetch로 읽힙니다.
  - 공지 목록 항목은 제목, Severity, Advisory(F5 링크), CVE, Not vulnerable, Vulnerable 순입니다.
  - CVE 레코드는 `https://cveawg.mitre.org/api/cve/<CVE-ID>` JSON입니다. CVSS 3.1은 `containers.cna.metrics`에 있습니다.
  - my.f5.com, access.redhat.com은 내용이 스크립트로 그려집니다. Claude in Chrome으로 읽습니다.
- 바뀐 값은 criteria.toml에 반영하고 `revision`을 확인 날짜로 바꿉니다. README.md의 표와 "기준표 작성" 날짜도 고칩니다.
- `_core/sweep index`로 색인을 갱신합니다.

## 다음 nginx 보안 릴리스를 등록할 때

- 폴더 이름은 `YYYY-MM-DD_nginx_<mainline 버전>`입니다(예: `2026-12-16_nginx_1-31-10`). 이 폴더의 criteria.toml과 AGENTS.md를 출발점으로 씁니다.
- `supported_branches`, 각 CVE의 `range`, `fixed`는 매번 바뀝니다. 새 원문으로 전부 다시 확인합니다.
- 새 조건이 필요하면 `cond` 키를 `_core/vsweep/products.py`의 `NGX_CONDS`에 `core/` 브랜치로 먼저 추가합니다. 수집기에 새 지시어가 필요하면 `ngx_conf_flags`도 고칩니다.

## 하지 말 것

- 대상 서버에서 `nginx -t`, `nginx -T`, `nginx -V`를 실행하지 않습니다. 설정 검사는 로그 파일과 임시 디렉터리를 만들 수 있습니다.
- 설정 파일 내용(호스트명, upstream, 인증서 경로)을 출력하거나 결과 폴더에 복사하지 않습니다.
- 2차 출처의 값(블로그의 시작 버전, SCTP 취약점)을 criteria.toml에 넣지 않습니다.
- 배포판 패키지를 nginx 버전 번호만 보고 수정됐다고 판단하지 않습니다.
- HTTP/2 끄기 같은 완화 설정을 직접 적용하지 않습니다. 권고로만 씁니다.
- 이 폴더 파일에 고객명, 서버명, 점검 결과 수치를 쓰지 않습니다.
