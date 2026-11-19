# nginx 1.31.9 mainline, 1.30.7 stable 보안 수정 (2026-11-18)

| 항목 | 내용 |
|---|---|
| 취약점 ID | 2026-11-18_nginx_1-31-9 |
| 원문 | https://nginx.org/en/security_advisories.html (공지 목록), https://nginx.org/en/CHANGES , https://nginx.org/en/CHANGES-1.30 |
| 발표 | 2026-11-18 (nginx.org 뉴스. 공지 목록에는 개정 번호가 없음) |
| 종류 | 취약점 세트 (nginx 보안 릴리스) |
| 규모 | CVE 10건 (nginx.org 심각도 major 3, medium 4, minor 3) |
| 기준표 | [criteria.toml](criteria.toml) |
| 기준표 작성 | 2026-11-19, nginx.org 공지 목록 기준. CVSS는 CVE 레코드(CNA F5) |
| 에이전트 지침 | [AGENTS.md](AGENTS.md) (점검 절차, 판정 검토, 기준표 갱신) |

## 요약

- nginx.org가 2026-11-18에 1.31.9(mainline)와 1.30.7(stable)을 내고 CVE 10건을 고쳤습니다.
- 보안 연구 블로그 Xint.io의 nginx2root 글은 이 중 5건(CVE-2026-123007, 123634, 123633, 121810, 113425)을 묶어 설명합니다.
- 10건 모두 인증 없이 원격에서 공격할 수 있습니다(CVE 레코드 CVSS 3.1 벡터 AV:N, PR:N).
  - 최고 CVSS는 8.1(5건)이고, 이 5건은 공격 복잡도가 높습니다(AC:H).
  - CVE 설명에 따르면 결과는 worker 프로세스 비정상 종료(DoS)나 메모리 손상이고, ASLR이 꺼져 있거나 우회되면 코드 실행도 가능합니다.
- 실제 악용: nginx.org 공지에는 언급이 없습니다. CVE 레코드의 CISA ADP 평가는 Exploitation none입니다(2026-11-18 기준).
- 취약점마다 특정 기능을 쓸 때만 해당합니다. 아래 표의 조건을 봅니다.

## CVE별 영향 범위와 조건

영향 범위는 nginx.org 공지 목록의 Vulnerable 값입니다. 수정 버전은 모두 1.31.9 이상, 1.30.7 이상입니다(CVE-2026-120993은 1.31.9 이상만).

| CVE | nginx.org 제목 | 심각도 | CVSS 3.1 | 영향 버전 | 해당 조건 |
|---|---|---|---|---|---|
| CVE-2026-123007 | Memory corruption in HTTP/2 flow control | major | 8.1 | 1.9.5-1.31.8 | HTTP/2 사용 |
| CVE-2026-113425 | Use-after-free in mail proxy module | major | 8.1 | 0.5.33-1.31.8 | mail 프록시 사용 |
| CVE-2026-118899 | Infinite loop while reading client request body over TLS 1.3 | major | 7.5 | 1.13.0-1.31.8 | http에서 SSL 리스너, TLSv1.3 허용 |
| CVE-2026-123634 | Use-after-free during response processing in resolver | medium | 8.1 | 0.6.18-1.31.8 | resolver, 변수가 들어간 proxy_pass 서버 이름, SSI 또는 mirror 하위 요청 |
| CVE-2026-121810 | Use-after-free in HTTP/3 | medium | 8.1 | 1.25.0-1.31.8 | HTTP/3 사용, worker_connections 부족 |
| CVE-2026-123633 | Use-after-free in HTTP/2 | medium | 8.1 | 1.19.7-1.31.8 | HTTP/2로 받아 백엔드로 프록시, worker_connections 부족 |
| CVE-2026-120967 | SNI bypass when using client certificate validation in stream | medium | 4.8 | 1.25.5-1.31.8 | stream의 기본이 아닌 가상 서버에서 ssl_verify_client on |
| CVE-2026-120993 | NULL pointer dereference when using PROXY protocol version 2 | minor | 5.3 | 1.31.4-1.31.8 | stream에서 인증서 동적 로딩과 PROXY protocol v2 |
| CVE-2026-125283 | Buffer overflow when using alias with try_files | minor | 5.3 | 0.9.6-1.31.8 | alias와 try_files, 정규식 map 변수 |
| CVE-2026-123640 | Insufficient validation in stream ssl_preread module | minor | 5.3 | 1.15.2-1.31.8 | stream에서 ssl_preread on |

## 수정 버전과 배포판 상태 (2026-11-19 확인)

- nginx.org: 1.31.9 이상 또는 1.30.7 이상입니다. 지원 계열은 1.31과 1.30뿐이라 1.29 이하 계열에는 수정본이 없습니다.
- 배포판 패키지

| 배포판 | 상태 | 근거 |
|---|---|---|
| Amazon Linux 2023 | 수정: nginx 1.30.7-1.amzn2023.0.1 (CVE 9건, 1.31 전용인 CVE-2026-120993 제외) | ALAS2023-2026-3494 |
| Amazon Linux 2 (nginx1 extras) | 수정: nginx 1.30.7-1.amzn2.0.1 (CVE 9건, CVE-2026-120993 제외) | ALAS2NGINX1-2026-018 (2026-11-19) |
| Ubuntu (16.04-26.10) | Vulnerable, 수정 패키지 없음 | ubuntu.com/security/CVE-2026-123007 |
| Debian bookworm, trixie | vulnerable (sid는 1.30.6-4에서 수정) | security-tracker.debian.org |
| RHEL | 확인하지 못함(상태표가 브라우저에서만 보임) | access.redhat.com/security/cve/cve-2026-123007 |

- Kubernetes ingress-nginx: 2026-03-24에 저장소가 보관(archived)되었고, README는 이후 보안 수정이 없다고 밝힙니다.
- NGINX Plus: CVE 레코드 기준 R33 이후가 영향입니다. 수정 버전은 F5 공지(K000163925-K000163935)로 확인합니다.

## 판정할 때 주의할 점

- 배포판 패키지는 보안 수정을 반영해도 nginx 버전 문자열이 그대로입니다(예: Ubuntu 22.04는 1.18.0).
  - 판정기는 배포판 공지에 수정 패키지 버전이 있으면 패키지 버전으로 비교합니다(criteria `[nginx.distro_fixed]`).
  - 없으면 P2(배포판 수정 확인 필요)로 둡니다.
- 설정 조건은 실행 중인 nginx의 설정 파일에서 지시어 사용 여부만 보고 판단합니다.
  - 블록 위치는 보지 않으므로 조건 해당은 가능성입니다.
  - 영향 버전이라도 조건이 하나도 없으면 P3입니다.
- 공식 출처끼리 다른 곳
  - nginx.org 공지 목록의 HTTP/3 항목은 CVE를 CVE-CVE-2026-121810으로 잘못 적었습니다. CHANGES와 CVE 레코드는 CVE-2026-121810입니다.
  - CVE 레코드의 영향 범위가 nginx.org와 다른 항목이 있습니다.
    - CVE-2026-118899: 레코드는 1.31.0 이후, nginx.org는 1.13.0-1.31.8
    - CVE-2026-121810: 레코드의 시작 버전이 1.25.09로 적혀 있음
    - 기준표는 nginx.org 공지 목록을 따릅니다.
  - Amazon Linux 공지의 CVE별 점수(예: CVE-2026-113425 5.9)는 Amazon 자체 점수입니다. 기준표는 CNA(F5) 점수를 씁니다.
- 2차 출처 (참고만 하고 판정에는 쓰지 않음)
  - Xint.io 블로그(https://xint.io/blog/nginx2root-remote-code-execution , 2026-11-18)
    - 5건의 공격 경로와, 리눅스 커널 SCTP 취약점을 연계한 root 권한 상승과 컨테이너 탈출을 설명합니다.
    - SCTP 취약점의 CVE 번호와 커널 수정 버전은 블로그에 없습니다.
    - 블로그가 적은 시작 버전 중 nginx.org와 다른 것이 있습니다(CVE-2026-123634 1.13.4, CVE-2026-113425 0.5.15). 기준표는 nginx.org 값을 씁니다.
  - 수집기는 SCTP 커널 모듈 상태(META sctp)를 남깁니다. 판정에는 쓰지 않습니다.

## 업그레이드 전 완화 (공식 출처)

- CVE-2026-123634: SSI, mirror 지시어를 피하고 proxy_pass 서버 이름에 변수를 쓰지 않습니다(CVE 레코드의 회피책).
- CVE-2026-113425: mail 리스너를 신뢰하는 네트워크로 제한합니다(CVE 레코드의 회피책).
- CVE-2026-123007: listen의 http2 파라미터를 지우고, 1.25 이상은 http2 off로 HTTP/2를 끕니다(Red Hat 공지의 완화책).
- 근본 조치는 업그레이드입니다. 실행 파일을 바꾼 뒤에는 재기동해야 하며, reload로는 실행 파일이 바뀌지 않습니다.

## 점검

점검 명령과 단계별 추가 확인 사항은 [AGENTS.md](AGENTS.md)에 있습니다. 이 공지는 수집기 2026.11.2 이상이 필요합니다.
