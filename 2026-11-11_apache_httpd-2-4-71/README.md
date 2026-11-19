# Apache HTTP Server 2.4.71 보안 수정 (2026-11-11)

| 항목 | 내용 |
|---|---|
| 취약점 ID | 2026-11-11_apache_httpd-2-4-71 |
| 원문 | https://httpd.apache.org/security/vulnerabilities_24.html (Fixed in Apache HTTP Server 2.4.71) |
| 발표 | 2026-11-11 |
| 종류 | 취약점 세트 (httpd 보안 릴리스) |
| 규모 | CVE 3건 (critical 1, important 1, low 1) |
| 기준표 | [criteria.toml](criteria.toml) |
| 기준표 작성 | 2026-11-19, Apache 취약점 페이지 기준. CVSS는 CVE 레코드의 CISA ADP 점수 |
| 에이전트 지침 | [AGENTS.md](AGENTS.md) (점검 절차, 판정 검토, 기준표 갱신) |
| 후보 Issue | KISA 보안공지 Apache 제품 보안 업데이트 권고 (2026-11-12) |

## 요약

- Apache가 2026-11-11에 httpd 2.4.71을 내고 CVE 3건을 고쳤습니다.
- 3건 모두 인증 없이 원격에서 공격할 수 있고, 각각 특정 모듈을 쓸 때만 해당합니다.
- 가장 위험한 것은 CVE-2026-119618(critical, CVSS 8.1)입니다.
  - mod_http2에서 원격 코드 실행이 가능합니다.
  - 공격 복잡도가 높습니다(AC:H).
- 실제 악용: Apache 페이지에 언급이 없습니다.
- 2.4.69(2026-10-01)에서 고친 CVE 20건은 이 폴더에 없습니다. 2.4.68 이하는 그 20건에도 해당합니다.

## CVE별 영향 범위와 조건

| CVE | Apache 심각도 | CVSS 3.1 (ADP) | 영향 버전 | 해당 조건 |
|---|---|---|---|---|
| CVE-2026-119618 | critical | 8.1 | 2.4.55-2.4.70 | mod_http2를 로드하고 Protocols에 h2 또는 h2c를 켬. GitHub 배포 mod_h2 2.0.8-2.0.42도 해당 |
| CVE-2026-106023 | important | 7.5 | 2.4.30-2.4.70 | mod_md 로드 (child 프로세스 비정상 종료) |
| CVE-2026-109163 | low | 5.9 | 2.4.69-2.4.70 | mod_vhost_alias와 VirtualDocumentRoot 계열 지시어 사용 |

수정 버전은 2.4.71입니다.

## 배포판 상태 (2026-11-19 확인)

배포판은 버전 번호를 그대로 두고 수정을 넣습니다(백포트). 패키지 버전으로 확인합니다.

| 배포판 | 수정 패키지 | 근거 |
|---|---|---|
| Amazon Linux 2 | httpd 2.4.71-1.amzn2.0.1 (3건) | ALAS2-2026-4114 |
| Amazon Linux 2023 | httpd 2.4.71-1.amzn2023.0.1 (CVE-2026-119618, 109163). CVE-2026-106023은 Not Affected | ALAS2023-2026-3458 |
| Ubuntu 14.04-26.04 | apache2 (예: 22.04 2.4.52-1ubuntu4.27, 24.04 2.4.58-1ubuntu8.19) | USN-9090-1 |
| Debian 12 (bookworm) | apache2 `2.4.71-1~deb12u1` | DLA-4902-1 |
| Debian 13 (trixie) | apache2 `2.4.71-1~deb13u1` | DSA-6620-1 |
| RHEL 9, 10 | CVE-2026-119618은 mod_http2 패키지로 수정(예: RHEL 9 mod_http2 2.0.26-7.el9_9.1, RHSA-2026:98981). 나머지 2건은 Red Hat 자료 없음 | Red Hat Security Data API |
| RHEL 7, 8 | CVE-2026-119618 Not affected. 나머지 2건은 자료 없음 | Red Hat Security Data API |

## 판정할 때 주의할 점

- 배포판 httpd의 영향 범위 하한은 업스트림 버전으로 거르지 않습니다.
  - 예: Ubuntu 20.04의 2.4.41도 USN-9090-1에서 CVE-2026-109163(업스트림 2.4.69 이후) 수정 대상으로 나옵니다.
  - 그래서 배포판 패키지는 배포판 공지로만 판단합니다.
- RHEL은 mod_http2가 httpd와 별도 패키지입니다. httpd 패키지를 올려도 mod_http2를 올리지 않으면 CVE-2026-119618이 남습니다.
- 조건은 실행 중 프로세스에 실제로 올라온 모듈(mod_*.so)과 설정 지시어로 봅니다.
  - Protocols의 기본값은 http/1.1이라, mod_http2를 로드해도 h2를 켜지 않으면 CVE-2026-119618은 해당하지 않습니다.
  - 정적으로 컴파일된 모듈은 보이지 않습니다(배포판과 공식 이미지는 공유 모듈).
- 실행 중이 아닌 설치본, 이미지 레이어는 모듈 정보가 없어 조건 미확인입니다(P3).

## 업그레이드 전 완화

- 공식 원문(Apache 페이지, CVE 레코드)에 완화 방법은 없습니다.
- 모듈을 쓰지 않으면 해당 CVE는 공격 대상이 아니므로, 쓰지 않는 mod_http2, mod_md, mod_vhost_alias를 끄는 것은 일반적인 설정 정리입니다. 서비스 영향은 고객이 판단합니다.
- 근본 조치는 업데이트 후 재시작입니다. graceful 재시작은 부모 프로세스의 실행 파일을 바꾸지 않으므로 중지 후 시작(restart)이 확실합니다.

## 점검

점검 명령과 단계별 추가 확인 사항은 [AGENTS.md](AGENTS.md)에 있습니다. 이 공지는 수집기 2026.11.3 이상이 필요합니다.
