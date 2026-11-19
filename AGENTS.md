# AGENTS.md

이 리포에서 작업하는 AI 에이전트(Claude Code 등)를 위한 지침입니다. 사용자와는 한국어로 소통합니다.

## 이 리포가 하는 일

보안 공지가 나오면 다음 순서로 일합니다.

1. 공지를 리포 루트에 취약점 폴더로 등록합니다(기준표 criteria.toml).
2. 고객 AWS 환경의 서버 전체를 읽기 전용으로 점검합니다.
3. 수집 결과를 기준표와 대조해 우선순위(P1, P2, P3)를 매깁니다.
4. 고객 보고용 엑셀을 만듭니다.

패치 적용은 이 리포의 범위가 아닙니다.

- 리포 루트에는 취약점 폴더가 바로 놓입니다.
  - 취약점 세트: `YYYY-MM-DD_<벤더>_<공지키>`
  - 단일 CVE: `CVE-YYYY-NNNN`
  - 공통 엔진은 `_core/`에 있고, 모든 명령은 `_core/sweep <명령>`으로 실행합니다.
- 고객 설정과 결과는 리포 밖 `$SWEEP_RUNS`(기본: 리포 상위 폴더의 `vuln-sweep-runs/`)에 둡니다.

## 취약점 폴더의 AGENTS.md

취약점 폴더마다 그 취약점 전용 지침(`<취약점ID>/AGENTS.md`)이 있습니다. Claude Code는 같은 폴더의 `CLAUDE.md`(`@AGENTS.md`)를 통해 읽습니다.

- 어떤 취약점을 점검하거나 고치기 전에, 그 폴더의 AGENTS.md를 먼저 읽습니다.
- 담긴 내용: 점검 절차, 단계별 추가 확인(RDS 엔진 등), 판정 검토 포인트, 보고 문안 가이드, 기준표 갱신 방법, 하지 말 것
- 이 문서(루트)의 절대 규칙이 항상 먼저입니다. 폴더 지침이 루트 규칙과 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.
- 점검하다가 그 취약점에만 해당하는 새 함정을 알게 되면 폴더 AGENTS.md에 추가합니다. 여러 취약점에 공통이면 이 문서의 "알려진 함정"에 추가합니다.

## 절대 규칙

1. 대상 서버를 바꾸지 않습니다.
   - 실행해도 되는 것은 `_core/scan_linux.sh`, `_core/scan_windows.ps1` 같은 읽기 전용 수집기뿐입니다.
   - 패치, 설치, 재기동, 설정 변경, 파일 정리는 사용자가 요청해도 하지 않고, 별도 작업으로 넘깁니다.
2. 고객 AWS 계정에 리소스를 만들거나 바꾸지 않습니다.
   - 허용되는 호출은 describe, list, get 계열과 `ssm send-command`(수집기 실행)입니다.
   - S3 버킷, IAM, SSM 문서, 로그 그룹, 보안 그룹, 태그는 만들지도 바꾸지도 않습니다.
3. 고객 정보는 리포에 들어오지 않습니다.
   - 이 리포는 공개(PUBLIC)입니다.
   - 고객명, 계정 ID, 서버명, IP, 키 경로, 점검 결과를 취약점 폴더, 코드, 문서, 커밋 메시지, PR 어디에도 쓰지 않습니다.
   - 예시가 필요하면 `acme`, `i-0123456789abcdef0`, `10.0.0.1`처럼 가짜 값을 씁니다.
   - 커밋 전에는 아래 "커밋 전 검사"를 반드시 실행합니다.
4. 자격증명을 다루지 않습니다.
   - 비밀번호를 입력하지 않고, 키 파일 내용을 출력하지 않습니다.
   - SSO 로그인은 사용자에게 요청합니다(`! aws sso login --profile <이름>`).
5. 운영 서버에서 실행하기 전에 사용자 확인을 받습니다.
   - 대상 고객, 계정, 범위를 확인합니다.
   - 시범 1-2대 결과를 보고한 다음 전체로 넓힙니다.
6. 기준표 값은 공식 원문에서만 가져옵니다.
   - 2차 보도와 블로그 내용은 README.md에 출처와 함께 참고로만 적고, 판정에는 쓰지 않습니다.
7. 접근 제한은 우회하지 않습니다.
   - 원문이 403이면 User-Agent 위장 같은 방법을 쓰지 않습니다.
   - 사용자 브라우저(Claude in Chrome)로 읽거나, 사용자에게 원문 텍스트를 요청합니다.
8. 보고서를 외부에 공유할지는 사용자가 정합니다. 에이전트가 고객에게 직접 보내거나 게시하지 않습니다.

## 작업 A. 새 취약점 등록 (커밋 대상)

사용자 요청 예: "이 공지 등록해줘 <URL>", "CVE-2026-12345 등록해줘"

1. 원문을 읽고 폴더 이름을 정합니다. 규칙은 README.md의 "폴더 이름 규칙"을 따릅니다.
   - 여러 CVE를 묶은 벤더 공지면 세트(`2026-12-15_oracle_cspudec2026`)로 만듭니다.
   - CVE 하나면 `CVE-2026-12345`로 만듭니다.
   - 먼저 `grep <CVE> CVE_INDEX.csv`로 이미 다룬 CVE인지 확인합니다.
2. 최신 main에서 브랜치를 만들고 폴더를 만듭니다. 브랜치 이름은 README.md의 "브랜치 규칙"을 따릅니다.
   ```bash
   git fetch origin && git checkout -b set/2026-12-15_oracle_cspudec2026 origin/main   # 단일 CVE면 single/CVE-2026-12345
   _core/sweep new 2026-12-15_oracle_cspudec2026
   ```
3. `criteria.toml`을 채웁니다. 템플릿 주석을 따르고, 루트 키는 표 헤더보다 위에 둡니다.
   - 같은 벤더의 이전 폴더를 출발점으로 쓰면 빠릅니다.
   - 이전 값을 그대로 두지 말고, 바뀐 값은 모두 원문으로 다시 확인합니다.
4. `README.md`와 `AGENTS.md`를 채웁니다.
   - README.md는 사람용 요약입니다. 영향 버전과 판정 주의점을 적습니다.
   - AGENTS.md는 에이전트용 절차입니다. 템플릿의 모든 절을 채웁니다.
     - 점검 절차, 단계별 추가 확인, 판정 검토 포인트, 보고 문안 가이드, 기준표 갱신 방법(원문 읽는 법), 하지 말 것
     - 같은 벤더의 이전 폴더 AGENTS.md를 출발점으로 쓰면 원문 추출 방법 같은 내용을 다시 쓰지 않아도 됩니다.
5. 수집기가 대상 제품을 잡는지 확인합니다.
   - 현재 수집 대상: Java(JDK/JRE, 컨테이너 포함), MySQL/MariaDB, Oracle Home(DB, Client, WebLogic/FMW), 파일(weblogic.jar, helidon-*.jar, ords.war, VBoxManage), nginx 계열(nginx, OpenResty, Angie, NGINX Plus 바이너리와 설정의 지시어 사용 여부, 컨테이너 포함)
   - 그 밖의 제품(OpenSSL, Log4j 등)은 수집기와 판정기를 확장해야 합니다. 절차는 `_core/COLLECTORS.md` 끝부분에 있습니다.
   - criteria.toml에 제품 섹션이 없는 제품은 판정하지 않고 보고서에도 넣지 않습니다. 이번 공지와 무관한 섹션은 지웁니다.
   - 판정기는 `_core/vsweep/products.py`에 함수를 만들고, `_core/vsweep/judge.py`에서 레코드 종류별로 호출합니다.
   - 수집기나 판정기를 고쳐야 하면 `core/<설명>` 브랜치로 따로 올리고, 취약점 브랜치는 그 위에서 작업합니다.
6. `_core/sweep index`를 실행하고 경고가 없는지 봅니다.
7. 취약점 폴더, `INDEX.md`, `CVE_INDEX.csv`를 함께 커밋합니다.
   - 커밋하기 전에 "커밋 전 검사"를 실행합니다.
   - push하고 PR을 엽니다. 제목은 `[set] <세트ID>: <공지 제목>` 또는 `[single] <CVE-ID>: <요약>`입니다.
   - PR 본문에도 고객명이나 고객 환경 규모(서버 수, 발견 건수)를 쓰지 않습니다. 검증은 "기존 점검 결과로 재판정해 동일함을 확인"처럼 씁니다.

## 작업 B. 고객 점검 (리포 밖, 커밋하지 않음)

사용자 요청 예: "acme 고객에 2026-11-17_oracle_cspunov2026 점검 진행해줘"

### 0. 시작 전
- 대상 취약점 폴더의 AGENTS.md를 읽습니다. 아래 단계마다 그 문서의 "단계별 추가 확인"을 함께 합니다.

사용자에게 확인할 것
- 고객 코드(소문자 영문), AWS 프로파일(SSO 여부), 대상 계정과 리전
- SSM이 없는 서버를 위한 bastion 접속 수단
- 점검 시간대 제약. 운영 서버가 있으면 업무 시간 외가 좋습니다.

### 1. 준비
```bash
V=2026-11-17_oracle_cspunov2026; C=acme
_core/sweep init $C            # $SWEEP_RUNS/acme/config.env 생성 (처음 한 번). AWS_PROFILE, AWS_REGION, BASTION, BASTION_KEY 채우기
set -a; . "$(dirname "$(_core/sweep path $C $V)")/config.env"; set +a
aws sts get-caller-identity    # 계정 확인. SSO 토큰은 보통 1시간이라 만료 시각도 확인
```

### 2. 자산 조회
```bash
_core/sweep inventory $C $V    # 마지막에 대상 목록(SSM Linux/Windows, 미관리 서버)을 출력
```
- 결과에서 SSM 대상 수, SSM 미관리 running 서버, RDS와 Lambda 엔진을 사용자에게 보고합니다.
- 취약점 폴더 README의 "추가 확인 사항"(RDS 엔진 버전 대조 등)도 이 단계에서 합니다.

### 3. SSM 미관리 서버 접속 확인 (bastion)
```bash
_core/sweep probe $C $V 10.0.1.10 10.0.1.11      # targets_unmanaged.tsv 의 사설 IP
```
보유 키로 접속이 안 되는 서버는 미점검으로 두고, 사유를 notes.toml `[unscanned]`에 적습니다.

### 4. 시범 실행 (Linux 1대, Windows 1대)
```bash
_core/sweep ssm $C $V linux i-xxxxxxxx
_core/sweep ssm $C $V windows i-yyyyyyyy
```
- `hosts/<id>.tsv`의 마지막 줄이 `END`인지, 오류가 없는지, 소요 시간이 적당한지 확인합니다.
- 결과를 사용자에게 보고하고 전체 진행 확인을 받습니다.

### 5. 전체 실행
```bash
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep bastion $C $V i-aaa centos 10.0.1.10 i-bbb rocky 10.0.1.11
_core/sweep status $C $V
```
- 오래 걸리므로 백그라운드로 실행하고 완료 알림을 기다립니다(Claude Code는 Bash `run_in_background`).
- `pgrep -f run_ssm.sh`로 대기하면 대기 명령 자신이 매칭되어 끝나지 않습니다. 쓰지 않습니다.
- SSO가 중간에 만료돼도 이미 보낸 SSM 명령은 서버에서 계속 돕니다.
  - 사용자가 다시 로그인하면 RUN_DIR의 `commands.log`에 있는 Command ID로 `aws ssm get-command-invocation`을 호출해 결과를 회수합니다.

### 6. 판정
```bash
_core/sweep judge $C $V
```
- 출력의 "끝까지 실행되지 않은 서버"는 다시 실행합니다.
- `findings.csv`에서 다음 항목을 훑어봅니다.
  - vendor가 `미상`인 것
  - `버전 확인 필요`, `수동 확인`인 것
  - 판정이 이상해 보이는 것
- 판정 로직을 고쳤다면 기존 RUN_DIR 하나로 다시 판정해서, 이전 findings.csv와 달라진 줄이 의도한 것뿐인지 확인합니다.

### 7. 보고 문안과 보고서
```bash
_core/sweep notes $C $V        # RUN_DIR/notes.toml 생성 후 작성
_core/sweep export $C $V
```
- notes.toml에는 주요 발견, 권고, 서버별 비고, 미점검 사유를 씁니다. 사실만 쓰고, 추정은 추정이라고 밝힙니다.
- 엑셀 수식은 결과값이 저장되지 않습니다. Excel이 열 때 계산되도록 설정되어 있습니다.
  - 사용자에게 보내기 전에 Excel로 한 번 열어 저장하라고 안내합니다.
  - LibreOffice가 있으면 recalc 검증을 합니다.

### 8. 이력과 보고
- `$SWEEP_RUNS/<고객>/SWEEPS.md`에 한 줄을 추가합니다(리포 밖).
  ```
  | 날짜 | 취약점 ID | EC2 | 점검 | P1 | P2 | P3 | 확인 필요 | 미점검 | 비고 |
  ```
- 사용자에게 보고할 내용:
  - 커버리지: 전체, 점검, 미점검과 그 사유
  - P1과 P2 서버 목록(서버, 버전, 서비스)
  - 공지 대상인데 발견되지 않은 제품
  - 한계
  - 엑셀 경로

## 우선순위 규칙 (_core/vsweep/judge.py)

| 우선순위 | 조건 |
|---|---|
| P1 | 공지 대상 제품(criteria `primary_vendors`, MySQL, Oracle Home)이 영향 버전 또는 EOL 버전으로 실행 중 |
| P2 | 파생 빌드(Corretto, Temurin, OS 패키지 OpenJDK, 배포판 nginx 패키지 등)가 영향 범위 버전 또는 EOL 버전으로 실행 중 |
| P3 | 영향 버전 또는 EOL 버전이 설치만 되어 있음 (미실행, 컨테이너 이미지 레이어). nginx는 실행 중이어도 수집한 설정에 공지의 사용 조건이 하나도 없으면 P3 |
| 확인 필요 | 버전을 읽지 못했거나 사람이 대조해야 함. 스캔이 끝까지 안 된 서버 |
| 해당 없음 | 공지 대상 아님(MariaDB, IBM Java 등) 또는 범위 밖 버전 |
| 미점검 | 정지, 접속 수단 없음 |

## 알려진 함정

| 상황 | 대응 |
|---|---|
| SSM API 출력은 인스턴스당 24,000자에서 잘림 | 수집기가 항목별 상한을 두고, 마지막 줄 END로 완주를 판단 |
| AWS-RunShellScript가 sh로 실행될 수 있음 | run_ssm.sh가 base64 인자로 `bash -c` 실행 |
| Oracle 원문이 WebFetch, curl에서 403 | 사용자 브라우저로 읽음. 표 추출 방법은 `2026-11-17_oracle_cspunov2026/README.md` |
| Chrome 확장 출력 필터가 `key=`, `auth` 들어간 문자열을 가림 | 추출 결과의 키 이름과 구분자를 바꿈 |
| OPatch 11.x는 `lspatches` 미지원(error 14) | 수집기가 `lsinventory` 요약으로 대체 |
| Windows Tomcat 서비스는 java.exe 없이 tomcatN.exe 안에서 JVM 실행 | 수집기가 jvm.dll 모듈과 procrun 레지스트리로 탐지 |
| `libjvm.so (deleted)` | JDK 교체 후 미재기동. 실제 실행 버전은 디스크 버전보다 낮을 수 있음 |
| Oracle Java 버전은 다섯 자리(21.0.13.0.3) | 다섯 자리로 비교. Corretto CSPU 빌드는 네 번째 자리가 오름(21.0.13.1) |
| Java 8 업데이트 번호 | Oracle 8u511과 OpenJDK 계열 8u512처럼 1 차이. `derivative_latest_affected`로 처리 |
| Windows java.exe 파일 버전 8.0.910.15 | 8u91 (세 번째 자리 나누기 10) |
| IBM Java도 `Java(TM)` 문자열을 씀 | vendor 판정에서 IBM을 먼저 거름 |
| RHEL/CentOS RPM OpenJDK에는 release 파일이 없음 | `java -version` 출력으로 판정 |
| 컨테이너 안 JVM | `/proc/<pid>/root`로 release 파일을 읽음. 이미지 레이어 바이너리는 실행하지 않음 |
| LB 대상으로 등록됨 | 그 포트가 해당 Java 서비스인지는 별도 확인. 보고서에는 등록 사실만 씀 |
| TOML 표 헤더 뒤에 쓴 루트 키 | 그 표 안으로 들어감. 루트 키는 맨 위에 |
| EOL 버전 접두어 | 제품별로 둠(`[oracle_home.eol_prefixes]`). WebLogic 12.2.1.4는 지원 중이라 Client/DB의 `12.`와 섞지 않음 |
| `nginx -t`, `nginx -T` | 로그 파일과 임시 디렉터리를 만들 수 있어 쓰지 않음. 버전과 configure 인자는 바이너리 문자열로 읽음 |
| 배포판 nginx는 백포트해도 버전 문자열이 그대로(예: Ubuntu 1.18.0) | 패키지 버전을 배포판 공지의 수정 버전과 비교(`[nginx.distro_fixed]`). 공지가 없으면 P2로 두고 배포판 확인 |
| nginx 실행 파일 `(deleted)` | 패키지 갱신 후 재기동하지 않음. 패키지 버전과 무관하게 이전 바이너리가 동작하므로 배포판 수정 버전 비교를 하지 않음 |
| 컨테이너 안 절대 경로 심볼릭 링크 | `/proc/<pid>/root` 경유로 읽으면 호스트 기준으로 풀림. 수집기가 링크를 읽어 컨테이너 루트 기준으로 다시 붙임 |

## 커밋 전 검사

```bash
git status --short --ignored            # 고객 결과 파일이 추적 대상에 없어야 함
git diff --cached --name-only           # 취약점 폴더, _core/, INDEX.md, CVE_INDEX.csv, 루트 문서만 있어야 함
git diff --cached | grep -nE '\b[0-9]{12}\b|(^|[^0-9.])10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|\.pem\b|BEGIN .*PRIVATE KEY|i-0[0-9a-f]{16}' && echo "민감정보 의심, 확인 필요"
```
- 12자리 숫자(계정 ID), 사설 IP, 인스턴스 ID, 키 경로, 고객명이 나오면 커밋하지 않습니다.
- 커밋 메시지와 PR 본문도 같은 기준으로 봅니다. 한 번 push한 내용은 이력을 고쳐도 GitHub에 남을 수 있으므로 push 전에 확인합니다.
- 예외는 두 가지뿐입니다.
  - 문서의 가짜 예시 값(`i-0123456789abcdef0`, `10.0.0.1`)
  - 버전 문자열처럼 오탐이 확실한 경우

## 문서 표기 규칙 (고객 보고 문안, 취약점 README)

- 마크다운 bold(`**`), `§`, em dash와 en dash, 가운뎃점, 범위 물결표(`~`)를 쓰지 않습니다. 범위는 하이픈으로 씁니다(예: 19.3-19.33).
- 큰따옴표는 실제 인용에만 씁니다.
- 검사 명령: `grep -nE '\*\*|§|—|–|·|~' <파일>`

## 코드 수정 원칙

- `_core/`와 루트 문서 변경은 `core/<짧은 설명>` 브랜치에서 하고, PR 제목은 `[core] <설명>`으로 씁니다.
- Python 3.11 이상(tomllib), 외부 의존성은 openpyxl만 씁니다.
- 수집기를 바꾸면 `META collector` 버전 문자열을 올리고 시범 서버 1대로 출력 길이와 소요 시간을 확인합니다.
- 판정 로직을 바꾸면 기존 RUN_DIR로 재판정해서 차이를 확인하고, 커밋 메시지에 판정이 달라지는 경우를 적습니다.
- 러너를 고칠 때는 PATH 앞에 가짜 `aws` 스크립트를 둔 시험 환경(SWEEP_RUNS는 임시 폴더)에서 inventory, ssm, judge 흐름을 돌려 봅니다.
- Linux 수집기는 로컬 Docker 컨테이너로 먼저 시험할 수 있습니다.
  - 제품을 설치한 컨테이너 안에서 `bash /core/scan_linux.sh`를 실행합니다(리포 `_core`를 읽기 전용으로 마운트).
  - 컨테이너 프로세스 탐지는 `docker run --pid=container:<대상>`으로 띄운 수집용 컨테이너에서 시험합니다.
  - 컨테이너 루트는 overlay라 FIND 구간이 루트를 보지 않습니다. FIND를 시험할 때는 `MNTS=/`로 바꾼 사본을 씁니다.

## 구조

```
AGENTS.md, CLAUDE.md, README.md
INDEX.md, CVE_INDEX.csv         _core/sweep index 가 생성
<취약점ID>/README.md            사람용 요약 (영향 버전, 판정 주의점)
<취약점ID>/AGENTS.md            이 취약점 전용 에이전트 지침 (CLAUDE.md가 불러옴)
<취약점ID>/criteria.toml        판정 기준표
_core/sweep                     진입점
_core/*.sh, *.ps1               수집기, 러너 (출력 형식은 _core/COLLECTORS.md)
_core/vsweep/                   판정, 보고서, 색인 (Python)
_core/templates/                새 취약점 폴더와 고객 설정, 보고 문안 템플릿
```
