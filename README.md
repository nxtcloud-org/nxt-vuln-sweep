# nxt-vuln-sweep

보안 공지(Oracle CPU/CSPU, OpenSSL, Log4j 등)가 나왔을 때 AWS 환경의 서버 전체를 읽기 전용으로 점검하고, 공지의 영향 버전과 대조해 보고서를 만드는 도구입니다.

## 구조

리포 루트의 폴더 하나가 취약점 하나입니다. 공통 점검 엔진은 `_core/`에 있습니다.

```
nxt-vuln-sweep/
├── INDEX.md                          취약점 목록 (자동 생성)
├── CVE_INDEX.csv                     CVE -> 취약점 폴더 색인 (자동 생성)
├── 2026-11-17_oracle_cspunov2026/    취약점 세트 (예): 발표일_벤더_공지키
│   ├── README.md                     사람용 요약 (영향 버전, 판정 주의점)
│   ├── AGENTS.md, CLAUDE.md          이 취약점 전용 에이전트 지침 (점검 절차, 판정 검토, 기준표 갱신)
│   └── criteria.toml                 판정 기준표 (영향 버전, CVE 목록)
├── CVE-2021-44228/                   단일 CVE (예)
└── _core/                            공통 엔진: 수집기, 러너, 판정기, 보고서, 템플릿
```

### 폴더 이름 규칙

| 종류 | 형식 | 예 |
|---|---|---|
| 취약점 세트 (여러 CVE를 묶은 벤더 공지) | `YYYY-MM-DD_<벤더>_<공지키>` 소문자 | `2026-11-17_oracle_cspunov2026`, `2027-01-19_oracle_cpujan2027`, `2026-12-02_aws_alas-2026-1234` |
| 단일 CVE | `CVE-YYYY-NNNN` 원문 표기 그대로 | `CVE-2021-44228`, `CVE-2026-114938` |

- 날짜는 벤더 공지의 발표일이고, 공지키는 벤더가 붙인 식별자입니다.
- 벤더 공지에 CVE가 하나뿐이면 단일 CVE 폴더로 만듭니다.
- 이미 세트 폴더에 들어 있는 CVE를 따로 다뤄야 할 때(긴급 재점검 등)만 별도 CVE 폴더를 만듭니다.
- 어떤 CVE를 이미 다뤘는지는 `grep CVE-2026-114938 CVE_INDEX.csv`로 찾습니다.
- 같은 CVE가 여러 폴더에 있으면 색인에 폴더별로 한 줄씩 남습니다.
- 공지가 개정되면(Rev 2 등) 같은 폴더의 criteria.toml을 고치고 `revision`을 올립니다. 이전 값은 git 이력으로 남습니다.

### 브랜치 규칙

취약점 하나가 브랜치 하나, PR 하나입니다.

| 작업 | 브랜치 | PR 제목 |
|---|---|---|
| 단일 CVE 등록, 수정 | `single/CVE-YYYY-NNNN` | `[single] CVE-YYYY-NNNN: <제품, 요약>` |
| 취약점 세트 등록, 수정 | `set/YYYY-MM-DD_<벤더>_<공지키>` | `[set] <세트ID>: <공지 제목>` |
| 엔진, 문서 변경 (_core/, 루트 문서) | `core/<짧은 설명>` | `[core] <설명>` |

- 브랜치 이름의 ID는 폴더 이름과 같게 씁니다.
- 취약점을 등록하다가 수집기나 판정기를 고쳐야 하면 `core/` 브랜치로 먼저 올리고, 취약점 브랜치는 그 위에서 작업합니다.
- INDEX.md, CVE_INDEX.csv는 각 브랜치에서 `_core/sweep index`로 다시 생성해서 함께 커밋합니다. 충돌이 나면 다시 생성하면 됩니다.

## 고객 정보는 리포에 두지 않습니다

공개 리포입니다. 고객 설정(AWS 프로파일, bastion, 키 경로)과 점검 결과(서버 목록, 취약점 목록, 보고서)는 리포 밖 `$SWEEP_RUNS`(기본: 리포 상위 폴더의 `vuln-sweep-runs/`)에 저장됩니다. 경로가 리포 안을 가리키면 실행을 거부하고, .gitignore도 결과 파일 형식을 막아 둡니다.

## 에이전트에게 맡기기

이 리포는 에이전트(Claude Code 등)가 운영하는 것을 전제로 합니다. 지침은 두 단계입니다.

- 루트 [AGENTS.md](AGENTS.md): 모든 작업에 적용되는 절차, 안전 규칙, 알려진 함정
- `<취약점ID>/AGENTS.md`: 그 취약점의 점검 절차, 판정 검토 포인트, 보고 문안 가이드, 기준표 갱신 방법

Claude Code는 각 위치의 `CLAUDE.md`를 통해 이 문서들을 자동으로 읽습니다.

리포 루트에서 에이전트를 실행하고 이렇게 요청합니다.

| 하고 싶은 일 | 요청 예 |
|---|---|
| 새 공지 후보 확인 | `새 공지 후보 확인해줘` 또는 `intake Issue 처리해줘` |
| 새 취약점 등록 | `이 공지 등록해줘 https://www.oracle.com/security-alerts/cspudec2026.html` |
| 단일 CVE 등록 | `CVE-2026-12345 등록해줘. 원문은 <URL>` |
| 고객 점검 | `acme 고객(프로파일 acme-sso)에 2026-12-15_oracle_cspudec2026 점검 진행해줘. bastion은 acme-bastion` |
| 이미 다룬 CVE인지 확인 | `CVE-2026-114938 다룬 적 있어?` |
| 보고서 다시 만들기 | `acme 2026-12-15_oracle_cspudec2026 결과로 엑셀 다시 만들어줘` |
| 수집 대상 확장 | `OpenSSL 공지 대응하게 수집기랑 판정기 확장해줘` |

에이전트는 운영 서버에서 실행하기 전에 대상과 범위를 확인하고, 시범 1-2대 결과를 보고한 뒤 전체로 넓힙니다. SSO 로그인처럼 사람이 해야 하는 단계는 사용자에게 요청합니다.

## 공지 후보 자동 수집

매일 GitHub Actions가 `_core/sweep intake --days 7 --issues`를 돌려, 아직 등록하지 않은 주요 공지를 `[intake]` Issue로 올립니다.

- 소스는 KISA 보호나라 보안공지(보안 업데이트 권고)입니다. 국내 기준으로 주요 벤더 업데이트만 올라오고, Oracle CPU/CSPU도 포함됩니다.
- Issue에는 KISA 상세 페이지의 CVE 목록과 참고 링크(벤더 원문)가 들어갑니다.
- 감시 목록(`_core/intake.toml`의 `[[watch]]`)에 든 제품만 후보가 됩니다. 고객 서버 스택 위주로 두었습니다.
- 후보는 등록 대상이 아니라 검토 대상입니다. 기준표 값은 벤더 원문으로 다시 확인해서 채웁니다.
- 등록하지 않기로 한 공지는 `[[dismissed]]`에 사유와 근거를 남깁니다.

## 직접 실행하기

```bash
_core/sweep help

V=2026-11-17_oracle_cspunov2026; C=acme
_core/sweep init $C                              # 고객 설정 생성 후 값 채우기
_core/sweep inventory $C $V                      # 1. AWS API 자산 조회, 대상 목록
_core/sweep ssm $C $V linux <instance-id>        # 2. 시범 1대
_core/sweep ssm $C $V linux @targets_linux.txt   #    전체
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep probe $C $V <사설IP>...               #    SSM 미관리 서버 접속 계정 확인
_core/sweep bastion $C $V <instance-id> <user> <사설IP>
_core/sweep judge $C $V                          # 3. 판정
_core/sweep notes $C $V                          # 4. 보고 문안 작성 후
_core/sweep export $C $V                         #    엑셀 생성
_core/sweep status $C $V                         # 진행 상황

_core/sweep intake                               # 공지 후보 찾기 (--issues --dry-run: 만들 Issue 미리 보기)
_core/sweep new 2026-12-15_oracle_cspudec2026    # 새 취약점 폴더
_core/sweep index                                # INDEX.md, CVE_INDEX.csv 갱신
```

요구 사항: AWS CLI v2, Python 3.11 이상, openpyxl(`pip install -r _core/requirements.txt`).

## 원칙

- 점검 대상 서버에는 아무것도 설치하거나 바꾸지 않습니다. 조회와 버전 출력만 합니다.
- 고객 AWS 계정에 S3 버킷 같은 리소스를 만들지 않습니다.
- 판정 기준은 벤더 공식 원문에서만 가져옵니다.

## 등록된 취약점

[INDEX.md](INDEX.md)를 봅니다.
