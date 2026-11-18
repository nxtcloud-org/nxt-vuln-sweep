# AGENTS.md (<취약점ID>)

이 폴더의 취약점을 다루는 에이전트 지침입니다. 리포 루트 [AGENTS.md](../AGENTS.md)의 절대 규칙이 항상 먼저이고, 이 문서는 이 취약점에만 해당하는 내용을 더합니다. 둘이 충돌하면 루트 규칙을 따르고 사용자에게 알립니다.

- 사람용 요약: [README.md](README.md)
- 판정 기준표: [criteria.toml](criteria.toml)
- 작업 브랜치: `set/<취약점ID>` 또는 `single/<CVE-ID>`

## 이 취약점

- 무엇인지: 제품, 취약점 종류, 원문 개정 번호를 한두 줄로 적습니다.
- 점검 대상 제품: 판정기가 다루는 제품(criteria의 [java], [mysql], [oracle_home] 등)을 적습니다.
- 수집기: 기본 수집기로 충분한지 적습니다. 확장했다면 무엇을 바꿨는지와 core 브랜치 PR을 적습니다.

## 점검 절차

```bash
V=<취약점ID>; C=<고객>
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

- 자산 조회 후: RDS, Lambda, 컨테이너 등 서버 밖에서 확인할 것을 적습니다.
- 수집 후: 이 취약점만의 확인 사항(설정값, 특정 파일 등)을 적습니다.

## 판정 검토 포인트

`_core/sweep judge` 다음에 findings.csv에서 확인할 것을 적습니다.

- 버전 체계의 함정(자릿수, 파생 빌드 번호 차이 등)
- 판정기가 `확인 필요`로 남기는 항목과 사람이 대조하는 방법
- 이 공지와 무관한 제품으로 분류해야 하는 것

## 보고 문안 가이드 (notes.toml)

- key_findings에 꼭 들어갈 것: P1 서버, 발견되지 않은 공지 대상 제품 등
- recommendations에 꼭 들어갈 것: 라이선스, 재기동, 벤더 패치 빌드 확인 등
- 쓰지 말아야 할 표현: 2차 보도를 판정 근거처럼 쓰는 것 등

## 기준표 갱신 (원문이 개정될 때)

- 원문의 개정 이력을 확인하는 위치와, 값이 바뀌었을 때 고칠 곳을 적습니다.
- 원문 읽는 방법: 직접 조회가 되는지, 브라우저 추출이 필요한지, 표 구조
- 이 폴더의 작업 브랜치에서 고치고 `_core/sweep index`로 색인을 갱신합니다.

## 하지 말 것

- 2차 출처의 버전, 조건을 criteria.toml에 넣지 않습니다.
- 이 취약점만의 금지 사항을 적습니다.
