# <공식 공지 제목 또는 CVE 이름>

| 항목 | 내용 |
|---|---|
| 취약점 ID | YYYY-MM-DD_vendor_key 또는 CVE-YYYY-NNNN (이 폴더명) |
| 원문 | https://... |
| 발표 | YYYY-MM-DD (Rev N) |
| 종류 | 취약점 세트(정기 패치, 여러 CVE) 또는 단일 CVE |
| 규모 | 패치 또는 CVE 수 |
| 기준표 | [criteria.toml](criteria.toml) |
| 기준표 작성 | 작성일, 원문 개정 번호 |

## 요약

- 어떤 제품의 어떤 취약점인지, 서버 인프라 점검에서 해당될 제품은 무엇인지 적습니다.
- 인증 없이 원격 공격 가능한지, 최고 CVSS, 실제 악용 여부(원문 기준)를 적습니다.

## 제품별 영향 버전

| 제품 | 영향 버전 | 최고 CVSS |
|---|---|---|

## 판정할 때 주의할 점

- 버전 체계, 파생 빌드 처리, 원문에 없는 조건(2차 보도) 등 판정에 영향을 주는 내용을 적습니다.
- 2차 출처 내용은 출처를 밝히고, 판정에 쓰는지 참고만 하는지 구분합니다.

## 원문 확인 방법

- 원문을 어떻게 읽었는지 적습니다(직접 조회, 브라우저 추출 등). 다음에 같은 벤더 공지를 등록할 때 다시 씁니다.

## 이 취약점 점검하기

수집기 변경: 없음 (기본 수집기로 대상 제품을 잡음) 또는 바꾼 내용

```bash
V=<이 폴더명>; C=<고객>
_core/sweep init $C                         # 처음 한 번, config.env 채우기
_core/sweep inventory $C $V
_core/sweep ssm $C $V linux <시범 1대>      # 시범 결과 확인 후 전체
_core/sweep ssm $C $V linux @targets_linux.txt
_core/sweep ssm $C $V windows @targets_windows.txt
_core/sweep judge $C $V
_core/sweep notes $C $V                     # notes.toml 작성
_core/sweep export $C $V
```

이 취약점만의 추가 확인 사항(RDS 엔진 버전, 특정 설정 확인 등)이 있으면 여기에 적습니다.
