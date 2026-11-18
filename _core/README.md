# _core

모든 취약점 폴더가 함께 쓰는 점검 엔진입니다. 실행은 진입점 `_core/sweep` 하나로 합니다(`_core/sweep help`).

| 파일 | 역할 |
|---|---|
| sweep | 진입점. 취약점 폴더와 고객 결과 폴더($SWEEP_RUNS)를 연결해서 아래 스크립트를 부름 |
| scan_linux.sh, scan_windows.ps1 | 대상 서버 안에서 도는 읽기 전용 수집기. 출력 형식은 [COLLECTORS.md](COLLECTORS.md) |
| api_inventory.sh | AWS API 자산 조회 (describe/list만) |
| run_ssm.sh | SSM Run Command로 수집기 실행, 결과 회수 |
| run_bastion.sh, probe_bastion.sh | SSM 미관리 서버를 bastion 경유 SSH로 수집, 접속 계정 확인 |
| vsweep/ | Python: targets(대상 목록), judge(판정), products(제품별 버전 해석), export_xlsx(보고서), build_index(색인) |
| templates/vuln/ | 새 취약점 폴더 템플릿 (README.md, AGENTS.md, CLAUDE.md, criteria.toml) |
| templates/run/ | 고객 설정(config.env)과 보고 문안(notes.toml) 템플릿 |

## 결과 폴더

고객 설정과 점검 결과는 리포 밖에 둡니다. `SWEEP_RUNS` 환경변수로 바꿀 수 있고, 기본값은 리포 상위 폴더의 `vuln-sweep-runs`입니다. 경로가 리포 안을 가리키면 `sweep`이 실행을 거부합니다.

```
$SWEEP_RUNS/<고객>/config.env
$SWEEP_RUNS/<고객>/SWEEPS.md                 점검 이력
$SWEEP_RUNS/<고객>/<취약점ID>/               RUN_DIR
  api/<리전>/, targets_*.txt, targets_unmanaged.tsv
  hosts/<instance-id>.tsv, scan_log.tsv, commands.log
  findings.csv, hosts_summary.csv, notes.toml, <취약점ID>_<고객>_점검결과.xlsx
```

같은 취약점을 같은 고객에게 다시 점검할 때는 이전 RUN_DIR을 `<취약점ID>.<날짜>`로 이름을 바꿔 보관한 뒤 새로 실행합니다.

## 요구 사항

AWS CLI v2, Python 3.11 이상, openpyxl(`pip install -r _core/requirements.txt`). bastion을 쓰면 `~/.ssh/config`에 bastion Host 별칭이 필요합니다.
