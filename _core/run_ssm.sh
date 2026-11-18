#!/usr/bin/env bash
# 2단계: SSM Run Command로 수집기 실행 후 결과 회수 (읽기 전용 스크립트만 실행)
# 보통 _core/sweep ssm <고객> <취약점ID> linux|windows <instance-id...|@targets_linux.txt> 로 실행한다.
# 직접 실행: _core/run_ssm.sh <RUN_DIR> linux|windows <instance-id>... (@파일이면 RUN_DIR 안의 목록 파일을 읽음)
# 환경변수: CONC(동시 실행 수, 기본 5), TIMEOUT(인스턴스별 실행 제한 초, 기본 1800), AWS_REGION
# 출력: RUN_DIR/hosts/<instance-id>.tsv, RUN_DIR/hosts/<instance-id>.invocation.json, RUN_DIR/scan_log.tsv에 한 줄씩 추가
# S3 버킷을 만들지 않고 API로 출력을 받는다(인스턴스당 24,000자 한도). 마지막 줄 END로 완주 여부를 판단한다.
set -euo pipefail
RUN_DIR=$(cd "${1:?RUN_DIR 필요}" && pwd); OS=${2:?linux 또는 windows}; shift 2
CORE=$(cd "$(dirname "$0")" && pwd)
if [ -f "$RUN_DIR/../config.env" ]; then set -a; . "$RUN_DIR/../config.env"; set +a; fi
REGION=${AWS_REGION:-ap-northeast-2}
export AWS_PAGER=""
OUT="$RUN_DIR/hosts"; mkdir -p "$OUT"

IDS=()
for a in "$@"; do
  if [[ $a == @* ]]; then more=(); read -r -a more < "$RUN_DIR/${a#@}" || true; IDS+=("${more[@]}"); else IDS+=("$a"); fi
done
[ ${#IDS[@]} -gt 0 ] || { echo "대상 인스턴스 없음" >&2; exit 1; }

if [ "$OS" = linux ]; then
  DOC=AWS-RunShellScript
  B64=$(base64 < "$CORE/scan_linux.sh" | tr -d '\n')
  # AWS-RunShellScript는 sh로 실행될 수 있어서 bash로 확실히 돌리도록 스크립트를 인자로 넘긴다
  CMD="bash -c \"\$(printf %s '$B64' | base64 -d)\""
elif [ "$OS" = windows ]; then
  DOC=AWS-RunPowerShellScript
  CMD=$(cat "$CORE/scan_windows.ps1")
else
  echo "OS는 linux 또는 windows" >&2; exit 1
fi
PARAMS=$(python3 -c 'import json,sys; print(json.dumps({"commands":[sys.argv[1]],"executionTimeout":[sys.argv[2]]}))' "$CMD" "${TIMEOUT:-1800}")

CID=$(aws ssm send-command --region "$REGION" --document-name "$DOC" --instance-ids "${IDS[@]}" \
  --parameters "$PARAMS" --comment "nxt-vuln-sweep read-only inventory" \
  --max-concurrency "${CONC:-5}" --max-errors 100% --timeout-seconds 600 \
  --query 'Command.CommandId' --output text)
echo "CommandId: $CID ($OS, ${#IDS[@]}대)"
printf '%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$CID" "$OS" "${IDS[*]}" >> "$RUN_DIR/commands.log"

while :; do
  st=$(aws ssm list-commands --region "$REGION" --command-id "$CID" --query 'Commands[0].Status' --output text)
  case "$st" in Success|Failed|TimedOut|Cancelled) break ;; esac
  sleep 15
done
echo "Command status: $st"

for iid in "${IDS[@]}"; do
  aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$iid" --output json > "$OUT/$iid.invocation.json" || true
  python3 -c '
import json, sys, datetime
inv, tsv, iid, cid, log = sys.argv[1:6]
try:
    d = json.load(open(inv))
except Exception:
    d = {}
out = d.get("StandardOutputContent", "") or ""
open(tsv, "w").write(out)
lines = out.rstrip().splitlines()
done = bool(lines) and lines[-1].startswith("END")
st = d.get("Status", "fetch-failed")
err = (d.get("StandardErrorContent", "") or "")[:160].replace("\n", " ").replace("\t", " ")
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
open(log, "a").write(f"{iid}\tSSM\t{st}\t{len(out)}\t{done}\t{cid}\t{now}\n")
print(f"{iid}\t{st}\tchars={len(out)}\tcomplete={done}\t{err}")
' "$OUT/$iid.invocation.json" "$OUT/$iid.tsv" "$iid" "$CID" "$RUN_DIR/scan_log.tsv"
done
