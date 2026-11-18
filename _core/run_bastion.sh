#!/usr/bin/env bash
# 2단계(보조): SSM 에이전트가 없는 Linux를 bastion 경유 SSH로 스캔
# 보통 _core/sweep bastion <고객> <취약점ID> ... 로 실행한다. 직접 실행: _core/run_bastion.sh <RUN_DIR> <instance-id> <user> <private-ip> [<instance-id> <user> <private-ip> ...]
# RUN_DIR/../config.env 에서 읽는 값:
#   BASTION      ~/.ssh/config 의 bastion Host 별칭 (ProxyJump 대상)
#   BASTION_KEY  대상 서버 접속용 키 파일 경로 (키 인증만 사용, 비밀번호 사용 안 함)
# 같은 _core/scan_linux.sh 를 sudo -n 으로 실행한다. 스크립트는 인자로 넘기므로 bastion과 대상 서버에 파일을 남기지 않는다.
set -uo pipefail
RUN_DIR=$(cd "${1:?RUN_DIR 필요}" && pwd) || exit 1; shift
CORE=$(cd "$(dirname "$0")" && pwd)
if [ -f "$RUN_DIR/../config.env" ]; then set -a; . "$RUN_DIR/../config.env"; set +a; fi
: "${BASTION:?config.env에 BASTION(ssh 별칭) 필요}" "${BASTION_KEY:?config.env에 BASTION_KEY 필요}"
KH="$RUN_DIR/known_hosts"
OUT="$RUN_DIR/hosts"; mkdir -p "$OUT"
B64=$(base64 < "$CORE/scan_linux.sh" | tr -d '\n')
while [ $# -ge 3 ]; do
  iid=$1 u=$2 ip=$3; shift 3
  timeout 1500 ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KH" -o LogLevel=ERROR \
    -i "${BASTION_KEY/#\~/$HOME}" -J "$BASTION" "$u@$ip" "sudo -n bash -c \"\$(printf %s '$B64' | base64 -d)\"" > "$OUT/$iid.tsv" 2> "$OUT/$iid.stderr"
  rc=$?
  last=$(tail -1 "$OUT/$iid.tsv" 2>/dev/null)
  done=$([[ $last == END* ]] && echo True || echo False)
  chars=$(wc -c < "$OUT/$iid.tsv" | tr -d ' ')
  printf '%s\tBastion(SSH)\trc=%s\t%s\t%s\t%s@%s\t%s\n' "$iid" "$rc" "$chars" "$done" "$u" "$ip" "$(date -u +%FT%TZ)" >> "$RUN_DIR/scan_log.tsv"
  echo "$iid	$u@$ip	rc=$rc	chars=$chars	complete=$done"
done
