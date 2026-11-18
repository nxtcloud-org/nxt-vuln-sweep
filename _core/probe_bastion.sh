#!/usr/bin/env bash
# SSM이 없는 서버의 SSH 접속 계정 확인 (bastion 경유, 키 인증만 시도, 비밀번호 사용 안 함)
# 보통 _core/sweep probe <고객> <취약점ID> <사설IP>... 로 실행한다. 직접 실행: _core/probe_bastion.sh <RUN_DIR> <private-ip>...
# 22번 포트 도달 여부와 ec2-user, rocky, centos, ubuntu, admin 순으로 키 로그인과 sudo -n 가능 여부를 출력한다.
set -uo pipefail
RUN_DIR=$(cd "${1:?RUN_DIR 필요}" && pwd) || exit 1; shift
if [ -f "$RUN_DIR/../config.env" ]; then set -a; . "$RUN_DIR/../config.env"; set +a; fi
: "${BASTION:?config.env에 BASTION 필요}" "${BASTION_KEY:?config.env에 BASTION_KEY 필요}"
KH="$RUN_DIR/known_hosts"
KEY=${BASTION_KEY/#\~/$HOME}
for h in "$@"; do
  port=$(timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR "$BASTION" "timeout 3 bash -c '</dev/tcp/$h/22' && echo open || echo closed" 2>/dev/null | tail -1)
  if [ "$port" != open ]; then echo "$h	port22=${port:-unknown}"; continue; fi
  ok=""
  for u in ec2-user rocky centos ubuntu admin; do
    r=$(timeout 25 ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KH" -o LogLevel=ERROR \
      -i "$KEY" -J "$BASTION" "$u@$h" 'echo OK; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"; sudo -n true 2>/dev/null && echo SUDO_OK || echo SUDO_NO' 2>/dev/null | tr '\n' ' ')
    case "$r" in OK*) echo "$h	user=$u	${r#OK }"; ok=1; break ;; esac
  done
  [ -n "$ok" ] || echo "$h	port22=open	키 로그인 실패(보유 키로 접속 불가)"
done
