#!/bin/bash
# nxt-vuln-sweep 호스트 수집기 (Linux). 공지와 무관하게 Java, MySQL, Oracle 계열, nginx 계열 설치/실행 정보를 모은다.
# 출력 형식은 _core/COLLECTORS.md 참고. 탐지 대상을 늘릴 때는 FIND 패턴과 README를 함께 고친다.
# 읽기 전용: 패키지 목록, 파일, /proc 조회와 버전 출력(java -version 등)만 하고 아무것도 설치하거나 바꾸지 않는다.
# nginx 바이너리는 실행하지 않고(nginx -t, -T는 로그 파일과 임시 디렉터리를 만들 수 있음) 내장 문자열만 읽는다.
# 출력: 탭 구분 한 줄이 발견 항목 하나 (TYPE<TAB>필드...). SSM 출력 한도(24,000자)를 넘지 않게 항목별 상한을 둔다.
# 마지막 줄이 END 이면 끝까지 실행된 것이다.
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
renice -n 19 -p $$ >/dev/null 2>&1
ionice -c3 -p $$ >/dev/null 2>&1
T0=$(date +%s)

o() { local IFS=$'\t'; printf '%s\n' "$*"; }
# 같은 줄 제거 + (TYPE, 2번째 필드) 조합별로 최대 $1 줄까지만 출력
capk() { awk -F'\t' -v n="$1" '!s[$0]++ { k=$1 FS $2; c[k]++; if (c[k] <= n) print } END { for (k in c) if (c[k] > n) printf "TRUNC\t%s\t%d\n", k, c[k] }'; }
# JAVA_HOME 후보의 release 파일에서 버전 정보를 한 줄로 (JDK 8의 jre 하위 경로도 고려해 상위 디렉터리까지 확인)
relvars() {
  local f
  for f in "$1/release" "$(dirname "$1")/release"; do
    if [ -f "$f" ]; then
      grep -E '^(JAVA_VERSION|JAVA_RUNTIME_VERSION|IMPLEMENTOR|IMPLEMENTOR_VERSION|GRAALVM_VERSION)=' "$f" 2>/dev/null | tr -d '"' | tr '\n' ' '
      return
    fi
  done
}
shortpath() { sed -E 's#^/var/lib/docker/overlay2/([0-9a-f]{12})[0-9a-f]*/diff#docker:\1#; s#^/var/lib/containerd/io\.containerd\.snapshotter\.v1\.overlayfs/snapshots/([0-9]+)/fs#containerd:\1#'; }

# ---- nginx 도우미: 바이너리 내장 문자열(버전, configure 인자)과 설정 파일의 지시어 사용 여부
ngx_banner() { grep -aoE '(nginx|openresty|Tengine|Angie|freenginx)/[0-9]+(\.[0-9]+){1,3}|nginx-plus-r[0-9]+(-p[0-9]+)?' "$1" 2>/dev/null | sort -u | head -5 | paste -sd' ' -; }
ngx_mods() { grep -aoE -- '--with-(http_v2_module|http_v3_module|http_ssl_module|mail|mail_ssl_module|stream|stream_ssl_module|stream_ssl_preread_module)(=dynamic)?' "$1" 2>/dev/null | sort -u | paste -sd' ' -; }
ngx_cfgopt() { grep -aoE -- "--$2=[^ \"']+" "$1" 2>/dev/null | head -1 | cut -d= -f2-; }
# 루트($1, 예: /proc/<pid>/root) 안의 경로($2)를 실제 파일로. 컨테이너 안의 절대 경로 심볼릭 링크는 루트 기준으로 다시 붙인다.
ngx_real() {
  local root=$1 f=$2 t i
  for i in 1 2 3 4 5; do
    [ -L "$root$f" ] || break
    t=$(readlink "$root$f")
    case "$t" in /*) f=$t ;; *) f="$(dirname "$f")/$t" ;; esac
  done
  printf '%s' "$f"
}
# 메인 설정($2)부터 include를 따라가며 읽을 수 있는 파일을 출력한다 (최대 300개). 상대 경로는 메인 설정 파일의 디렉터리 기준
ngx_conf_files() {
  local root=$1 base n=0 f g inc seen=" "
  local -a queue=("$2")
  base=$(dirname "$2")
  while [ ${#queue[@]} -gt 0 ] && [ $n -lt 300 ]; do
    f=$(ngx_real "$root" "${queue[0]}"); queue=("${queue[@]:1}")
    case "$seen" in *" $f "*) continue ;; esac
    seen="$seen$f "
    [ -f "$root$f" ] && [ -r "$root$f" ] || continue
    n=$((n + 1)); printf '%s\n' "$root$f"
    while IFS= read -r inc; do
      case "$inc" in /*) ;; *) inc="$base/$inc" ;; esac
      for g in $root$inc; do { [ -e "$g" ] || [ -L "$g" ]; } && queue+=("${g#"$root"}"); done   # -L: 루트 밖을 가리키는 절대 경로 링크
    done < <(sed -e 's/#.*//' "$root$f" | tr ';{}' '\n\n\n' | sed -nE "s/^[[:space:]]*include[[:space:]]+[\"']?([^\"' ]+)[\"']?[[:space:]]*$/\1/p")
  done
}
# 설정 파일 목록(stdin) -> 지시어 사용 여부. 설정 내용(호스트명, 경로, 값)은 출력하지 않는다
ngx_conf_flags() {
  while IFS= read -r f; do cat "$f" 2>/dev/null; echo; done | sed -e 's/#.*//' | tr ';{}' '\n\n\n' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | awk '
    /^listen[ \t]/ { if ($0 ~ /[ \t]http2([ \t]|$)/) h2 = 1; if ($0 ~ /[ \t]quic([ \t]|$)/) q = 1; if ($0 ~ /[ \t]ssl([ \t]|$)/) s = 1; if ($0 ~ /[ \t]proxy_protocol([ \t]|$)/) pp = 1 }
    /^http2[ \t]+on$/ { h2 = 1 }
    /^http3[ \t]+on$/ { q = 1 }
    /^ssl[ \t]+on$/ { s = 1 }
    /^ssl_protocols[ \t]/ { sp = 1; if ($0 ~ /TLSv1\.3/) t13 = 1 }
    /^resolver[ \t]/ { rs = 1 }
    /^(proxy|grpc|fastcgi|uwsgi|scgi|memcached)_pass[ \t]/ { ps = 1; if ($0 ~ /\$/) pv = 1 }
    /^mirror[ \t]/ && $2 != "off" { mr = 1 }
    /^ssi[ \t]+on$/ { ssi = 1 }
    /^mail$/ { ml = 1 }
    /^stream$/ { st = 1 }
    /^ssl_preread[ \t]+on$/ { pr = 1 }
    /^ssl_verify_client[ \t]+(on|optional|optional_no_ca)$/ { vc = 1 }
    /^ssl_certificate[ \t].*\$/ { cv = 1 }
    /^proxy_protocol[ \t]+on$/ { pp = 1 }
    /^alias[ \t]/ { al = 1 }
    /^try_files[ \t]/ { tf = 1 }
    END { printf "http2=%d quic=%d ssl=%d ssl_protocols=%d tls13=%d resolver=%d pass=%d proxy_var=%d mirror=%d ssi=%d mail=%d stream=%d ssl_preread=%d verify_client=%d cert_var=%d proxy_protocol=%d alias=%d try_files=%d",
                 h2, q, s, sp, t13, rs, ps, pv, mr, ssi, ml, st, pr, vc, cv, pp, al, tf }'
}
# 컨테이너 루트($1)의 nginx 패키지 버전 (dpkg, apk). rpm DB는 읽지 않는다
ngx_ctr_pkg() {
  local v
  v=$(awk '/^Package: /{p=$2} /^Version: /{ if (p ~ /^(nginx|nginx-core|nginx-full|nginx-light|nginx-extras|openresty|angie)$/) { print $2; exit } }' "$1/var/lib/dpkg/status" 2>/dev/null)
  [ -n "$v" ] && { printf 'dpkg:%s' "$v"; return; }
  v=$(awk -F: '/^P:/{p=$2} /^V:/{ if (p ~ /^(nginx|openresty|angie)$/) { print $2; exit } }' "$1/lib/apk/db/installed" 2>/dev/null)
  [ -n "$v" ] && printf 'apk:%s' "$v"
}

# ---- META
. /etc/os-release 2>/dev/null
o META collector "scan_linux.sh 2026.11.2"
o META host "$(hostname)"
o META os "${PRETTY_NAME:-unknown}"
o META os_id "${ID:-unknown}-${VERSION_ID:-}"
o META arch "$(uname -m)"
o META cpu "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
o META avx512vbmi "$(grep -qw avx512vbmi /proc/cpuinfo && echo yes || echo no)"
# SCTP 커널 모듈 상태 (참고 정보): 로드 여부, 커널 내장 여부, modprobe 차단 설정 여부
o META sctp "loaded=$(grep -qw '^sctp' /proc/modules 2>/dev/null && echo 1 || echo 0) builtin=$(grep -qs '/sctp\.ko' "/lib/modules/$(uname -r)/modules.builtin" && echo 1 || echo 0) blocked=$(grep -rqsE '^[[:space:]]*(install[[:space:]]+sctp[[:space:]]+/(usr/)?bin/(false|true)|blacklist[[:space:]]+sctp)([[:space:]]|$)' /etc/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d /run/modprobe.d && echo 1 || echo 0)"

# ---- PKG: 패키지 관리자로 설치된 Java, MySQL, Oracle 계열, nginx 계열
{
  command -v rpm >/dev/null 2>&1 && rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Status}\n' | awk -F'\t' '$3 == "installed" {print $1 "\t" $2}'
} 2>/dev/null | awk -F'\t' '{ n = tolower($1) } n ~ /(jdk|jre|java|corretto|temurin|zulu|graalvm|mysql|mariadb|percona|oracle|virtualbox|helidon|nginx|openresty|tengine|angie)/ && n !~ /javascript|javapackages|ca-certificates-java|java-common|^tzdata|certbot/ { print "PKG\t" $1 "\t" $2 }' | capk 60

# ---- PROC: 실행 중인 JVM(libjvm.so를 올린 모든 프로세스, jsvc 포함)과 MySQL/Oracle DB 프로세스
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  comm=$(cat "$d/comm" 2>/dev/null) || continue
  ljline=$(grep -m1 'libjvm\.so' "$d/maps" 2>/dev/null)
  case "$comm" in
    mysqld|mariadbd|tnslsnr|ora_pmon_*) ;;
    *) [ -n "$ljline" ] || continue ;;
  esac
  exe=$(readlink "$d/exe" 2>/dev/null)
  usr=$(stat -c %U "$d" 2>/dev/null)
  cg=$(grep -m1 -oE '(docker|containerd|kubepods|libpod)[^/]{0,20}' "$d/cgroup" 2>/dev/null | head -1)
  rv=""; stale=""
  if [ -n "$ljline" ]; then
    lj=$(printf '%s' "$ljline" | grep -oE '/[^ ]*/libjvm\.so')
    case "$ljline" in *"(deleted)"*) stale="LIBJVM_DELETED(패치 후 미재기동 가능성)";; esac
    jh=$(printf '%s' "$lj" | sed -E 's#/lib/([a-z0-9_]+/)?(server|client|zero|minimal)/libjvm\.so$##')
    rv=$(relvars "$d/root$jh")
    [ -n "$rv" ] || rv="libjvm=$lj"
  fi
  hint=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | awk 'NR==1 {next} sk {sk=0; next} /^(-cp|-classpath|--class-path|-p|--module-path)$/ {sk=1; next} /^-jar$/ {getline; print; exit} /^-D(catalina\.base|weblogic\.Name|kafka\.logs\.dir|es\.path\.home|jenkins\.home)=/ {print; exit} /^-/ {next} {print; exit}' | grep -viE 'pass|secret|token|key' | cut -c1-100)
  o PROC "$p" "$usr" "$comm" "$exe" "${cg:-host}" "$rv" "$hint" "$stale"
done | capk 40

# ---- NGINX: 실행 중인 nginx 계열 master 프로세스(호스트, 컨테이너)와 설정의 지시어 사용 여부(NGXCONF)
# 위치: host 또는 <런타임>:<컨테이너 ID 12자리>. 컨테이너 파일은 /proc/<pid>/root 로 읽는다
for d in /proc/[0-9]*; do
  comm=$(cat "$d/comm" 2>/dev/null) || continue
  case "$comm" in nginx|openresty|angie|tengine|nginx-ingress-c|nginx-ingress) ;; *) continue ;; esac
  cl=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
  case "$cl" in *"worker process"*|*"cache manager"*|*"cache loader"*|*"helper process"*) continue ;; esac
  p=${d#/proc/}
  exe=$(readlink "$d/exe" 2>/dev/null)
  cid=$(grep -oE '[0-9a-f]{64}' "$d/cgroup" 2>/dev/null | head -1 | cut -c1-12)
  rt=$(grep -oE 'kubepods|docker|containerd|crio|libpod' "$d/cgroup" 2>/dev/null | head -1)
  loc=host; [ -n "$cid" ] && loc="${rt:-container}:$cid"
  case "$comm" in
    nginx-ingress-c) o NGXCTL "$loc" "$p" "ingress-nginx" "$exe"; continue ;;   # Kubernetes 커뮤니티 ingress-nginx 컨트롤러
    nginx-ingress) o NGXCTL "$loc" "$p" "f5-nginx-ingress" "$exe"; continue ;;  # F5 NGINX Ingress Controller
  esac
  stale=""; case "$exe" in *" (deleted)") stale="EXE_DELETED(교체 후 미재기동 가능성)" ;; esac
  conf=$(printf '%s\n' "$cl" | grep -oE '(^| )-c +[^ ]+' | head -1 | awk '{print $2}')
  [ -n "$conf" ] || conf=$(ngx_cfgopt "$d/exe" conf-path)
  pre=$(printf '%s\n' "$cl" | grep -oE '(^| )-p +[^ ]+' | head -1 | awk '{print $2}')
  [ -n "$pre" ] || pre=$(ngx_cfgopt "$d/exe" prefix)
  [ -n "$conf" ] || conf=conf/nginx.conf
  case "$conf" in /*) ;; *) conf="${pre:-/usr/local/nginx}/$conf" ;; esac
  pkgv=""; [ "$loc" != host ] && pkgv=$(ngx_ctr_pkg "$d/root")
  o NGINX "$loc" "${exe% (deleted)}" "$(ngx_banner "$d/exe")" "$(ngx_mods "$d/exe")" "pid $p" "$stale" "$pkgv"
  files=$(ngx_conf_files "$d/root" "$conf")
  o NGXCONF "$loc" "$p" "$conf" "files=$(printf '%s' "$files" | grep -c .)" "$(printf '%s\n' "$files" | grep . | ngx_conf_flags)"
done | capk 30

# ---- ORACLE: oraInventory와 oratab에 등록된 Oracle Home (DB, WebLogic/FMW), 적용 패치 목록
INV=$(awk -F= '/^inventory_loc/ {print $2}' /etc/oraInst.loc 2>/dev/null)
HOMES=$( { [ -n "$INV" ] && grep -oE 'LOC="[^"]+"' "$INV/ContentsXML/inventory.xml" 2>/dev/null | cut -d'"' -f2; awk -F: '!/^#/ && NF >= 2 && $2 != "" {print $2}' /etc/oratab 2>/dev/null; } | sort -u)
for h in $HOMES; do
  [ -d "$h" ] || continue
  own=$(stat -c %U "$h" 2>/dev/null)
  o OHOME "$h" "$own"
  if [ -f "$h/inventory/registry.xml" ]; then
    grep -oE '<distribution [^>]*>' "$h/inventory/registry.xml" | grep -oE '(name|version|status)="[^"]*"' | paste -sd' ' - | sed "s#^#OREG\t$h\t#"
  fi
  if [ -x "$h/OPatch/opatch" ]; then
    op=$(timeout 120 su -s /bin/bash "$own" -c "ORACLE_HOME='$h' '$h/OPatch/opatch' lspatches" </dev/null 2>&1)
    # 오래된 OPatch(11.x)는 lspatches를 지원하지 않으므로 lsinventory에서 제품/패치 줄만 추린다
    if printf '%s' "$op" | grep -qE 'error code|syntax'; then
      op=$(timeout 180 su -s /bin/bash "$own" -c "ORACLE_HOME='$h' '$h/OPatch/opatch' lsinventory" </dev/null 2>&1 | grep -E '^(Patch |Oracle [A-Za-z].*[0-9]+\.[0-9]|There are|Installed Top-level)')
    fi
    printf '%s\n' "$op" | grep -vE '^[[:space:]]*$|OPatch succeeded' | head -15 | sed "s#^#OPATCH\t$h\t#"
  fi
done

# ---- DOCKER: 실행 중인 컨테이너와 이미지
if command -v docker >/dev/null 2>&1; then
  timeout 20 docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | sed 's/^/DOCKER\tps\t/' | capk 30
fi

# ---- FIND: 로컬 디스크 전체(tarball 설치 JDK, 앱 번들 JDK, 컨테이너 이미지 레이어 포함)
MNTS=$(findmnt -rn -o TARGET,FSTYPE 2>/dev/null | awk '$2 ~ /^(ext2|ext3|ext4|xfs|btrfs|zfs)$/ {print $1}' | sort -u)
[ -n "$MNTS" ] || MNTS=/
FOUND=$(for m in $MNTS; do
  m=$(printf '%b' "$m")
  timeout 900 find "$m" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o -type f \
    \( -path '*/bin/java' -o -path '*/bin/mysqld' -o -path '*/sbin/mysqld' -o -path '*/bin/mariadbd' -o -path '*/sbin/mariadbd' -o -path '*/bin/mysql' -o -path '*/bin/mysqlsh' \
       -o -name weblogic.jar -o -name 'helidon-*.jar' -o -name ords.war -o -name VBoxManage \
       -o -path '*/sbin/nginx' -o -path '*/bin/nginx' -o -path '*/bin/openresty' -o -path '*/sbin/angie' \) -print 2>/dev/null
done | sort -u)
printf '%s\n' "$FOUND" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in /var/lib/docker/*|/var/lib/containerd/*|/var/lib/containers/*) loc=image ;; *) loc=host ;; esac
  sp=$(printf '%s' "$f" | shortpath)
  case "$(basename "$f")" in
    java)
      rv=$(relvars "$(dirname "$(dirname "$f")")")
      vv=""; [ "$loc" = host ] && vv=$(timeout 10 "$f" -version </dev/null 2>&1 | head -2 | tr '\t\n' '  ')
      o JAVA "$loc" "$sp" "$rv" "$vv" ;;
    mysqld|mariadbd|mysql|mysqlsh)
      vv=""; [ "$loc" = host ] && vv=$(timeout 10 "$f" --version </dev/null 2>&1 | head -1 | tr '\t' ' ')
      o MYSQL "$loc" "$sp" "$vv" ;;
    nginx|openresty|angie)
      bn=$(ngx_banner "$f")
      [ -n "$bn" ] && o NGINX "$loc" "$sp" "$bn" "$(ngx_mods "$f")" "" "" "" ;;   # 버전 문자열이 없으면 nginx가 아닌 파일
    *) o FILE "$loc" "$sp" ;;
  esac
done | capk 50

o END "$(( $(date +%s) - T0 ))s"
