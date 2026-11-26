#!/bin/bash
# nxt-vuln-sweep 호스트 수집기 (Linux). 공지와 무관하게 Java, MySQL, Oracle 계열, nginx 계열, PostgreSQL, Apache httpd, Node.js mongodb 패키지의 설치/실행 정보와
# 실행 중인 커널(패키지, NFS 서버 사용 여부)을 모은다.
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

# ---- SW 도우미: PostgreSQL, Apache httpd, Node.js 앱의 mongodb 패키지 (레코드 SW, 형식은 COLLECTORS.md)
# 버전은 바이너리 내장 문자열로 읽는다(실행하지 않음). 컨테이너 파일은 /proc/<pid>/root 를 앞에 붙여 읽는다
sw_ver() {   # $1 제품, $2 파일
  case "$1" in
    postgresql) grep -aoE 'PostgreSQL [0-9]+(\.[0-9]+){0,2}(beta[0-9]+|rc[0-9]+)? (\([^)]{0,80}\) )?on ' "$2" 2>/dev/null | head -1 | awk '{print $2}' ;;
    postgresql-client) grep -aoE '(pg_dump|psql) \(PostgreSQL\) [0-9]+(\.[0-9]+){0,2}' "$2" 2>/dev/null | head -1 | awk '{print $3}' ;;
    httpd) grep -aoE 'Apache/2\.[0-9]+\.[0-9]+' "$2" 2>/dev/null | head -1 | cut -d/ -f2 ;;
    npm-mongodb) grep -q '"name": *"mongodb"' "$2" 2>/dev/null && grep -m1 -oE '"version": *"[^"]+"' "$2" | sed -E 's/.*"([^"]+)"$/\1/' ;;
  esac
}
# PostgreSQL 바이너리($2, 루트 $1 기준)와 같은 설치의 확장 라이브러리 존재 여부 (CVE 사용 조건 판단용)
pg_flags() {
  local root=$1 bin=$2 dir out="" x c hit
  [ -n "$bin" ] || { printf 'libdir=unknown'; return; }
  dir=$(dirname "$bin")
  for x in plperl pltcl dblink dict_int; do
    hit=0
    for c in "$dir/../lib" "$dir/../lib64/pgsql" "$dir/../lib/pgsql" "$dir/../lib/postgresql" /usr/lib64/pgsql /usr/lib/postgresql; do
      [ -e "$root$c/$x.so" ] && { hit=1; break; }
    done
    out="$out $x=$hit"
  done
  printf '%s' "${out# }"
}
# Apache 설정: 메인 설정($2, 루트 $1)부터 Include/IncludeOptional을 따라가며 파일 목록 출력 (최대 300개)
ap_conf_files() {
  local root=$1 conf=$2 sr n=0 f g inc seen=" "
  local -a queue=("$conf")
  sr=$(sed -nE 's/^[[:space:]]*ServerRoot[[:space:]]+"?([^"[:space:]]+)"?.*/\1/Ip' "$root$conf" 2>/dev/null | head -1)
  if [ -z "$sr" ]; then
    case "$(basename "$(dirname "$conf")")" in conf) sr=$(dirname "$(dirname "$conf")") ;; *) sr=$(dirname "$conf") ;; esac
  fi
  while [ ${#queue[@]} -gt 0 ] && [ $n -lt 300 ]; do
    f=${queue[0]}; queue=("${queue[@]:1}")
    case "$seen" in *" $f "*) continue ;; esac
    seen="$seen$f "
    if [ -d "$root$f" ]; then
      for g in "$root$f"/*; do [ -f "$g" ] && queue+=("${g#"$root"}"); done
      continue
    fi
    [ -f "$root$f" ] && [ -r "$root$f" ] || continue
    n=$((n + 1)); printf '%s\n' "$root$f"
    while IFS= read -r inc; do
      case "$inc" in /*) ;; *) inc="$sr/$inc" ;; esac
      for g in $root$inc; do { [ -e "$g" ] || [ -L "$g" ]; } && queue+=("${g#"$root"}"); done
    done < <(sed -nE 's/^[[:space:]]*Include(Optional)?[[:space:]]+"?([^"[:space:]]+)"?.*/\2/Ip' "$root$f")
  done
}
# 설정 파일 목록(stdin) -> 지시어 사용 여부. 설정 값은 출력하지 않는다
ap_conf_flags() {
  while IFS= read -r f; do cat "$f" 2>/dev/null; echo; done | sed -e 's/#.*//' | awk '
    BEGIN { IGNORECASE = 1 }
    tolower($1) == "protocols" { for (i = 2; i <= NF; i++) if (tolower($i) == "h2" || tolower($i) == "h2c") h2 = 1 }
    tolower($1) ~ /^(mdomain|mdomainset|manageddomain|<mdomainset|<manageddomain)$/ { md = 1 }
    tolower($1) ~ /^(virtualdocumentroot|virtualdocumentrootip|virtualscriptalias|virtualscriptaliasip)$/ { vda = 1 }
    END { printf "h2=%d md_conf=%d vhost_alias_conf=%d", h2, md, vda }'
}
# 컨테이너 루트($1)에서 패키지 이름 정규식($2)에 맞는 첫 패키지 버전 (dpkg, apk)
ctr_pkg() {
  local v
  v=$(awk -v re="$2" '/^Package: /{p=$2} /^Version: /{ if (p ~ re) { print $2; exit } }' "$1/var/lib/dpkg/status" 2>/dev/null)
  [ -n "$v" ] && { printf 'dpkg:%s' "$v"; return; }
  v=$(awk -F: -v re="$2" '/^P:/{p=$2} /^V:/{ if (p ~ re) { print $2; exit } }' "$1/lib/apk/db/installed" 2>/dev/null)
  [ -n "$v" ] && printf 'apk:%s' "$v"
}
proc_loc() {   # $1 /proc/<pid> -> host 또는 <런타임>:<컨테이너 ID 12자리>
  local cid rt
  cid=$(grep -oE '[0-9a-f]{64}' "$1/cgroup" 2>/dev/null | head -1 | cut -c1-12)
  rt=$(grep -oE 'kubepods|docker|containerd|crio|libpod' "$1/cgroup" 2>/dev/null | head -1)
  if [ -n "$cid" ]; then printf '%s:%s' "${rt:-container}" "$cid"; else printf host; fi
}

# ---- META
. /etc/os-release 2>/dev/null
o META collector "scan_linux.sh 2026.11.4"
o META host "$(hostname)"
o META os "${PRETTY_NAME:-unknown}"
o META os_id "${ID:-unknown}-${VERSION_ID:-}"
o META arch "$(uname -m)"
o META cpu "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
o META avx512vbmi "$(grep -qw avx512vbmi /proc/cpuinfo && echo yes || echo no)"
# SCTP 커널 모듈 상태 (참고 정보): 로드 여부, 커널 내장 여부, modprobe 차단 설정 여부
o META sctp "loaded=$(grep -qw '^sctp' /proc/modules 2>/dev/null && echo 1 || echo 0) builtin=$(grep -qs '/sctp\.ko' "/lib/modules/$(uname -r)/modules.builtin" && echo 1 || echo 0) blocked=$(grep -rqsE '^[[:space:]]*(install[[:space:]]+sctp[[:space:]]+/(usr/)?bin/(false|true)|blacklist[[:space:]]+sctp)([[:space:]]|$)' /etc/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d /run/modprobe.d && echo 1 || echo 0)"

# ---- SW 커널: 실행 중인 커널(uname -r)과 그 패키지, 같은 패키지의 설치된 버전, NFS 서버(nfsd) 사용 여부
# 패키지 조회(rpm -qa, dpkg-query)와 /proc, /etc 읽기만 한다. /etc/exports는 공유 항목이 있는지만 보고 내용은 출력하지 않는다
# 패키지 이름: rpm은 -core, -64k, -debug 접미어를 뗀 이름(kernel, kernel-rt, kernel-uek, kernel6.12),
#              dpkg는 Source에서 -signed와 아키텍처 접미어를 뗀 이름(linux, linux-aws, linux-aws-5.15). 배포판 공지의 소스 패키지 이름과 같다
kr=$(uname -r); krb=${kr%%+*}   # +64k, +debug 같은 접미어는 패키지 버전에 없다
kpkg=""; kinst=""; kl=""
command -v rpm >/dev/null 2>&1 && kl=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{VERSION}-%{RELEASE}\n' 'kernel*' 2>/dev/null |
  awk -F'\t' '$1 ~ /^kernel[0-9.]*(-(rt|uek|64k|debug))*(-core)?$/ { n = $1; sub(/-core$/, "", n); sub(/(-64k)?(-debug)?$/, "", n); print n "\t" $2 "\t" $3 }')
if [ -n "$kl" ]; then
  kn=$(printf '%s\n' "$kl" | awk -F'\t' -v r="$krb" '$2 == r {print $1 "=" $3; exit}')
  [ -n "$kn" ] && kpkg="rpm:$kn" && kinst=$(printf '%s\n' "$kl" | awk -F'\t' -v n="${kn%%=*}" '$1 == n {print $3}' | sort -uV | tail -10 | paste -sd, -)
elif command -v dpkg-query >/dev/null 2>&1; then
  kl=$(dpkg-query -W -f='${Package}\t${Version}\t${Source}\t${db:Status-Status}\n' 'linux-image-*' 2>/dev/null |
    awk -F'\t' '$4 == "installed" && $1 ~ /^linux-image-(unsigned-)?[0-9]/ { s = $3; sub(/ .*/, "", s); if (s == "") s = $1; sub(/-signed/, "", s); sub(/-(amd64|arm64|i386|armhf|ppc64el|s390x)$/, "", s); print $1 "\t" $2 "\t" s }')
  kn=$(printf '%s\n' "$kl" | awk -F'\t' -v a="linux-image-$kr" -v b="linux-image-unsigned-$kr" '$1 == a || $1 == b {print $3 "=" $2; exit}')
  [ -n "$kn" ] && kpkg="dpkg:$kn" && kinst=$(printf '%s\n' "$kl" | awk -F'\t' -v n="${kn%%=*}" '$3 == n {print $2}' | sort -uV | tail -10 | paste -sd, -)
fi
nfsd=0; grep -qsxF nfsd /proc/[0-9]*/comm && nfsd=1   # 커널 스레드 nfsd. 사용자 공간 NFS 서버(nfs-ganesha)는 커널 nfsd가 아니다
v41=""   # /proc/fs/nfsd/versions 예: "-2 +3 +4 +4.1 +4.2". 읽지 못하면 비워 둔다(조건 미확인)
if [ -r /proc/fs/nfsd/versions ]; then
  vv=" $(cat /proc/fs/nfsd/versions 2>/dev/null) "
  case "$vv" in "  ") ;; *" -4 "*) v41=0 ;; *" +4.1 "*|*" +4.2 "*) v41=1 ;; *) v41=0 ;; esac
fi
nm=0; grep -qs '^nfsd ' /proc/modules && nm=1
l2049=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4 == "0A" && $2 ~ /:0801$/ {f = 1} END {print f + 0}')
ex=0; grep -qsvE '^[[:space:]]*(#|$)' /etc/exports /etc/exports.d/*.exports && ex=1
be=""; if command -v systemctl >/dev/null 2>&1; then case "$(timeout 10 systemctl is-enabled nfs-server.service 2>/dev/null)" in enabled*) be=1 ;; *) be=0 ;; esac; fi
o SW linux-kernel host "/boot/vmlinuz-$kr" "$kr" running "" "$kpkg" "nfsd=$nfsd${v41:+ nfs4_1=$v41} nfsd_mod=$nm listen2049=$l2049 exports=$ex${be:+ boot_enabled=$be}${kinst:+ installed=$kinst}"

# ---- PKG: 패키지 관리자로 설치된 Java, MySQL, Oracle 계열, nginx 계열, PostgreSQL, Apache httpd, Node.js
{
  command -v rpm >/dev/null 2>&1 && rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Status}\n' | awk -F'\t' '$3 == "installed" {print $1 "\t" $2}'
} 2>/dev/null | awk -F'\t' '{ n = tolower($1) } n ~ /(jdk|jre|java|corretto|temurin|zulu|graalvm|mysql|mariadb|percona|oracle|virtualbox|helidon|nginx|openresty|tengine|angie|postgres|libpq|httpd|apache2|mod_http2|mod_md|nodejs)/ && n !~ /javascript|javapackages|ca-certificates-java|java-common|^tzdata|certbot/ { print "PKG\t" $1 "\t" $2 }' | capk 60

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

# ---- SW 실행 중: PostgreSQL, Apache httpd의 부모(master) 프로세스, Node.js 프로세스가 쓰는 mongodb 패키지
for d in /proc/[0-9]*; do
  comm=$(cat "$d/comm" 2>/dev/null) || continue
  case "$comm" in postgres|postmaster|httpd|apache2|node|nodejs) ;; *) continue ;; esac
  p=${d#/proc/}
  ppid=$(awk '{print $4}' "$d/stat" 2>/dev/null)
  pcomm=$(cat "/proc/$ppid/comm" 2>/dev/null)
  loc=$(proc_loc "$d")
  exe=$(readlink "$d/exe" 2>/dev/null)
  stale=""; case "$exe" in *" (deleted)") stale="EXE_DELETED(교체 후 미재기동 가능성)" ;; esac
  exe=${exe% (deleted)}
  root="$d/root"; [ "$loc" = host ] && root=""   # 호스트 프로세스는 / 기준으로 읽는다(다른 사용자 프로세스의 root 링크는 권한에 따라 막힘)
  bin="$d/exe"
  if [ -z "$exe" ]; then   # exe 링크를 못 읽으면(권한) 명령행 첫 인자의 절대 경로로 대신한다
    exe=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -1)
    case "$exe" in /*) bin="$root$exe" ;; *) exe=""; bin="" ;; esac
  fi
  case "$comm" in
    postgres|postmaster)
      case "$pcomm" in postgres|postmaster) continue ;; esac   # 하위 프로세스(backend, checkpointer 등)는 건너뜀
      pkgv=""; [ "$loc" != host ] && pkgv=$(ctr_pkg "$root" '^postgresql(-[0-9]+|[0-9]+)(-server)?$')
      o SW postgresql "$loc" "$exe" "$(sw_ver postgresql "$bin")" "pid $p" "$stale" "$pkgv" "$(pg_flags "$root" "$exe")" ;;
    httpd|apache2)
      [ "$pcomm" = "$comm" ] && continue
      conf=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | awk 'p {print; exit} $0 == "-f" {p=1}')
      if [ -z "$conf" ]; then
        for c in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /usr/local/apache2/conf/httpd.conf /etc/apache2/httpd.conf; do
          [ -f "$root$c" ] && { conf=$c; break; }
        done
      fi
      mods=$(grep -oE '/mod_[a-z0-9_]+\.so' "$d/maps" 2>/dev/null | sed -E 's#^/mod_##; s#\.so$##' | sort -u | paste -sd, -)
      files=""; [ -n "$conf" ] && files=$(ap_conf_files "$root" "$conf")
      flags="mods=${mods:-none} files=$(printf '%s' "$files" | grep -c .) $(printf '%s\n' "$files" | grep . | ap_conf_flags)"
      pkgv=""; [ "$loc" != host ] && pkgv=$(ctr_pkg "$root" '^(apache2-bin|apache2|httpd)$')
      o SW httpd "$loc" "$exe" "$(sw_ver httpd "$bin")" "pid $p" "$stale" "$pkgv" "$flags" ;;
    node|nodejs)
      cwd=$(readlink "$d/cwd" 2>/dev/null)
      script=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | awk 'NR > 1 && $0 !~ /^-/ {print; exit}')
      case "$script" in /*) ;; ?*) script="$cwd/$script" ;; esac
      for start in "$cwd" "$(dirname "${script:-/}")"; do
        dir=$start
        for _ in 1 2 3 4 5 6; do
          pj="$dir/node_modules/mongodb/package.json"
          v=$(sw_ver npm-mongodb "$root$pj")
          [ -n "$v" ] && { o SW npm-mongodb "$loc" "$pj" "$v" "pid $p" "" "" ""; break; }
          [ "$dir" = / ] && break
          dir=$(dirname "$dir")
        done
      done ;;
  esac
done | capk 40

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

# ---- FIND: 로컬 디스크 전체(tarball 설치 JDK, 앱 번들 JDK, 컨테이너 이미지 레이어 포함). SW는 위 실행 중 항목과 판정기가 경로로 합친다
MNTS=$(findmnt -rn -o TARGET,FSTYPE 2>/dev/null | awk '$2 ~ /^(ext2|ext3|ext4|xfs|btrfs|zfs)$/ {print $1}' | sort -u)
[ -n "$MNTS" ] || MNTS=/
FOUND=$(for m in $MNTS; do
  m=$(printf '%b' "$m")
  timeout 900 find "$m" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o -type f \
    \( -path '*/bin/java' -o -path '*/bin/mysqld' -o -path '*/sbin/mysqld' -o -path '*/bin/mariadbd' -o -path '*/sbin/mariadbd' -o -path '*/bin/mysql' -o -path '*/bin/mysqlsh' \
       -o -name weblogic.jar -o -name 'helidon-*.jar' -o -name ords.war -o -name VBoxManage \
       -o -path '*/sbin/nginx' -o -path '*/bin/nginx' -o -path '*/bin/openresty' -o -path '*/sbin/angie' \
       -o -path '*/bin/postgres' -o -path '*/libexec/postgresql*/postgres' -o -path '*/bin/pg_dump' -o -path '*/bin/psql' \
       -o -path '*/sbin/httpd' -o -path '*/bin/httpd' -o -path '*/sbin/apache2' -o -path '*/bin/apache2' \
       -o -path '*/node_modules/mongodb/package.json' \) -print 2>/dev/null
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
    postgres)
      v=$(sw_ver postgresql "$f"); [ -n "$v" ] && o SW postgresql "$loc" "$sp" "$v" "" "" "" "$(pg_flags "" "$f")" ;;
    pg_dump|psql)
      v=$(sw_ver postgresql-client "$f"); [ -n "$v" ] && o SW postgresql-client "$loc" "$sp" "$v" "" "" "" "" ;;
    httpd|apache2)
      v=$(sw_ver httpd "$f"); [ -n "$v" ] && o SW httpd "$loc" "$sp" "$v" "" "" "" "" ;;   # 버전 문자열이 없으면 Apache가 아닌 파일
    package.json)
      v=$(sw_ver npm-mongodb "$f"); [ -n "$v" ] && o SW npm-mongodb "$loc" "$sp" "$v" "" "" "" "" ;;
    *) o FILE "$loc" "$sp" ;;
  esac
done | capk 80

o END "$(( $(date +%s) - T0 ))s"
