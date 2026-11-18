#!/bin/bash
# nxt-vuln-sweep 호스트 수집기 (Linux). 공지와 무관하게 Java, MySQL, Oracle 계열 설치/실행 정보를 모은다.
# 출력 형식은 _core/COLLECTORS.md 참고. 탐지 대상을 늘릴 때는 FIND 패턴과 README를 함께 고친다.
# 읽기 전용: 패키지 목록, 파일, /proc 조회와 버전 출력(java -version 등)만 하고 아무것도 설치하거나 바꾸지 않는다.
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

# ---- META
. /etc/os-release 2>/dev/null
o META collector "scan_linux.sh 2026.11.1"
o META host "$(hostname)"
o META os "${PRETTY_NAME:-unknown}"
o META arch "$(uname -m)"
o META cpu "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
o META avx512vbmi "$(grep -qw avx512vbmi /proc/cpuinfo && echo yes || echo no)"

# ---- PKG: 패키지 관리자로 설치된 Java, MySQL, Oracle 계열
{
  command -v rpm >/dev/null 2>&1 && rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Status}\n' | awk -F'\t' '$3 == "installed" {print $1 "\t" $2}'
} 2>/dev/null | awk -F'\t' '{ n = tolower($1) } n ~ /(jdk|jre|java|corretto|temurin|zulu|graalvm|mysql|mariadb|percona|oracle|virtualbox|helidon)/ && n !~ /javascript|javapackages|ca-certificates-java|java-common|^tzdata/ { print "PKG\t" $1 "\t" $2 }' | capk 60

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
       -o -name weblogic.jar -o -name 'helidon-*.jar' -o -name ords.war -o -name VBoxManage \) -print 2>/dev/null
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
    *) o FILE "$loc" "$sp" ;;
  esac
done | capk 50

o END "$(( $(date +%s) - T0 ))s"
