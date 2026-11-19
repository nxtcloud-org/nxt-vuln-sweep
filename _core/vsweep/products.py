"""제품별 버전 해석과 판정. 판정 기준 값은 공지의 criteria.toml에서 받는다.

판정 결과 status 값
  affected_primary     공지 대상 제품(예: Oracle JDK)이 영향 버전
  affected_derivative  같은 소스의 파생 빌드(예: Corretto, Temurin, 배포판 nginx 패키지)가 영향 범위 버전. 벤더 패치 확인 필요
  affected_unreached   영향 버전이지만 수집한 설정에 공지의 사용 조건이 없음 (nginx)
  eol                  지원 종료 계열이라 패치가 없음
  out_of_range         영향 범위보다 높은 버전
  not_applicable       이번 공지와 무관 (MariaDB, IBM Java 등)
  manual               사람이 확인해야 함
  unknown              버전을 읽지 못함
"""
import re

from .common import vtuple

AFFECTED = ("affected_primary", "affected_derivative", "affected_unreached", "eol")


# ---------------- Java
def java_vendor(text):
    t = text or ""
    if re.search(r"pxa64|pxi32|pwa64|\bSR\d+ FP\d+|IBM|[\\/]ibm[\\/]|ibm-jre|Semeru|OpenJ9", t):
        return "IBM Java"
    if "GraalVM" in t:
        return "Oracle GraalVM"
    if "Corretto" in t or "Amazon" in t:
        return "Amazon Corretto"
    if "Temurin" in t or "Adoptium" in t:
        return "Eclipse Temurin"
    if "Zulu" in t or "Azul" in t:
        return "Azul Zulu"
    if "Microsoft" in t:
        return "Microsoft OpenJDK"
    if "BellSoft" in t or "Liberica" in t:
        return "BellSoft Liberica"
    if "Java(TM)" in t or "Java HotSpot(TM)" in t:
        return "Oracle Java SE"
    if "Red Hat" in t or re.search(r"\.el[789]|amzn2", t):
        return "OpenJDK (OS 패키지)"
    if "Debian" in t or "Ubuntu" in t:
        return "OpenJDK (Debian/Ubuntu)"
    if "Oracle Corporation" in t and "OpenJDK" not in t:
        return "Oracle Java SE"
    if "OpenJDK" in t or "openjdk" in t:
        return "OpenJDK (기타 빌드)"
    return "미상"


def parse_java_version(text):
    """(다섯 자리 튜플, 원문) 반환. JAVA_VERSION, java -version, Windows 파일 버전 순으로 시도."""
    t = text or ""
    m = re.search(r"JAVA_VERSION=(\S+)", t) or re.search(r'version "([^"]+)"', t)
    if m:
        v = m.group(1)
        m8 = re.match(r"1\.(\d+)\.0(?:_(\d+))?", v)
        if m8:
            return (int(m8.group(1)), 0, int(m8.group(2) or 0), 0, 0), v
        nums = [int(x) for x in re.findall(r"\d+", v.split("+")[0].split("-")[0])][:5]
        if nums:
            return tuple(nums + [0] * (5 - len(nums))), v
    m = re.search(r"file=(\d+)\.(\d+)\.(\d+)", t)
    if m:
        a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if a in (5, 6, 7, 8) and b == 0:  # Java 5-8 파일 버전: 8.0.<업데이트*10>.<빌드> (예: 8.0.910.15 = 8u91)
            return (a, 0, c // 10, 0, 0), f"{a}u{c // 10} ({m.group(0)})"
        return (a, 0, c, 0, 0), m.group(0)
    return None, ""


def java_judge(ver, vendor, jc, vendor_label):
    """(status, 판정 문구, 서버 해당 최고 CVSS) 반환. jc는 criteria의 [java] 표."""
    if not jc:
        return "not_applicable", "참고(이번 공지의 Java 대상 아님)", ""
    excl = jc.get("exclude_vendors", {})
    if vendor in excl:
        return "not_applicable", excl[vendor], ""
    if ver is None:
        return "unknown", "버전 확인 필요", ""
    fam = str(ver[0])
    latest = jc.get("latest_affected", {})
    if fam not in latest:
        return "eol", f"EOL 계열(Java {fam}, 패치 없음)", ""
    primary = vendor in jc.get("primary_vendors", [])
    th = latest[fam] if primary else jc.get("derivative_latest_affected", {}).get(fam, latest[fam])
    cvss = str(jc.get("max_server_cvss", {}).get(fam, ""))
    if ver > vtuple(th):
        return "out_of_range", "영향 범위 밖(더 높은 버전)", ""
    if primary:
        return "affected_primary", f"영향({vendor_label} 제품)", cvss
    return "affected_derivative", f"영향 범위 버전({jc.get('derivative_label', '파생 빌드')}, 벤더 패치 확인)", cvss


# ---------------- MySQL
def mysql_version(text):
    m = re.search(r"Distrib (\d+)\.(\d+)\.(\d+)", text or "") or re.search(r"Ver (\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def mysql_judge(text, mc):
    t = text or ""
    if not mc:
        return "not_applicable", "참고(이번 공지의 MySQL 대상 아님)", ""
    if "MariaDB" in t:
        return "not_applicable", mc.get("mariadb_note", "해당 없음(MariaDB)"), ""
    v = mysql_version(t)
    if not v:
        return "unknown", "버전 확인 필요", ""
    for lo, hi in mc.get("affected", []):
        if vtuple(lo, 3) <= v <= vtuple(hi, 3):
            return "affected_primary", "영향(MySQL)", str(mc.get("max_cvss", ""))
    if v < vtuple(mc.get("eol_below", "0"), 3):
        note = mc.get("eol_notes", {}).get(f"{v[0]}.{v[1]}")
        return "eol", note or f"EOL(MySQL {v[0]}.{v[1]}, 패치 없음)", ""
    return "manual", "영향 범위 밖 또는 EOL 버전, 확인", ""


# ---------------- Oracle Home (DB, Client, WebLogic/FMW)
def oracle_home_judge(text, oc):
    if not oc:
        return "not_applicable", "참고(이번 공지의 Oracle Home 대상 아님)", ""
    pm = re.search(r"Oracle (Client|Database[^0-9|]*|WebLogic Server|Fusion Middleware[^0-9|]*)\s+(\d+(?:\.\d+)+)", text or "")
    if pm:
        product, ver = pm.group(1).strip(), pm.group(2)
        # EOL 접두어는 제품별로 둔다 (WebLogic 12.2.1.4는 지원 중이므로 Client/Database의 '12.'와 섞으면 안 됨)
        prefixes = oc.get("eol_prefixes", {}).get(product.split()[0], [])
        if any(ver.startswith(p) for p in prefixes):
            return "eol", f"EOL(Oracle {product} {ver}, 공지 지원 버전 목록 밖)", ""
    return "manual", "수동 확인(DB/FMW 버전과 패치 대조)", ""


# ---------------- nginx
# criteria [[cves]]의 cond 값 -> (판정 함수, 필요한 컴파일 모듈, 보고서 표시 이름). f는 NGXCONF 지시어 사용 여부, v는 버전 튜플
NGX_CONDS = {
    "http2": (lambda f, v: f["http2"], "http_v2_module", "HTTP/2"),
    "http2_proxy": (lambda f, v: f["http2"] and f["pass"], "http_v2_module", "HTTP/2 + 프록시"),
    "http3": (lambda f, v: f["quic"], "http_v3_module", "HTTP/3(QUIC)"),
    "resolver_subrequest": (lambda f, v: f["resolver"] and f["proxy_var"] and (f["mirror"] or f["ssi"]), None,
                            "resolver + 변수 proxy_pass + mirror/SSI"),
    "mail": (lambda f, v: f["mail"], "mail", "mail 프록시"),
    "tls13_request_body": (lambda f, v: f["ssl"] and (f["tls13"] or (not f["ssl_protocols"] and v >= (1, 23, 4))),
                           "http_ssl_module", "TLS 1.3 리스너"),
    "proxy_protocol_dynamic_cert": (lambda f, v: f["proxy_protocol"] and f["cert_var"], "stream_ssl_module",
                                    "PROXY protocol + 변수 인증서"),
    "alias_try_files": (lambda f, v: f["alias"] and f["try_files"], None, "alias + try_files"),
    "stream_verify_client": (lambda f, v: f["stream"] and f["verify_client"], "stream_ssl_module", "stream 클라이언트 인증서 검증"),
    "ssl_preread": (lambda f, v: f["ssl_preread"], "stream_ssl_preread_module", "ssl_preread"),
}
NGX_FORKS = (("openresty", "OpenResty"), ("Tengine", "Tengine"), ("Angie", "Angie"), ("freenginx", "freenginx"))


def nginx_version(banner):
    """배너(예: 'nginx/1.24.0', 'openresty/1.25.3.2')에서 nginx 코어 버전 세 자리. 포크는 nginx/ 문자열이 없으면 앞 세 자리."""
    m = re.search(r"(?<![A-Za-z])nginx/(\d+)\.(\d+)\.(\d+)", banner or "")
    if not m:
        m = re.search(r"(?:openresty|Tengine|freenginx)/(\d+)\.(\d+)\.(\d+)", banner or "")
    return tuple(int(x) for x in m.groups()) if m else None


def nginx_flags(text):
    """NGXCONF 마지막 필드('http2=1 quic=0 ...') -> dict. 비어 있으면 None."""
    d = {k: v == "1" for k, v in re.findall(r"(\w+)=([01])", text or "")}
    return d or None


def nginx_has_module(mods, mod):
    """configure 인자 문자열에 모듈이 있는지. 인자를 못 읽었으면 None."""
    if not mods:
        return None
    return bool(re.search(rf"--with-{mod}(=dynamic)?(\s|$)", mods))


def nginx_in_range(v, cve):
    """nginx.org 표기: Vulnerable 'A-B'(포함), Not vulnerable 'X+, Y+'(같은 계열에서 그 이상)."""
    lo, hi = (vtuple(x, 3) for x in cve["range"])
    if not lo <= v <= hi:
        return False
    return not any(v[:2] == vtuple(fx, 3)[:2] and v >= vtuple(fx, 3) for fx in cve.get("fixed", []))


def nginx_reach(cve, flags, mods, v):
    """met(조건 해당) | unmet(조건 없음) | unknown(설정 미확인)"""
    fn, mod, _ = NGX_CONDS[cve["cond"]]
    if mod and nginx_has_module(mods, mod) is False:
        return "unmet"
    if flags is None:
        return "unknown"
    return "met" if fn(flags, v) else "unmet"


def nginx_judge(banner, mods, flags, origin, pkg, nc, cves, distro_fixed=None):
    """(status, 판정 문구, 최고 CVSS, 비고) 반환. origin은 nginx_origin() 값, pkg는 패키지 버전(없으면 ''),
    distro_fixed는 (배포판 수정 버전, 비교 방식 'deb'|'rpm', 근거) 또는 None."""
    if not nc:
        return "not_applicable", "참고(이번 공지의 nginx 대상 아님)", "", ""
    if "nginx-plus" in (banner or ""):
        return "manual", nc.get("plus_note", "NGINX Plus: 벤더 공지의 Plus 버전표로 확인"), "", ""
    v = nginx_version(banner)
    fork = next((label for key, label in NGX_FORKS if key in (banner or "")), None)
    if fork:
        base = f", nginx {'.'.join(map(str, v))} 기반" if v and "nginx/" in banner else ""
        return "manual", f"포크 제품({fork}{base}): 해당 벤더 공지로 확인", "", ""
    if v is None:
        return "unknown", "버전 확인 필요", "", ""
    ver = ".".join(map(str, v))
    hit = [c for c in cves if nginx_in_range(v, c)]
    if not hit:
        return "out_of_range", f"영향 범위 밖(nginx {ver})", "", ""
    if distro_fixed and pkg:
        fixed, kind, src = distro_fixed
        if pkg_vercmp(pkg, fixed, kind) >= 0:
            return "out_of_range", f"배포판 수정 버전 이상(패키지 {pkg}, 수정 {fixed}, {src})", "", ""
    reach = {c["id"]: nginx_reach(c, flags, mods, v) for c in hit}
    live = [c for c in hit if reach[c["id"]] != "unmet"]
    met = [c for c in hit if reach[c["id"]] == "met"]
    cvss = max((float(c.get("cvss") or 0) for c in live), default=0.0)

    def names(cs):
        return ", ".join(f"{c['id']}({NGX_CONDS[c['cond']][2]})" for c in cs)

    detail = []
    if met:
        detail.append(f"조건 해당: {names(met)}")
    unk = [c for c in hit if reach[c["id"]] == "unknown"]
    if unk:
        detail.append(f"설정 미확인: {names(unk)}")
    unmet = [c for c in hit if reach[c["id"]] == "unmet"]
    if unmet:
        detail.append(f"조건 없음: {', '.join(c['id'] for c in unmet)}")
    branch = f"{v[0]}.{v[1]}"
    if branch not in nc.get("supported_branches", []):
        detail.append(nc.get("unsupported_note", f"지원 종료 계열({branch})"))
    detail = "; ".join(detail)
    if not live:
        return "affected_unreached", f"영향 버전이나 수집한 설정에 공지 조건 없음(nginx {ver}, {len(hit)}건)", "", detail
    scope = f"조건 해당 {len(met)}건" if met else "설정 미확인"
    if origin == "distro":
        if distro_fixed and pkg:
            return "affected_primary", f"영향(배포판 수정 버전 {distro_fixed[0]} 미만, {scope})", str(cvss), detail
        return "affected_derivative", f"영향 범위 버전(배포판 패키지 {pkg or ver}, 배포판 수정 확인, {scope})", str(cvss), detail
    return "affected_primary", f"영향(nginx {ver}, {scope})", str(cvss), detail


def nginx_origin(path, pkg, loc):
    """official(nginx.org 패키지), distro(배포판 패키지), build(소스 빌드, 이미지 내장)와 표시 이름"""
    if pkg:
        if re.search(r"~[a-z]+\d*$|\.ngx(\.|$)", pkg):
            return "official", "nginx (nginx.org 패키지)"
        if pkg.startswith("apk:"):
            return "distro", "nginx (Alpine 패키지)"
        return "distro", "nginx (배포판 패키지)"
    if loc != "host":
        return "build", "nginx (컨테이너 이미지)"
    return "build", "nginx (소스 빌드 또는 수동 설치)"


def _deb_order(c):
    if c == "~":
        return -1
    if c == "" or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_cmp(a, b):
    """dpkg verrevcmp"""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = _deb_order(a[i] if i < len(a) else ""), _deb_order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            first = first or (ord(a[i]) - ord(b[j]))
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _rpm_cmp(a, b):
    """rpmvercmp (~, ^ 포함)"""
    if a == b:
        return 0
    i = j = 0
    while True:
        while i < len(a) and not (a[i].isalnum() or a[i] in "~^"):
            i += 1
        while j < len(b) and not (b[j].isalnum() or b[j] in "~^"):
            j += 1
        ta, tb = a[i] if i < len(a) else "", b[j] if j < len(b) else ""
        if ta == "~" or tb == "~":
            if ta != "~":
                return 1
            if tb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ta == "^" or tb == "^":
            if not ta:
                return -1
            if not tb:
                return 1
            if ta != "^":
                return 1
            if tb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not ta or not tb:
            break
        pat = r"\d+" if ta.isdigit() else r"[A-Za-z]+"
        sa = re.match(pat, a[i:]).group()
        mb = re.match(pat, b[j:])
        if not mb:
            return 1 if ta.isdigit() else -1
        sb = mb.group()
        if ta.isdigit():
            na, nb = sa.lstrip("0"), sb.lstrip("0")
            if len(na) != len(nb):
                return 1 if len(na) > len(nb) else -1
            if na != nb:
                return 1 if na > nb else -1
        elif sa != sb:
            return 1 if sa > sb else -1
        i, j = i + len(sa), j + len(sb)
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def pkg_vercmp(a, b, kind):
    """패키지 버전 비교. kind='deb'(epoch:upstream-revision) 또는 'rpm'(version-release, epoch 선택). 접두어 'dpkg:', 'apk:'는 뗀다."""
    a, b = re.sub(r"^(dpkg|apk|rpm):", "", a), re.sub(r"^(dpkg|apk|rpm):", "", b)

    def split(x):
        e, _, rest = x.rpartition(":") if ":" in x else ("0", "", x)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(e or 0), up, rev

    (ea, ua, ra), (eb, ub, rb) = split(a), split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    cmp = _deb_cmp if kind == "deb" else _rpm_cmp
    r = cmp(ua, ub) or cmp(ra, rb)
    return (r > 0) - (r < 0)


# ---------------- CPU
def avx512vbmi_guess(meta_flag, cpu):
    """Linux는 /proc/cpuinfo 플래그, Windows는 CPU 모델로 추정 (Ice Lake 이후 Xeon, Zen 4 이후 EPYC)."""
    if meta_flag:
        return meta_flag
    if re.search(r"Platinum 8[3-5]\d\d|Xeon.*(6[0-9]{3}[EP]|Gold 6[3-5]\d\d)|EPYC 9\w*[45]\b|EPYC 9R14|EPYC 9R45", cpu or ""):
        return "yes(CPU 모델 추정)"
    return "no(CPU 모델 추정)" if cpu else "미확인"
