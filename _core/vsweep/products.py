"""제품별 버전 해석과 판정. 판정 기준 값은 공지의 criteria.toml에서 받는다.

판정 결과 status 값
  affected_primary     공지 대상 제품(예: Oracle JDK)이 영향 버전
  affected_derivative  같은 소스의 파생 빌드(예: Corretto, Temurin)가 영향 범위 버전. 벤더 패치 확인 필요
  eol                  지원 종료 계열이라 패치가 없음
  out_of_range         영향 범위보다 높은 버전
  not_applicable       이번 공지와 무관 (MariaDB, IBM Java 등)
  manual               사람이 확인해야 함
  unknown              버전을 읽지 못함
"""
import re

from .common import vtuple

AFFECTED = ("affected_primary", "affected_derivative", "eol")


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


# ---------------- CPU
def avx512vbmi_guess(meta_flag, cpu):
    """Linux는 /proc/cpuinfo 플래그, Windows는 CPU 모델로 추정 (Ice Lake 이후 Xeon, Zen 4 이후 EPYC)."""
    if meta_flag:
        return meta_flag
    if re.search(r"Platinum 8[3-5]\d\d|Xeon.*(6[0-9]{3}[EP]|Gold 6[3-5]\d\d)|EPYC 9\w*[45]\b|EPYC 9R14|EPYC 9R45", cpu or ""):
        return "yes(CPU 모델 추정)"
    return "no(CPU 모델 추정)" if cpu else "미확인"
