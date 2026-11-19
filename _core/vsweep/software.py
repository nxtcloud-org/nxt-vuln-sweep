"""범용 소프트웨어 판정: 수집기 SW 레코드(PostgreSQL, Apache httpd, Node.js mongodb 패키지 등)를 기준표로 판정한다.

수집 레코드 (scan_linux.sh, scan_windows.ps1)
  SW <제품> <위치> <경로> <버전> <실행(pid N)> <stale> <컨테이너 패키지> <플래그>
  제품 키: postgresql, postgresql-client, httpd, npm-mongodb (수집기가 아는 것만)
  플래그: 'plperl=1 dblink=0', 'mods=http2,md h2=1' 처럼 공백으로 구분한 키=값. mods 목록은 mod_<이름>=1 로 풀어서 쓴다

기준표 (criteria.toml)
  [software.<제품 키>]       이 공지가 다루는 제품. 없는 제품의 SW 레코드는 판정하지 않는다
    label                    보고서 제품 이름 (예: "PostgreSQL 서버")
    branch_parts             버전 계열 자릿수. 수정 버전은 같은 계열 안에서만 비교한다 (PostgreSQL 1, httpd 2, 없으면 0)
    supported_branches       벤더가 지원하는 계열. 목록 밖 계열은 지원 종료로 본다 (비우면 검사 안 함)
    unsupported_note, branch_notes = { "14" = "..." }
    distro_backport          true면 배포판 패키지는 버전 번호로 판단하지 않는다(백포트). 배포판 공지(distro_fixed)로만 수정 여부를 본다
    package_re               호스트 PKG 레코드에서 이 제품 패키지를 찾는 정규식 (표시용. 버전 문자열이 들어 있는 패키지만 붙인다)
    merge_dir                true면 같은 폴더의 바이너리를 한 줄로 합친다 (클라이언트 도구)
    [[software.<키>.distro_fixed]]  배포판 수정 정보. os(META os_id, rhel-9 처럼 주 버전만도 됨), package, version, kind(deb|rpm),
                             source, cves(비우면 이 제품의 모든 CVE), status("fixed" 기본, "not_affected")
  [[cves]] 에 판정용 키
    sw = ["postgresql"]      이 CVE가 해당하는 제품 키
    range = ["0", "18.6"]    영향 범위(포함). fixed = ["18.7", "17.12"] 같은 계열에서 이 버전 이상이면 수정
    cond = ["mod_http2", "h2"]  사용 조건 플래그(모두 1이어야 해당). 없으면 조건 없음
    condition                보고서에 쓰는 조건 설명

판정 결과 status는 products.py 와 같다. 우선순위는 judge.priority()가 정한다.
"""
import re
from collections import OrderedDict

from .common import vtuple
from .products import pkg_vercmp

ORIGIN_LABEL = {"pkg": "패키지 설치", "build": "소스 빌드 또는 수동 설치", "image": "컨테이너 이미지", "app": "애플리케이션 의존성"}


def parse_flags(text):
    """'mods=http2,md h2=1 plperl=0' -> {'mod_http2': True, 'mod_md': True, 'h2': True, 'plperl': False}. 비어 있으면 None"""
    if not (text or "").strip():
        return None
    out = {}
    for k, v in re.findall(r"([\w-]+)=(\S*)", text):
        if k == "mods":
            for m in filter(None, v.split(",")):
                if m != "none":
                    out[f"mod_{m}"] = True
            out["_mods_known"] = True
        elif v in ("0", "1"):
            out[k] = v == "1"
    return out


def branch_of(v, parts):
    return v[:parts] if parts else ()


def in_range(v, cve, parts, ignore_lo=False):
    lo, hi = (vtuple(x, 3) for x in cve["range"])
    if v > hi or (not ignore_lo and v < lo):
        return False
    return not any(branch_of(v, parts) == branch_of(vtuple(fx, 3), parts) and v >= vtuple(fx, 3) for fx in cve.get("fixed", []))


def reach(cve, flags):
    """met | unmet | unknown"""
    cond = cve.get("cond") or []
    if isinstance(cond, str):
        cond = [cond]
    if not cond:
        return "met"
    if flags is None:
        return "unknown"
    states = []
    for c in cond:
        if c.startswith("mod_"):   # 모듈 목록을 읽었으면 목록에 없는 모듈은 없는 것
            states.append(("met" if flags.get(c) else "unmet") if flags.get("_mods_known") else "unknown")
        elif c not in flags:
            states.append("unknown")
        else:
            states.append("met" if flags[c] else "unmet")
    if "unmet" in states:   # 조건은 모두 만족해야 하므로 하나라도 없으면 해당 없음
        return "unmet"
    return "unknown" if "unknown" in states else "met"


def distro_resolution(cve_id, entries, pkgs):
    """'fixed' | 'available' | None. entries는 이 호스트 os_id에 맞는 distro_fixed 항목(정확히 맞는 것 먼저)"""
    for e in entries:
        if e.get("cves") and cve_id not in e["cves"]:
            continue
        if e.get("status", "fixed") == "not_affected":
            return "fixed", f"{e.get('source', '')} 해당 없음"
        have = pkgs.get(e.get("package", ""))
        if not have:
            continue
        if pkg_vercmp(have, e["version"], e.get("kind", "rpm")) >= 0:
            return "fixed", e.get("source", "")
        return "available", f"{e['package']} {e['version']} ({e.get('source', '')})"
    return None, ""


def host_distro_entries(sc, os_id):
    exact = [e for e in sc.get("distro_fixed", []) if e.get("os") == os_id]
    prefix = [e for e in sc.get("distro_fixed", []) if e.get("os") != os_id and os_id.startswith(e.get("os", "") + ".")]
    return exact + prefix


def judge_one(key, sc, cves, version, flags, origin, pkg_ver, entries, pkgs, stale):
    """(status, 판정 문구, 최고 CVSS, 비고)"""
    if not re.search(r"\d", version or ""):
        return "unknown", "버전 확인 필요", "", ""
    v = vtuple(version, 3)
    parts = sc.get("branch_parts", 0)
    br = ".".join(map(str, branch_of(v, parts)))
    notes = []
    if br in sc.get("branch_notes", {}):
        notes.append(sc["branch_notes"][br])
    supported = sc.get("supported_branches", [])
    unsupported = bool(supported) and br not in supported and v < max(vtuple(b, 3) for b in supported)
    backport = sc.get("distro_backport", False) and origin == "pkg"
    mine = [c for c in cves if key in c.get("sw", [])]

    if unsupported:
        hit = [c for c in mine if in_range(v, c, 0, ignore_lo=backport)]
        note = sc.get("unsupported_note", f"지원 종료 계열({br})")
        if origin == "pkg":
            return ("affected_derivative", f"지원 종료 계열({br}) 배포판 패키지: 배포판의 수정본 제공 여부 확인",
                    str(max((float(c.get("cvss") or 0) for c in hit), default="")) if hit else "", "; ".join([note] + notes))
        return "eol", f"지원 종료 계열({br}, 수정 버전 없음)", str(max((float(c.get("cvss") or 0) for c in hit), default="")) if hit else "", "; ".join([note] + notes)

    hit = [c for c in mine if in_range(v, c, parts, ignore_lo=backport)]
    if not hit:
        return "out_of_range", f"영향 범위 밖({version})", "", "; ".join(notes)

    res = {}
    if backport:
        for c in hit:
            res[c["id"]] = distro_resolution(c["id"], entries, pkgs) if not stale else (None, "")
        fixed = [c for c in hit if res[c["id"]][0] == "fixed"]
        hit = [c for c in hit if res[c["id"]][0] != "fixed"]
        if fixed:
            notes.append(f"배포판 수정 확인 {len(fixed)}건({', '.join(sorted({res[c['id']][1] for c in fixed if res[c['id']][1]}))})")
        if not hit:
            return "out_of_range", f"배포판 수정 버전 이상(패키지 {pkg_ver})", "", "; ".join(notes)

    rc = {c["id"]: reach(c, flags) for c in hit}
    live = [c for c in hit if rc[c["id"]] != "unmet"]
    met = [c for c in hit if rc[c["id"]] == "met" and c.get("cond")]
    unk = [c for c in hit if rc[c["id"]] == "unknown"]
    unmet = [c for c in hit if rc[c["id"]] == "unmet"]
    nocond = [c for c in hit if not c.get("cond")]
    detail = []
    if nocond:
        detail.append(f"조건 없이 해당 {len(nocond)}건")
    if met:
        detail.append("조건 해당: " + ", ".join(f"{c['id']}({c.get('condition', '')})" for c in met))
    if unk:
        detail.append("조건 미확인: " + ", ".join(f"{c['id']}({c.get('condition', '')})" for c in unk))
    if unmet:
        detail.append("조건 없음: " + ", ".join(c["id"] for c in unmet))
    if not live:
        return ("affected_unreached", f"영향 버전이나 수집한 정보에 사용 조건 없음({version}, {len(hit)}건)", "",
                "; ".join(detail + notes))
    cvss = str(max(float(c.get("cvss") or 0) for c in live))
    if backport:
        avail = [c for c in live if res[c["id"]][0] == "available"]
        if avail:
            detail.append("배포판 수정 패키지 미적용: " + "; ".join(sorted({res[c['id']][1] for c in avail})))
            return "affected_primary", f"영향(배포판 수정 패키지 미적용, {len(live)}건)", cvss, "; ".join(detail + notes)
        why = "실행 파일 교체 후 미재기동이라 패키지로 판단 불가" if stale else "배포판 수정 확인 필요"
        return "affected_derivative", f"영향 범위 가능(배포판 패키지 {pkg_ver}, {why}, {len(live)}건)", cvss, "; ".join(detail + notes)
    return "affected_primary", f"영향({version}, {len(live)}건)", cvss, "; ".join(detail + notes)


def software_findings(rows, crit, add):
    """SW 레코드 판정. 같은 위치, 경로는 한 줄로 합친다(실행 중 레코드와 디스크 레코드)."""
    sw_cfg = crit.get("software") or {}
    cves = crit.get("cves", [])
    meta = {r[1]: r[2] for r in rows if r[0] == "META" and len(r) > 2}
    os_id = meta.get("os_id", "")
    pkgs = OrderedDict((r[1], r[2]) for r in rows if r[0] == "PKG" and len(r) > 2)
    entries = OrderedDict()
    for r in rows:
        if r[0] != "SW" or len(r) < 5:
            continue
        key, loc, path, ver, run, stale, cpkg, flags = (r + [""] * 10)[1:9]
        if key not in sw_cfg:
            continue
        if sw_cfg[key].get("merge_dir") and loc != "image":   # 같은 폴더의 도구(pg_dump, psql)는 한 줄로
            path = path.rsplit("/", 1)[0].rsplit("\\", 1)[0] + "/"
        e = entries.setdefault((key, loc, path), {"ver": "", "pids": [], "stale": "", "cpkg": "", "flags": None})
        e["ver"] = e["ver"] or ver
        if run:
            e["pids"].append(run.replace("pid ", ""))
        e["stale"] = e["stale"] or stale
        e["cpkg"] = e["cpkg"] or cpkg
        fl = parse_flags(flags)
        if fl is not None:
            e["flags"] = {**fl, **(e["flags"] or {})} if not run else {**(e["flags"] or {}), **fl}
    # 이미지 레이어는 경로가 레이어마다 달라서 (제품, 버전)별로 묶는다
    merged = OrderedDict()
    for (key, loc, path), e in entries.items():
        if loc == "image":
            m = merged.setdefault((key, "image", e["ver"]), {**e, "layers": 0})
            m["layers"] += 1
        else:
            merged[(key, loc, path)] = e
    for (key, loc, path), e in merged.items():
        if loc == "image":
            path = f"레이어 {e['layers']}개"
        sc = sw_cfg[key]
        pkg_ver = ""
        if loc == "host" and sc.get("package_re"):
            cands = [(n, v) for n, v in pkgs.items() if re.search(sc["package_re"], n)]
            pick = next(((n, v) for n, v in cands if e["ver"] and e["ver"] in v), None)   # 버전이 맞는 패키지만 (다른 설치본의 패키지를 붙이지 않음)
            if pick:
                pkg_ver = pick[1]
        if e["cpkg"]:
            pkg_ver = e["cpkg"]
        if key.startswith("npm-"):
            origin = "app"
        elif pkg_ver:
            origin = "pkg"
        elif loc == "host":
            origin = "build"
        else:
            origin = "image"
        ents = host_distro_entries(sc, os_id) if loc == "host" else []
        status, verdict, cvss, detail = judge_one(key, sc, cves, e["ver"], e["flags"], origin, pkg_ver, ents, pkgs, bool(e["stale"]))
        notes = [f"설치 방식: {ORIGIN_LABEL[origin]}"]
        if e["stale"]:
            notes.append("실행 파일 교체 후 미재기동(deleted): 실행 중인 것은 이전 바이너리")
        if e["cpkg"]:
            notes.append(f"컨테이너 패키지 {e['cpkg']}")
        version = e["ver"] + (f" (패키지 {re.sub(r'^(dpkg|apk):', '', pkg_ver)})" if pkg_ver and loc == "host" else "")
        if loc == "image":
            kind = f"{sc.get('label', key)}(컨테이너 이미지 레이어)"
        elif loc != "host":
            kind = f"{sc.get('label', key)}(컨테이너 실행 중)"
        else:
            kind = sc.get("label", key)
        running = "; ".join(f"pid {p}" for p in e["pids"])
        add(kind, loc, path, sc.get("label", key), version, running, (status, verdict, cvss), "; ".join(x for x in [detail] + notes if x))
