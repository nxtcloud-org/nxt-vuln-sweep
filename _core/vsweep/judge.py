"""3단계: 수집 결과(RUN_DIR/hosts/*.tsv)를 공지 기준표와 대조해 항목별, 서버별로 판정한다.

사용법: _core/sweep judge <고객> <취약점ID>   (직접: cd _core && python3 -m vsweep.judge <취약점 폴더> <RUN_DIR>)
출력: RUN_DIR/findings.csv (발견 항목별), RUN_DIR/hosts_summary.csv (서버별)

우선순위 규칙
  P1  공지 대상 제품이 영향 버전 또는 EOL 버전으로 실행 중
  P2  파생 빌드(OpenJDK 계열 등)가 영향 범위 버전 또는 EOL 버전으로 실행 중
  P3  영향 버전 또는 EOL 버전이 설치만 되어 있음 (미실행, 컨테이너 이미지 레이어 포함)
  확인 필요  버전을 읽지 못했거나 사람이 대조해야 하는 항목
  해당 없음  공지 대상이 아니거나 범위 밖 버전
"""
import os
import re
import sys
from collections import OrderedDict

from .common import PRIO_ORDER, find_advisory, load_criteria, load_inventory, load_scan_log, read_tsv, write_csv
from .products import (AFFECTED, avx512vbmi_guess, java_judge, java_vendor, mysql_judge, mysql_version,
                       oracle_home_judge, parse_java_version)

JDK1_RE = re.compile(r"(jdk|jre)[-_]?1\.?[0-7]\.?\d", re.I)


def java_home(path):
    p = path.replace(" (deleted)", "")
    return re.sub(r"[\\/](jre[\\/])?bin[\\/]javaw?(\.exe)?$", "", p, flags=re.I)


def priority(f, primary_vendors):
    st, run = f["status"], bool(f["running"])
    if st == "affected_primary" and run:
        return "P1"
    if st == "eol" and run and f["vendor"] in primary_vendors:
        return "P1"
    if st in ("affected_derivative", "eol") and run:
        return "P2"
    if st in AFFECTED:
        return "P3"
    if st in ("manual", "unknown"):
        return "확인 필요"
    return "해당 없음"


def judge_host(rows, crit, common):
    vendor_label = crit.get("vendor_label", crit.get("vendor", ""))
    jc, mc, oc = crit.get("java"), crit.get("mysql"), crit.get("oracle_home")
    out = []

    def add(kind, loc, where, vendor, version, running, judged, detail=""):
        status, verdict, cvss = judged
        out.append(OrderedDict(**common, kind=kind, loc=loc, path=where, vendor=vendor, version=version, running=running,
                               status=status, verdict=verdict, max_server_cvss=cvss, detail=detail))

    # 실행 중 JVM을 JAVA_HOME 기준으로 모은다
    host_procs, container_procs = {}, []
    for r in rows:
        if r[0] != "PROC":
            continue
        pid, usr, comm, exe, where, rv, hint, stale = (r + [""] * 9)[1:9]
        if not ("libjvm" in rv or "JAVA_VERSION" in rv or "jvm.dll" in rv or "java" in comm.lower()):
            continue
        if where not in ("host", ""):
            container_procs.append((pid, exe, where, rv, hint, stale))
        else:
            host_procs.setdefault(java_home(exe), []).append((pid, hint, stale, rv, exe))

    seen_homes, image_versions, oracle_homes = set(), OrderedDict(), OrderedDict()
    for r in rows:
        k = r[0]
        if k == "JAVA":
            loc, p, rv, vv = (r + ["", "", "", ""])[1:5]
            vendor = java_vendor(f"{rv} {vv} {p}")
            ver, raw = parse_java_version(f"{rv} {vv}")
            judged = java_judge(ver, vendor, jc, vendor_label)
            if ver is None and JDK1_RE.search(p) and jc:
                judged, raw = ("eol", "EOL 계열(경로상 JDK 1.x, 패치 없음)", ""), JDK1_RE.search(p).group(0)
            if loc == "image":
                image_versions.setdefault((vendor, raw), [judged, 0])[1] += 1
                continue
            if re.search(r"\\Oracle\\Java\\javapath", p, re.I):
                continue  # Oracle 설치 프로그램이 만드는 java.exe 런처 복사본
            jh = java_home(p)
            if jh in seen_homes:
                continue  # 같은 JDK의 bin/java와 jre/bin/java는 한 줄로
            seen_homes.add(jh)
            procs = host_procs.get(jh, [])
            running = "; ".join(f"pid {pid} {hint}".strip() for pid, hint, _, _, _ in procs)
            stale = any(s for _, _, s, _, _ in procs)
            detail = "실행 중 JVM이 교체 전 바이너리(deleted) 사용: 실제 버전은 디스크 버전보다 낮을 수 있음" if stale else ""
            add("Java", "host", p, vendor, raw, running, judged, detail)
        elif k == "MYSQL":
            loc, p, vv = (r + ["", "", ""])[1:4]
            mv = mysql_version(vv)
            is_server = os.path.basename(p.replace("\\", "/")).lower().startswith(("mysqld", "mariadbd"))
            running = "실행 중" if is_server and any(x[0] == "PROC" and len(x) > 3 and x[3].lower() in ("mysqld", "mariadbd") for x in rows) else ""
            add("MySQL/MariaDB", loc, p, "MariaDB" if "MariaDB" in vv else "MySQL",
                ".".join(map(str, mv)) if mv else vv.strip(), running, mysql_judge(vv, mc))
        elif k in ("OHOME", "OREG", "OPATCH") and len(r) > 1:
            oracle_homes.setdefault(r[1], []).append(" ".join(r[2:]).strip())
        elif k == "PKG" and len(r) > 2 and "oracle-instantclient" in r[1].lower():
            note = (oc or {}).get("instant_client_note", "참고(Oracle Instant Client)")
            add("Oracle Instant Client", "host", r[1], "Oracle", r[2], "", ("not_applicable", note, ""))
        elif k == "FILE":
            add("기타 파일", r[1] if len(r) > 1 else "", r[2] if len(r) > 2 else "", "", "", "", ("manual", "수동 확인", ""))
        elif k == "TRUNC":
            add("출력 상한 초과", "", " ".join(r[1:]), "", "", "", ("manual", "일부 항목 생략됨, 재조사 필요", ""))

    for oh, lines in oracle_homes.items():
        txt = " | ".join(x for x in lines if x and not re.search(r"Copyright|Invoking|Oracle Interim|history file|Oracle Home\s+:", x))
        add("Oracle Home", "host", oh, "Oracle", txt[:300], "", oracle_home_judge(txt, oc))

    # 디스크 스캔에서 못 찾은 호스트 JVM: procrun 서비스처럼 exe가 JDK 밖이면 같은 버전 JDK 행에 붙인다
    for jh, procs in host_procs.items():
        if jh in seen_homes:
            continue
        pid, hint, stale, rv, exe = procs[0]
        mv = re.search(r"JAVA_VERSION=(\S+)", rv)
        target = next((f for f in out if f["kind"] == "Java" and mv and f["version"] == mv.group(1)), None)
        if target is not None:
            label = os.path.basename(exe.replace("\\", "/"))
            target["running"] = "; ".join(x for x in [target["running"], f"pid {pid} {label}(내장 JVM, 같은 버전)"] if x)
            continue
        vendor = java_vendor(rv + " " + exe)
        ver, raw = parse_java_version(rv)
        add("Java(실행 중, 디스크 스캔 밖)", "host", exe, vendor, raw,
            "; ".join(f"pid {p} {h}".strip() for p, h, _, _, _ in procs), java_judge(ver, vendor, jc, vendor_label))
    for pid, exe, where, rv, hint, stale in container_procs:
        vendor = java_vendor(rv + " " + exe)
        ver, raw = parse_java_version(rv)
        add("Java(컨테이너 실행 중)", where, exe, vendor, raw, f"pid {pid} {hint}".strip(), java_judge(ver, vendor, jc, vendor_label))
    for (vendor, raw), (judged, cnt) in image_versions.items():
        add("Java(컨테이너 이미지 레이어)", "image", f"레이어 {cnt}개", vendor, raw, "", judged)
    return out


def main():
    adv_dir, run_dir = find_advisory(sys.argv[1]), os.path.abspath(sys.argv[2])
    crit = load_criteria(adv_dir)
    primary = set((crit.get("java") or {}).get("primary_vendors", [])) | {"MySQL", "Oracle"}
    ec2, ssm, _ = load_inventory(run_dir)
    meta_by_id = {i["id"]: i for i in ec2}
    scan_log = load_scan_log(run_dir)
    findings, hosts = [], []
    for iid in sorted(os.path.basename(p)[:-4] for p in os.listdir(os.path.join(run_dir, "hosts")) if p.startswith("i-") and p.endswith(".tsv")):
        rows = read_tsv(os.path.join(run_dir, "hosts", f"{iid}.tsv"))
        meta = meta_by_id.get(iid, {})
        m = {r[1]: r[2] for r in rows if r[0] == "META" and len(r) > 2}
        complete = bool(rows) and rows[-1][0] == "END"
        common = OrderedDict(
            instance_id=iid, name=meta.get("name") or "", os=m.get("os", ""), arch=meta.get("arch", ""), type=meta.get("type", ""),
            cpu=m.get("cpu", ""), avx512vbmi=avx512vbmi_guess(m.get("avx512vbmi", ""), m.get("cpu", "")), public_ip=meta.get("publicIp") or "",
        )
        hf = judge_host(rows, crit, common) if rows else []
        for f in hf:
            f["prio"] = priority(f, primary)
        findings.extend(hf)
        prio = min((f["prio"] for f in hf), key=lambda p: PRIO_ORDER[p], default="해당 없음")
        if not complete:
            prio = min(prio, "확인 필요", key=lambda p: PRIO_ORDER[p])
        pkgs = [f"{r[1]} {r[2]}" for r in rows if r[0] == "PKG" and len(r) > 2]
        hosts.append(OrderedDict(
            **common, ssm=(ssm.get(iid) or {}).get("ping", "NO"), method=(scan_log.get(iid) or {}).get("method", ""),
            scan_complete=complete, prio=prio,
            affected_or_eol=sum(1 for f in hf if f["status"] in AFFECTED),
            affected_running=sum(1 for f in hf if f["status"] in AFFECTED and f["running"]),
            packages="; ".join(pkgs)[:1500],
        ))
    write_csv(os.path.join(run_dir, "findings.csv"), findings)
    write_csv(os.path.join(run_dir, "hosts_summary.csv"), hosts)
    cnt = {p: sum(1 for h in hosts if h["prio"] == p) for p in PRIO_ORDER}
    print(f"findings.csv {len(findings)}행, hosts_summary.csv {len(hosts)}행 (완주 {sum(h['scan_complete'] for h in hosts)}대)")
    print("서버 우선순위: " + ", ".join(f"{k} {v}" for k, v in cnt.items() if v))
    incomplete = [h["name"] or h["instance_id"] for h in hosts if not h["scan_complete"]]
    if incomplete:
        print("끝까지 실행되지 않은 서버(재실행 필요): " + ", ".join(incomplete))


if __name__ == "__main__":
    main()
