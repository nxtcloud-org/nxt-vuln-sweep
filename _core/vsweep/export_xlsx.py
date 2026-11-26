"""4단계: 고객사 보고용 엑셀 생성.

사용법: _core/sweep export <고객> <취약점ID>   (직접: cd _core && python3 -m vsweep.export_xlsx <취약점 폴더> <RUN_DIR>)
입력: RUN_DIR/findings.csv, hosts_summary.csv, scan_log.tsv, api/, notes.toml(에이전트가 작성하는 보고 문안)
      취약점 폴더의 criteria.toml (판정 기준 시트)
출력: RUN_DIR/<공지ID>_<고객>_점검결과.xlsx (notes.toml [report].output_name으로 바꿀 수 있음)

요약 시트의 수치는 다른 시트를 세는 수식이다. openpyxl은 수식 결과값을 저장하지 않으므로 Excel이 열 때 재계산하도록 지정한다.
고객에게 보내기 전에 Excel로 한 번 열어 저장하면 미리보기에서도 숫자가 보인다.
"""
import os
import re
import sys
import tomllib
from collections import Counter, OrderedDict, defaultdict

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.workbook.properties import CalcProperties

from .common import PRIO_ORDER, find_advisory, load_criteria, load_inventory, load_scan_log, read_csv, read_tsv

FONT = "맑은 고딕"
F_BASE = Font(name=FONT, size=10)
F_BOLD = Font(name=FONT, size=10, bold=True)
F_HEAD = Font(name=FONT, size=10, bold=True, color="FFFFFF")
F_TITLE = Font(name=FONT, size=14, bold=True)
F_SUB = Font(name=FONT, size=11, bold=True, color="1F4E78")
F_NOTE = Font(name=FONT, size=9, color="595959")
FILL_HEAD = PatternFill("solid", fgColor="1F4E78")
FILL_LABEL = PatternFill("solid", fgColor="DDEBF7")
PRIO_FILL = {
    "P1": PatternFill("solid", fgColor="F4B6B6"),
    "P2": PatternFill("solid", fgColor="FCD5B4"),
    "P3": PatternFill("solid", fgColor="FFF2CC"),
    "확인 필요": PatternFill("solid", fgColor="DDEBF7"),
    "해당 없음": PatternFill("solid", fgColor="E2EFDA"),
    "미점검": PatternFill("solid", fgColor="D9D9D9"),
}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="top", wrap_text=True)
RIGHT = Alignment(horizontal="right", vertical="top")
SCOPE_TEXT = {
    "server": "서버 해당 (웹 서비스 등 API로 데이터 전달 시)",
    "client": "클라이언트 전용 (샌드박스 애플릿, Web Start)",
    "both": "서버, 클라이언트 모두 해당",
}
DEFAULT_LIMITS = [
    "fat jar, WAR 내부에 묶인 라이브러리는 파일명 기반 탐색이라 검출되지 않음",
    "Windows의 AVX-512 VBMI 지원 여부는 CPU 모델 기준 추정값 (Linux는 /proc/cpuinfo로 직접 확인)",
    "외부 노출은 인터넷용 ALB/NLB 대상 등록 기준이며, 등록 포트가 해당 서비스 포트인지는 서비스별 확인 필요",
    "파생 빌드(OpenJDK 계열 등)의 패치 빌드 출시 여부는 벤더별 확인 필요",
]


# ---------------- 표시용 변환
def display_version(f):
    v = f["version"]
    if f["kind"] == "Oracle Home":
        m = re.search(r"Oracle (Client|Database[^0-9|]*|WebLogic Server)\s+(\d+(?:\.\d+)+)", v)
        return m.group(2) if m else v
    m = re.match(r"1\.([5-8])\.0(?:_(\d+))?$", v)
    if m:
        return f"{m.group(1)}u{m.group(2) or 0}"
    m = re.match(r"(\d)u(\d+) \(file=", v)
    if m:
        return f"{m.group(1)}u{m.group(2)}"
    m = re.match(r"(?i)(?:jdk|jre)[-_]?1\.?([0-7])\.?(\d)$", v)
    if m:
        return f"1.{m.group(1)}.{m.group(2)}"
    return v


def display_product(f):
    if f["kind"] == "Oracle Home":
        m = re.search(r"Oracle (Client|Database[^0-9|]*|WebLogic Server)\s+\d", f["version"])
        return f"Oracle {m.group(1).strip()}" if m else "Oracle Home"
    if f["kind"] == "Oracle Instant Client":
        return "Oracle Instant Client"
    return {"Oracle Java SE": "Oracle JDK", "미상": "JDK(제조사 미상)"}.get(f["vendor"], f["vendor"])


def display_kind(f):
    k = f["kind"]
    if "(컨테이너 실행" in k:
        return k.split("(")[0] + "(컨테이너)"
    if "이미지 레이어" in k:
        return k.split("(")[0] + "(이미지 레이어)"
    if k.startswith("Java(실행 중"):
        return "Java"
    return k


def run_state(f):
    if "이미지 레이어" in f["kind"]:
        return "이미지 레이어"
    return "실행 중" if f["running"] else "미실행"


def services(f):
    if not f["running"]:
        return ""
    if f["kind"].startswith("MySQL"):
        return "mysqld (서비스)"
    if f["kind"].startswith("nginx"):
        n = len(f["running"].split("; "))
        return "nginx master" + (f" x{n}" if n > 1 else "") + (" [컨테이너]" if "컨테이너" in f["kind"] else "")
    if not f["kind"].startswith("Java"):   # SW 레코드(PostgreSQL, httpd, Node.js 앱 등)
        if not f["running"].startswith("pid "):   # 프로세스가 아닌 것(커널)
            return f"{f['vendor']} {f['running']}"
        n = len(f["running"].split("; "))
        return f"{f['vendor']} 프로세스" + (f" x{n}" if n > 1 else "") + (" [컨테이너]" if "컨테이너" in f["kind"] else "")
    parts = []
    for seg in f["running"].split("; "):
        seg = re.sub(r"^pid \d+\s*", "", seg).strip()
        m = re.match(r'-Dcatalina\.base="?([^"]+)"?', seg)
        if m:
            parts.append(f"Tomcat ({m.group(1)})")
        elif "(내장 JVM" in seg:
            parts.append(seg.split("(")[0] + " (내장 JVM)")
        elif not seg:
            parts.append("java 프로세스")
        else:
            parts.append(os.path.basename(seg.replace("\\", "/").rstrip("/")) if re.search(r"[\\/]", seg) else seg)
    cnt = Counter(parts)
    out = [f"{p} x{cnt[p]}" if cnt[p] > 1 else p for p in OrderedDict.fromkeys(parts)]
    if f["kind"].startswith("Java(컨테이너 실행"):
        out = [o + " [컨테이너]" for o in out]
    return ", ".join(out)


# ---------------- 시트 도우미
def style_table(ws, top, left, rows, cols, widths=None):
    for r in range(top, top + rows):
        for c in range(left, left + cols):
            cell = ws.cell(r, c)
            cell.border = BORDER
            if r == top:
                cell.font, cell.fill, cell.alignment = F_HEAD, FILL_HEAD, CENTER
            else:
                cell.font, cell.alignment = F_BASE, WRAP
    for i, w in enumerate(widths or []):
        ws.column_dimensions[get_column_letter(left + i)].width = w


def put_table(ws, top, left, rows, widths=None):
    for r, row in enumerate(rows, start=top):
        for c, v in enumerate(row, start=left):
            ws.cell(r, c, v)
    style_table(ws, top, left, len(rows), len(rows[0]), widths)


def put_numbered(ws, top, items, last_col, height=42):
    for k, t in enumerate(items, start=1):
        c = ws.cell(top + k, 1, f"{k}.")
        c.font, c.alignment = F_BASE, RIGHT
        ws.merge_cells(start_row=top + k, start_column=2, end_row=top + k, end_column=last_col)
        c2 = ws.cell(top + k, 2, t)
        c2.font, c2.alignment = F_BASE, WRAP
        ws.row_dimensions[top + k].height = height


def title(ws, text, sub=None):
    ws["A1"], ws["A1"].font = text, F_TITLE
    if sub:
        ws["A2"], ws["A2"].font = sub, F_NOTE


def end_seconds(run_dir, iid):
    try:
        last = read_tsv(os.path.join(run_dir, "hosts", f"{iid}.tsv"))[-1]
        return int(re.sub(r"\D", "", last[1])) if last[0] == "END" else None
    except Exception:
        return None


def main():
    adv_dir, run_dir = find_advisory(sys.argv[1]), os.path.abspath(sys.argv[2])
    crit = load_criteria(adv_dir)
    notes_path = os.path.join(run_dir, "notes.toml")
    notes = tomllib.load(open(notes_path, "rb")) if os.path.exists(notes_path) else {}
    rep = notes.get("report", {})
    host_notes = notes.get("host_notes", {})
    vendor_label = crit.get("vendor_label", crit.get("vendor", ""))

    ec2, ssm, lb = load_inventory(run_dir)
    scan_log = load_scan_log(run_dir)
    findings = read_csv(os.path.join(run_dir, "findings.csv"))
    hosts = {h["instance_id"]: h for h in read_csv(os.path.join(run_dir, "hosts_summary.csv"))}
    state_ko = {"healthy": "정상", "unhealthy": "비정상", "unused": "미사용", "draining": "드레이닝", "initial": "초기화"}

    # ---------------- 서버별 현황
    server_rows = []
    for i in ec2:
        iid, name = i["id"], i.get("name") or ""
        h = hosts.get(iid)
        fs = [f for f in findings if f["instance_id"] == iid]
        if h:
            method = h.get("method") or (scan_log.get(iid) or {}).get("method") or "SSM"
            prio, os_name = h["prio"], h["os"]
            lines = []
            for f in sorted(fs, key=lambda x: PRIO_ORDER[x["prio"]]):
                if f["prio"] == "해당 없음":
                    continue
                state = {"실행 중": "실행 중", "미실행": "설치(미실행)", "이미지 레이어": "이미지 레이어"}[run_state(f)]
                lines.append(f"[{f['prio']}] {display_product(f)} {display_version(f)} {state}")
            result = "\n".join(OrderedDict.fromkeys(lines)) or "공지 대상 제품 없음"
            if h["scan_complete"] != "True":
                result = "스캔이 끝까지 실행되지 않음(재점검 필요)\n" + result
        else:
            method = "미점검(정지)" if i["state"] == "stopped" else "미점검(접속 불가)"
            prio, result = "미점검", "점검하지 못함"
            s = ssm.get(iid)
            os_name = f"{s['os']} {s.get('osver', '')}".strip() if s and s.get("os") else (i.get("platform") or "")
        exp = defaultdict(list)
        for t in sorted(lb.get(iid, []), key=lambda x: (x["lb"], int(x["port"]) if x["port"].isdigit() else 0)):
            if t["scheme"] == "internet-facing":
                exp[t["lb"]].append(f"{t['port']}({state_ko.get(t['state'], t['state'])})")
        exposure = "\n".join(f"{k}: {', '.join(OrderedDict.fromkeys(v))}" for k, v in exp.items())
        if i.get("publicIp"):
            exposure = (f"공인 IP {i['publicIp']}\n" + exposure).strip()
        server_rows.append([name, iid, os_name, i.get("arch", ""), i.get("type", ""),
                            {"running": "실행", "stopped": "정지"}.get(i["state"], i["state"]),
                            method, prio, result, exposure or "-", host_notes.get(name, host_notes.get(iid, ""))])
    server_rows.sort(key=lambda r: (PRIO_ORDER[r[7]], r[0]))

    # ---------------- 발견 항목 상세
    name_of = {i["id"]: i.get("name") or "" for i in ec2}
    detail_rows = []
    for f in findings:
        cvss = float(f["max_server_cvss"]) if f["max_server_cvss"] else None
        detail_rows.append([f["prio"], name_of.get(f["instance_id"], f["name"]), f["instance_id"], display_kind(f), display_product(f),
                            display_version(f), run_state(f), services(f), f["verdict"], cvss, f["path"], f["detail"]])
    detail_rows.sort(key=lambda r: (PRIO_ORDER[r[0]], r[1], r[4], r[5]))

    wb = Workbook()
    srv, det = "'서버별 현황'", "'발견 항목 상세'"
    s_first, s_last = 5, 4 + len(server_rows)
    d_first, d_last = 5, 4 + max(len(detail_rows), 1)

    # ================= 요약
    ws = wb.active
    ws.title = "요약"
    title(ws, rep.get("title", f"{crit['title']} 영향 전수조사 결과"),
          f"작성일 {rep.get('written', '')}. 점검은 읽기 전용으로 수행했으며 패치, 설정 변경, 재기동은 하지 않았습니다.")
    ws["A4"], ws["A4"].font = "1. 조사 개요", F_SUB
    overview = [("항목", "내용"),
                ("대상", rep.get("target", "")),
                ("조사 일시", rep.get("period", "")),
                ("기준 공지", f"{crit['title']} ({crit.get('revision', '')}, {crit.get('published', '')})\n{crit.get('url', '')}"),
                ("조사 방식", rep.get("method", "AWS API 자산 조회, SSM Run Command 및 Bastion 경유 SSH로 서버 내부 읽기 전용 스캔")),
                ("조사 범위", rep.get("scope", crit.get("report_scope", "EC2 전체, RDS, Lambda, ECR. 서버 내부는 패키지, 실행 중 JVM, 디스크 전체의 JDK와 MySQL, Oracle Home, 컨테이너")))]
    put_table(ws, 5, 1, overview)
    for r in range(5, 5 + len(overview)):
        ws.merge_cells(start_row=r, start_column=2, end_row=r, end_column=4)
        for c in (3, 4):
            ws.cell(r, c).border = BORDER
        if r > 5:
            ws.cell(r, 1).fill, ws.cell(r, 1).font = FILL_LABEL, F_BOLD

    n_run = sum(1 for i in ec2 if i["state"] == "running")
    # 서버별 현황 열: A No, B 서버명, C 인스턴스 ID, ..., H 점검 방법, I 우선순위
    ids, method, prio = f"{srv}!$C${s_first}:$C${s_last}", f"{srv}!$H${s_first}:$H${s_last}", f"{srv}!$I${s_first}:$I${s_last}"
    r0 = 5 + len(overview) + 1
    ws.cell(r0, 1, "2. 결과 요약").font = F_SUB
    desc = {
        "P1": f"{vendor_label} 제품이 영향 버전 또는 EOL 버전으로 실행 중",
        "P2": "파생 빌드(OpenJDK 계열 등)가 영향 범위 버전 또는 EOL 버전으로 실행 중",
        "P3": "영향 버전 또는 EOL 버전이 설치만 되어 있음(미실행, 컨테이너 이미지 레이어 포함)",
        "확인 필요": "버전을 읽지 못했거나 사람이 대조해야 하는 항목이 있음",
        "해당 없음": "공지 대상 제품이 없거나 이미 범위 밖 버전",
        "미점검": "정지 또는 접속 수단 없음 (미점검 대상 시트 참고)",
    }
    desc.update(crit.get("priority_desc", {}))   # 공지별 설명 (criteria.toml)
    summary = [("구분", "서버 수", "발견 항목 수", "설명"),
               ("EC2 전체", f"=COUNTA({ids})", "", f"실행 중 {n_run}대, 그 외 {len(ec2) - n_run}대"),
               ("점검 완료", f'=COUNTIF({method},"SSM")+COUNTIF({method},"Bastion(SSH)")', "", "SSM 또는 Bastion 경유로 스캔을 수행한 서버")]
    for p in ("P1", "P2", "P3", "확인 필요", "해당 없음", "미점검"):
        cnt_items = f'=COUNTIF({det}!$B${d_first}:$B${d_last},"{p}")' if p != "미점검" else ""
        summary.append((p, f'=COUNTIF({prio},"{p}")', cnt_items, desc[p]))
    first_p, last_p = r0 + 4, r0 + 3 + 6
    summary.append(("합계 확인", f"=SUM(B{first_p}:B{last_p})", "", "P1부터 미점검까지 합계. EC2 전체와 같아야 함"))
    put_table(ws, r0 + 1, 1, summary, [16, 11, 13, 84])
    for r in range(r0 + 2, r0 + 1 + len(summary)):
        lab = ws.cell(r, 1)
        lab.font, lab.fill = F_BOLD, PRIO_FILL.get(lab.value, FILL_LABEL)
        for c in (2, 3):
            ws.cell(r, c).alignment, ws.cell(r, c).number_format = CENTER, "0"

    r1 = r0 + 1 + len(summary) + 1
    ws.cell(r1, 1, "3. 주요 발견 사항").font = F_SUB
    put_numbered(ws, r1, rep.get("key_findings", ["(notes.toml [report].key_findings에 작성)"]), 4)
    r2 = r1 + len(rep.get("key_findings", [""])) + 2
    ws.cell(r2, 1, "4. 후속 검토 사항 (권고)").font = F_SUB
    put_numbered(ws, r2, rep.get("recommendations", ["(notes.toml [report].recommendations에 작성)"]), 4)
    ws.sheet_view.showGridLines = False

    # ================= 서버별 현황
    ws2 = wb.create_sheet("서버별 현황")
    title(ws2, "서버별 현황 (EC2 전체)", "우선순위는 서버에서 발견된 항목 중 가장 높은 것 기준. 외부 노출은 인터넷용 ALB/NLB 대상 등록 포트와 대상 상태")
    cols = ["No", "서버명", "인스턴스 ID", "OS", "아키텍처", "인스턴스 유형", "상태", "점검 방법", "우선순위", "점검 결과", "외부 노출(인터넷용 LB)", "비고"]
    put_table(ws2, 4, 1, [cols] + [[n] + row for n, row in enumerate(server_rows, start=1)],
              [5, 24, 21, 26, 9, 12, 7, 13, 10, 46, 34, 52])
    for r in range(5, 5 + len(server_rows)):
        p = ws2.cell(r, 9)
        p.fill, p.alignment, p.font = PRIO_FILL[p.value], CENTER, F_BOLD
        for c in (1, 5, 7, 8):
            ws2.cell(r, c).alignment = CENTER
    ws2.freeze_panes = "C5"
    ws2.auto_filter.ref = f"A4:{get_column_letter(len(cols))}{s_last}"

    # ================= 발견 항목 상세
    ws3 = wb.create_sheet("발견 항목 상세")
    title(ws3, "발견 항목 상세", "서버별로 발견된 제품과 판정. 서버 해당 최고 CVSS는 서버 환경에도 적용되는 CVE 중 최고 점수")
    cols3 = ["No", "우선순위", "서버명", "인스턴스 ID", "구분", "제품", "버전", "실행 상태", "실행 중 서비스", "판정", "서버 해당 최고 CVSS", "설치 경로", "비고"]
    put_table(ws3, 4, 1, [cols3] + [[n] + row for n, row in enumerate(detail_rows, start=1)],
              [5, 10, 24, 21, 17, 22, 14, 12, 44, 40, 11, 56, 40])
    for r in range(5, 5 + len(detail_rows)):
        p = ws3.cell(r, 2)
        p.fill, p.alignment, p.font = PRIO_FILL[p.value], CENTER, F_BOLD
        for c in (1, 7, 8, 11):
            ws3.cell(r, c).alignment = CENTER
        ws3.cell(r, 11).number_format = "0.0"
    ws3.freeze_panes = "D5"
    ws3.auto_filter.ref = f"A4:{get_column_letter(len(cols3))}{d_last}"

    # ================= 판정 기준
    ws4 = wb.create_sheet("판정 기준")
    sub = f"출처: {crit.get('url', '')} ({crit.get('revision', '')}, {crit.get('published', '')})"
    if crit.get("total_patches"):
        sub += f". 신규 보안 패치 {crit['total_patches']}건"
    title(ws4, f"판정 기준 ({vendor_label} 공식 공지 발췌)", sub)
    ws4["A4"], ws4["A4"].font = "1. 제품별 영향 버전", F_SUB
    prod = [("제품", "공지의 영향 버전", "최고 CVSS", "비고")] + [
        (p["name"], p["versions"], p.get("max_cvss"), p.get("note", "")) for p in crit.get("products", [])]
    put_table(ws4, 5, 1, prod, [24, 50, 10, 16, 40, 70, 40])
    for r in range(6, 5 + len(prod)):
        ws4.cell(r, 3).alignment, ws4.cell(r, 3).number_format = CENTER, "0.0"
    rj = 5 + len(prod) + 1
    ws4.cell(rj, 1, "2. 판정에 사용한 CVE").font = F_SUB
    cves = [("CVE", "제품", "구성요소", "CVSS 3.1", "인증 없이 원격", "적용 환경(조건)", "영향 버전")] + [
        (c["id"], c["product"], c.get("component", ""), c.get("cvss"), "예" if c.get("remote_unauth") else "아니오",
         SCOPE_TEXT.get(c.get("scope", ""), c.get("scope", "")) or c.get("condition", ""), c.get("versions", "")) for c in crit.get("cves", [])]
    put_table(ws4, rj + 1, 1, cves)
    for r in range(rj + 2, rj + 1 + len(cves)):
        for c in (4, 5):
            ws4.cell(r, c).alignment = CENTER
        ws4.cell(r, 4).number_format = "0.0"
    rr = rj + 1 + len(cves) + 1
    ws4.cell(rr, 1, "3. 판정 규칙").font = F_SUB
    put_numbered(ws4, rr, crit.get("judgement_rules", []), 7, height=30)
    rn = rr + len(crit.get("judgement_rules", [])) + 2
    if crit.get("next_releases"):
        ws4.cell(rn, 1, "4. 다음 보안 패치 일정 (공지 기준)").font = F_SUB
        for k, nr in enumerate(crit["next_releases"], start=1):
            ws4.cell(rn + k, 1, str(nr["date"])).font = F_BASE
            ws4.cell(rn + k, 2, nr["type"]).font = F_BASE
    ws4.sheet_view.showGridLines = False

    # ================= 미점검 대상
    ws5 = wb.create_sheet("미점검 대상")
    title(ws5, "미점검 대상", "이번 조사에서 서버 내부를 스캔하지 못한 대상과 사유")
    un_notes = notes.get("unscanned", {})
    unscanned = []
    for i in ec2:
        if i["id"] in hosts:
            continue
        n = un_notes.get(i["id"], {})
        if i["state"] == "stopped":
            unscanned.append([i.get("name") or "", i["id"], "정지", n.get("reason", "인스턴스가 정지 상태"), n.get("action", "기동 시 같은 방식으로 점검")])
        else:
            unscanned.append([i.get("name") or "", i["id"], {"running": "실행"}.get(i["state"], i["state"]),
                              n.get("reason", "접속 수단 없음"), n.get("action", "접속 정보 확보 후 점검")])
    unscanned.sort(key=lambda r: (r[2] != "실행", r[0]))
    for x in notes.get("extra_unscanned", []):
        unscanned.append([x.get("target", ""), x.get("id", ""), x.get("state", "-"), x.get("reason", ""), x.get("action", "")])
    put_table(ws5, 4, 1, [["대상", "인스턴스 ID / 저장소", "상태", "사유", "필요 조치"]] + (unscanned or [["없음", "", "", "", ""]]),
              [24, 30, 8, 60, 44])

    # ================= 점검 방법
    ws6 = wb.create_sheet("점검 방법")
    title(ws6, "점검 방법과 한계")
    n_bastion = sum(1 for v in scan_log.values() if v["method"].startswith("Bastion"))
    secs = defaultdict(list)
    for iid, h in hosts.items():
        s = end_seconds(run_dir, iid)
        if s is not None:
            secs["Windows" if "Windows" in h["os"] else "Linux"].append(s)
    timing = ", ".join(f"{k} {min(v)}-{max(v)}초" for k, v in sorted(secs.items()))
    steps = [("단계", "내용"),
             ("1. 자산 조회", "AWS API(describe/list)로 전체 리전의 EC2, SSM 등록 상태, RDS, Lambda, ECR, ECS, EKS, Elastic Beanstalk, 로드밸런서 대상 조회"),
             ("2. 서버 스캔 (SSM)", "SSM Run Command(AWS-RunShellScript, AWS-RunPowerShellScript)로 읽기 전용 수집 스크립트 실행. 코멘트: nxt-vuln-sweep read-only inventory"),
             ("3. 서버 스캔 (Bastion)", f"SSM 에이전트가 없는 Linux {n_bastion}대는 Bastion 경유 SSH로 같은 스크립트 실행. 대상 서버에 파일을 남기지 않음"),
             ("4. 판정", "수집 결과를 공지의 영향 버전과 대조해 항목별, 서버별로 판정"),
             ("수집 항목", crit.get("collected_items", "패키지 목록, 실행 중 JVM(libjvm.so 또는 jvm.dll을 로드한 모든 프로세스와 실행 버전), 로컬 디스크 전체의 java, mysqld, weblogic.jar 등, Oracle Home과 OPatch 결과, Docker 컨테이너와 이미지 레이어, CPU 모델")),
             ("부하 최소화", f"스캔 프로세스의 CPU, 디스크 I/O 우선순위를 최저로 낮춰 실행. 서버당 소요 시간 {timing or '-'}")]
    for k, t in enumerate(rep.get("limitations", crit.get("limitations", DEFAULT_LIMITS)), start=1):
        steps.append((f"한계 {k}", t))
    put_table(ws6, 3, 1, steps, [22, 110])
    for r in range(4, 3 + len(steps)):
        ws6.cell(r, 1).font, ws6.cell(r, 1).fill = F_BOLD, FILL_LABEL

    for w in wb.worksheets:
        w.page_setup.orientation = "landscape"
        w.page_setup.fitToWidth, w.page_setup.fitToHeight = 1, 0
        w.sheet_properties.pageSetUpPr.fitToPage = True
    wb.calculation = CalcProperties(fullCalcOnLoad=True)
    out = os.path.join(run_dir, rep.get("output_name") or f"{crit['id']}_{rep.get('customer', os.path.basename(os.path.dirname(run_dir)))}_점검결과.xlsx")
    wb.save(out)
    print(f"{out} (서버 {len(server_rows)}대, 발견 항목 {len(detail_rows)}건)")


if __name__ == "__main__":
    main()
