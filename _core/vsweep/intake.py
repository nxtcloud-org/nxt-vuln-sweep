"""공지 후보 수집: KISA 보호나라 보안공지에서 최근 공지를 읽어 감시 목록에 든 것 중 아직 등록하지 않은 것을 찾는다.

사용법: _core/sweep intake [--days N] [--json 파일] [--issues [--dry-run]]
  (직접: cd _core && python3 -m vsweep.intake ...)
설정: _core/intake.toml (소스, 감시 목록, 검토 후 제외)
소스는 KISA 보안공지(보안 업데이트 권고)만 쓴다. 다른 소스를 붙이려면 src_<이름> 함수와 [sources.<이름>]을 함께 추가한다.
출력: 표준 출력에 마크다운 요약. --json 은 전체 항목, --issues 는 새 후보마다 GitHub Issue 생성(gh CLI)

공개 공지만 읽고 공개 리포의 Issue에 쓴다. 고객 환경 정보는 다루지 않는다.
후보는 등록 대상이 아니라 검토 대상이다. 기준표 값은 에이전트가 벤더 원문으로 다시 확인해서 채운다.
"""
import argparse
import datetime as dt
import email.utils
import html
import json
import os
import re
import subprocess
import tomllib
import urllib.request
import xml.etree.ElementTree as ET

from .common import CORE, REPO, load_criteria, read_csv

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
ISSUE_PREFIX = "[intake]"


def fetch(url, ua, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def text_of(el, name):
    for c in el:
        if c.tag.split("}")[-1] == name:
            return (c.text or "").strip()
    return ""


def parse_date(s):
    s = (s or "").strip()
    m = re.match(r"\d{4}-\d{2}-\d{2}", s)
    if m:
        return dt.date.fromisoformat(m.group(0))
    try:
        return email.utils.parsedate_to_datetime(s).date()
    except Exception:
        return None


def watch_of(text, watches):
    """감시 항목 중 match가 들어 있고 exclude가 없는 첫 항목"""
    t = (text or "").lower()
    return next((w for w in watches if any(k in t for k in w.get("match", [])) and not any(k in t for k in w.get("exclude", []))), None)


# ---------------- 소스별 읽기. 항목: key, source, date, title, url, vendor, cves, refs, note, watch
def src_kisa(cfg, ua, since, watches):
    root = ET.fromstring(fetch(cfg["url"], ua).encode())
    out = []
    for it in root.iter("item"):
        title, link, d = text_of(it, "title"), text_of(it, "link"), parse_date(text_of(it, "pubDate"))
        if not d or d < since or not any(k in title for k in cfg.get("title_must", [])):
            continue
        vendor = re.split(r"\s*제품|\s*보안", title)[0].strip()
        m = re.search(r"nttId=(\d+)", link)
        item = {"key": f"kisa:{m.group(1) if m else link}", "source": cfg.get("label", "KISA"), "date": str(d), "title": title,
                "url": link, "vendor": vendor, "cves": [], "refs": [], "note": "", "watch": watch_of(vendor, watches)}
        if item["watch"]:   # 감시 대상만 상세 페이지를 읽는다
            try:
                page = html.unescape(fetch(link, ua))
                item["cves"] = sorted(set(CVE_RE.findall(page)))
                i, j = page.find("참고사이트"), page.find("문의사항")
                seg = page[i:j if j > i else i + 8000] if i >= 0 else ""
                item["refs"] = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>]+", seg)))
            except Exception as e:
                item["note"] = f"상세 페이지를 읽지 못함: {e}"
        out.append(item)
    return out


SOURCES = {"kisa": src_kisa}


# ---------------- 등록 여부
def registered():
    """CVE -> 취약점 폴더 목록, 원문 URL -> 폴더"""
    by_cve, by_url = {}, {}
    p = os.path.join(REPO, "CVE_INDEX.csv")
    if os.path.exists(p):
        for r in read_csv(p):
            by_cve.setdefault(r["cve"], []).append(r["vuln_id"])
    for name in os.listdir(REPO):
        if os.path.isfile(os.path.join(REPO, name, "criteria.toml")):
            u = load_criteria(os.path.join(REPO, name)).get("url", "")
            if u:
                by_url[u.rstrip("/")] = name
    return by_cve, by_url


def classify(item, by_cve, by_url, dismissed):
    """새 후보 | 일부 등록 | 등록됨 | 제외 | 감시 목록 밖"""
    dk = next((d for d in dismissed if d.get("key") == item["key"] or (d.get("cve") and d["cve"] in item["cves"])), None)
    if dk:
        item["dismissed"] = dk
        return "제외"
    if not item["watch"]:
        return "감시 목록 밖"
    folder = by_url.get(item["url"].rstrip("/"))
    done = {c: by_cve[c] for c in item["cves"] if c in by_cve}
    item["registered"] = sorted({f for fs in done.values() for f in fs} | ({folder} if folder else set()))
    if folder or (item["cves"] and len(done) == len(item["cves"])):
        return "등록됨"
    if done:
        return "일부 등록"
    return "새 후보"


# ---------------- 출력
def issue_title(item):
    return f"{ISSUE_PREFIX} {item['key']} {item['title']}"[:200]


def issue_body(item):
    w = item["watch"] or {}
    col = ", ".join(w.get("collector", [])) or "없음(수집기와 판정기 확장 필요)"
    lines = [f"- 출처: {item['source']} ({item['date']})", f"- 제목: {item['title']}", f"- 링크: {item['url']}",
             f"- 감시 항목: {w.get('name', '-')} / 수집기 지원: {col}"]
    if item["vendor"]:
        lines.append(f"- 벤더, 제품: {item['vendor']}")
    if item["cves"]:
        lines.append(f"- CVE ({len(item['cves'])}건): {', '.join(item['cves'][:40])}" + (" ..." if len(item["cves"]) > 40 else ""))
    if item.get("registered"):
        lines.append(f"- 이미 등록된 폴더: {', '.join(item['registered'])}")
    if item["note"]:
        lines.append(f"- 메모: {item['note']}")
    if item["refs"]:
        lines.append("- 참고 링크")
        lines += [f"  - {u}" for u in item["refs"][:15]]
    lines += ["", "검토 방법",
              "- 벤더 공식 원문(참고 링크)을 찾아 읽고, 고객 서버 스택에 해당하는지 판단합니다. KISA 요약은 판정 근거로 쓰지 않습니다.",
              "- 등록하면: 에이전트에게 `이 공지 등록해줘 <벤더 원문 URL>` (AGENTS.md 작업 A). PR 본문에 이 Issue를 연결합니다.",
              "- 등록하지 않으면: `_core/intake.toml` `[[dismissed]]`에 사유와 근거를 적고 Issue를 닫습니다.",
              "", "_core/sweep intake 가 자동으로 만든 Issue입니다."]
    return "\n".join(lines)


def to_markdown(groups, errors, since):
    out = [f"# 공지 후보 수집 ({since} 이후)", ""]
    for e in errors:
        out.append(f"- 경고: {e}")
    for g in ("새 후보", "일부 등록", "등록됨", "제외"):
        items = groups.get(g, [])
        out += ["", f"## {g} ({len(items)})", ""]
        for it in items:
            w = (it["watch"] or {}).get("name", "-")
            extra = f" / 등록: {', '.join(it.get('registered', []))}" if it.get("registered") else ""
            if g == "제외":
                extra = f" / 사유: {it['dismissed'].get('reason', '')}"
            cv = f" / CVE {len(it['cves'])}건" if it["cves"] else ""
            out.append(f"- {it['date']} [{it['source']}] {it['title']} ({w}{cv}{extra}) {it['url']}")
    other = groups.get("감시 목록 밖", [])
    out += ["", f"## 감시 목록 밖 ({len(other)})", ""]
    out.append(", ".join(sorted({(it['vendor'] or it['title'])[:40] for it in other})) or "-")
    return "\n".join(out) + "\n"


def create_issues(items, dry_run):
    repo = os.environ.get("GITHUB_REPOSITORY")
    rflag = ["--repo", repo] if repo else []
    try:
        res = subprocess.run(["gh", "issue", "list", "--state", "all", "--limit", "1000", "--json", "title"] + rflag,
                             capture_output=True, text=True, check=True, cwd=REPO)
        existing = {x["title"].split(" ")[1] for x in json.loads(res.stdout) if x["title"].startswith(ISSUE_PREFIX)}
    except Exception as e:
        raise SystemExit(f"gh issue list 실패: {e}")
    made = 0
    for it in items:
        if it["key"] in existing:
            continue
        if dry_run:
            print(f"(dry-run) Issue 생성: {issue_title(it)}")
        else:
            subprocess.run(["gh", "issue", "create", "--title", issue_title(it), "--body", issue_body(it)] + rflag, check=True, cwd=REPO)
        made += 1
    print(f"새 Issue {made}건 ({'dry-run' if dry_run else '생성'}), 이미 있음 {sum(1 for it in items if it['key'] in existing)}건")


def main():
    ap = argparse.ArgumentParser(description="공지 후보 수집")
    ap.add_argument("--days", type=int)
    ap.add_argument("--json")
    ap.add_argument("--issues", action="store_true", help="새 후보와 일부 등록 항목마다 GitHub Issue 생성 (gh CLI)")
    ap.add_argument("--dry-run", action="store_true", help="--issues 와 함께: 만들 Issue만 출력")
    a = ap.parse_args()
    cfg = tomllib.load(open(os.path.join(CORE, "intake.toml"), "rb"))
    since = dt.date.today() - dt.timedelta(days=a.days or cfg.get("days", 14))
    watches, ua = cfg.get("watch", []), cfg.get("user_agent", "nxt-vuln-sweep-intake")
    items, errors = [], []
    for name, scfg in cfg.get("sources", {}).items():
        try:
            items += SOURCES[name](scfg, ua, since, watches)
        except Exception as e:
            errors.append(f"{scfg.get('label', name)} 읽기 실패: {e}")
    by_cve, by_url = registered()
    groups = {}
    for it in sorted(items, key=lambda x: x["date"], reverse=True):
        groups.setdefault(classify(it, by_cve, by_url, cfg.get("dismissed", [])), []).append(it)
    md = to_markdown(groups, errors, since)
    print(md)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(md)
    if a.json:
        with open(a.json, "w") as f:
            json.dump({k: v for k, v in groups.items()}, f, ensure_ascii=False, indent=1, default=str)
    if a.issues:
        create_issues(groups.get("새 후보", []) + groups.get("일부 등록", []), a.dry_run)
    return 1 if errors and not items else 0


if __name__ == "__main__":
    raise SystemExit(main())
