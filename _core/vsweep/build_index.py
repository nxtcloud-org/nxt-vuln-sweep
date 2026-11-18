"""취약점 색인 생성: 리포 루트의 INDEX.md, CVE_INDEX.csv

사용법: _core/sweep index
취약점 폴더를 추가하거나 criteria.toml을 고친 뒤 실행해서 함께 커밋한다.
같은 CVE가 여러 폴더에 나오면 CVE_INDEX.csv에 폴더별로 한 줄씩 남는다.
"""
import os

from .common import CVE_ID_RE, REPO, SET_ID_RE, is_vuln_id, load_criteria, write_csv


def main():
    vulns, cves, problems = [], [], []
    for name in sorted(os.listdir(REPO)):
        d = os.path.join(REPO, name)
        if not os.path.isdir(d) or name.startswith((".", "_")):
            continue
        if not is_vuln_id(name):
            problems.append(f"폴더명 형식 위반: {name} (YYYY-MM-DD_벤더_공지키 또는 CVE-YYYY-NNNN)")
            continue
        for f in ("criteria.toml", "README.md"):
            if not os.path.exists(os.path.join(d, f)):
                problems.append(f"{name}/{f} 없음")
        if not os.path.exists(os.path.join(d, "criteria.toml")):
            continue
        c = load_criteria(d)
        if c.get("id") != name:
            problems.append(f"{name}/criteria.toml의 id({c.get('id')})가 폴더명과 다름")
        if CVE_ID_RE.match(name) and name not in {x.get("id") for x in c.get("cves", [])}:
            problems.append(f"{name}: 단일 CVE 폴더인데 [[cves]]에 {name}이 없음")
        for x in c.get("cves", []):
            if not CVE_ID_RE.match(x.get("id", "")):
                problems.append(f"CVE 형식 위반: {name} {x.get('id')}")
            cves.append({"cve": x.get("id", ""), "vuln_id": name, "product": x.get("product", ""),
                         "component": x.get("component", ""), "cvss": x.get("cvss", ""),
                         "remote_unauth": "Y" if x.get("remote_unauth") else "N", "scope": x.get("scope", ""),
                         "affected_versions": x.get("versions", "")})
        vulns.append((name, c))

    def cve_key(r):
        if CVE_ID_RE.match(r["cve"]):
            _, y, n = r["cve"].split("-")
            return (int(y), int(n), r["vuln_id"])
        return (0, 0, r["cve"])

    cves.sort(key=cve_key)
    write_csv(os.path.join(REPO, "CVE_INDEX.csv"), cves, bom=False,
              fieldnames=["cve", "vuln_id", "product", "component", "cvss", "remote_unauth", "scope", "affected_versions"])

    lines = ["# 취약점 목록", "",
             "`_core/sweep index`가 생성하는 파일입니다. 직접 고치지 말고 각 폴더의 criteria.toml을 고친 뒤 다시 생성합니다.", "",
             "| 폴더 | 종류 | 발표일 | 벤더 | 제목 | 제품 | CVE 수 |", "|---|---|---|---|---|---|---|"]
    for name, c in sorted(vulns, key=lambda x: str(x[1].get("published", "")), reverse=True):
        kind = "단일 CVE" if CVE_ID_RE.match(name) else "취약점 세트"
        prods = ", ".join(p["name"] for p in c.get("products", []))
        lines.append(f"| [{name}]({name}/README.md) | {kind} | {c.get('published', '')} | {c.get('vendor', '')} | "
                     f"[{c.get('title', '')}]({c.get('url', '')}) | {prods} | {len(c.get('cves', []))} |")
    with open(os.path.join(REPO, "INDEX.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"취약점 폴더 {len(vulns)}개, CVE {len(cves)}건 -> INDEX.md, CVE_INDEX.csv")
    for p in problems:
        print("경고:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
