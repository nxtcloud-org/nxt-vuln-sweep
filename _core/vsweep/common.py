"""공통: 취약점 기준표(criteria.toml)와 점검 결과(RUN_DIR) 읽기, 버전 비교."""
import csv
import glob
import json
import os
import re
import tomllib
from collections import defaultdict

CORE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # <리포>/_core
REPO = os.path.dirname(CORE)                                          # 리포 루트 (취약점 폴더가 바로 아래)
PRIO_ORDER = {"P1": 1, "P2": 2, "P3": 3, "확인 필요": 4, "해당 없음": 5, "미점검": 6}
SET_ID_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_[a-z0-9-]+_[a-z0-9-]+$")   # 취약점 세트: 발표일_벤더_공지키
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")                          # 단일 CVE


def is_vuln_id(name):
    return bool(SET_ID_RE.match(name) or CVE_ID_RE.match(name))


def vtuple(s, n=5):
    """'21.0.13.0.3' -> (21, 0, 13, 0, 3). 숫자가 모자라면 0으로 채운다."""
    nums = [int(x) for x in re.findall(r"\d+", str(s))][:n]
    return tuple(nums + [0] * (n - len(nums)))


def find_advisory(vuln):
    """취약점 ID(루트 폴더명) 또는 경로를 받아 취약점 폴더 경로를 돌려준다."""
    for p in (vuln, os.path.join(REPO, vuln)):
        if os.path.isfile(os.path.join(p, "criteria.toml")):
            return os.path.abspath(p)
    raise SystemExit(f"취약점 폴더(criteria.toml)를 찾을 수 없음: {vuln}")


def load_criteria(adv_dir):
    with open(os.path.join(adv_dir, "criteria.toml"), "rb") as f:
        return tomllib.load(f)


def load_json(path, default):
    try:
        with open(path) as f:
            v = json.load(f)
            return v if v is not None else default
    except Exception:
        return default


def load_inventory(run_dir):
    """모든 리전의 ec2, ssm, LB 대상을 합쳐서 돌려준다."""
    ec2, ssm, lb = [], {}, defaultdict(list)
    for d in sorted(glob.glob(os.path.join(run_dir, "api", "*", ""))):
        region = os.path.basename(os.path.dirname(d))
        for i in load_json(os.path.join(d, "ec2.json"), []):
            i["region"] = region
            ec2.append(i)
        for s in load_json(os.path.join(d, "ssm.json"), []):
            ssm[s["id"]] = s
        p = os.path.join(d, "lb_targets.tsv")
        if os.path.exists(p):
            for line in open(p):
                f = line.rstrip("\n").split("\t")
                if len(f) >= 7:
                    lb[f[4]].append({"lb": f[0], "scheme": f[1], "type": f[2], "tg": f[3], "port": f[5], "state": f[6]})
    return ec2, ssm, lb


def load_scan_log(run_dir):
    """scan_log.tsv: instance-id, 방법, 상태, 글자 수, 완주 여부, command-id 또는 접속 정보, 시각. 같은 인스턴스는 마지막 줄 기준."""
    log = {}
    p = os.path.join(run_dir, "scan_log.tsv")
    if os.path.exists(p):
        for line in open(p):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 5 and f[0].startswith("i-"):
                log[f[0]] = {"method": f[1], "status": f[2], "chars": f[3], "complete": f[4],
                             "ref": f[5] if len(f) > 5 else "", "at": f[6] if len(f) > 6 else ""}
    return log


def read_tsv(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\r\n").split("\t") for line in f if line.strip()]


def read_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, bom=True):
    """bom=True: Excel에서 한글이 깨지지 않게 BOM을 붙인다(고객 결과용). 리포에 커밋하는 색인은 bom=False."""
    with open(path, "w", newline="", encoding="utf-8-sig" if bom else "utf-8") as f:
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
