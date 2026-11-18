"""자산 조회 결과로 스캔 대상 목록을 만든다.

사용법: _core/sweep inventory 마지막에 자동 실행 (직접: cd _core && python3 -m vsweep.targets <RUN_DIR>)
출력: RUN_DIR/targets_linux.txt, targets_windows.txt (SSM Online인 running 인스턴스, 공백 구분)
      RUN_DIR/targets_unmanaged.tsv (running인데 SSM에 없거나 Offline: id, 이름, 사설 IP, 키 페어, 플랫폼, 공인 IP)
"""
import os
import sys

from .common import load_inventory


def main():
    run_dir = os.path.abspath(sys.argv[1])
    ec2, ssm, lb = load_inventory(run_dir)
    running = [i for i in ec2 if i["state"] == "running"]
    online = {k for k, v in ssm.items() if v.get("ping") == "Online"}
    lin = [i for i in running if i["id"] in online and "Windows" not in (i.get("platform") or "")]
    win = [i for i in running if i["id"] in online and "Windows" in (i.get("platform") or "")]
    unm = [i for i in running if i["id"] not in online]
    with open(os.path.join(run_dir, "targets_linux.txt"), "w") as f:
        f.write(" ".join(i["id"] for i in lin) + "\n")
    with open(os.path.join(run_dir, "targets_windows.txt"), "w") as f:
        f.write(" ".join(i["id"] for i in win) + "\n")
    with open(os.path.join(run_dir, "targets_unmanaged.tsv"), "w") as f:
        for i in unm:
            f.write("\t".join(str(i.get(k) or "") for k in ("id", "name", "privateIp", "key", "platform", "publicIp")) + "\n")
    regions = sorted({i["region"] for i in ec2})
    print(f"EC2 {len(ec2)}대 (running {len(running)}, 기타 {len(ec2) - len(running)}), 리전: {', '.join(regions) or '-'}")
    print(f"SSM 대상: Linux {len(lin)}대, Windows {len(win)}대  -> targets_linux.txt, targets_windows.txt")
    print(f"SSM 미관리 running: {len(unm)}대 -> targets_unmanaged.tsv (bastion 경유 검토)")
    for i in unm:
        print(f"  {i['id']}\t{i.get('name') or ''}\t{i.get('privateIp') or ''}\t키={i.get('key') or '-'}\t{i.get('platform') or ''}")


if __name__ == "__main__":
    main()
