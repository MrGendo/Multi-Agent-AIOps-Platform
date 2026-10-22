"""E2E 第三轮: 只跑 Sigma 锻造 (5-6 步) — 校准链已实证 (run2 log).

真实 LLM. 用 run2 落盘的研判报告做经验.
"""
import json
import sys
import time

import httpx

BASE = "http://127.0.0.1:9900/api/v1"
c = httpx.Client(base_url=BASE, timeout=180, trust_env=False)

# 等服务就绪
r = None
for _ in range(30):
    try:
        r = c.get("/secops/calibration")
        if r.status_code == 200:
            break
    except Exception:
        time.sleep(2)
assert r is not None and r.status_code == 200, "service not ready"
print("[0] service ready, calibration:", r.json().get("status"))

# 取 run2 的研判报告当经验
record = None
for line in open("data/alert_history.jsonl", encoding="utf-8").read().splitlines():
    try:
        rec = json.loads(line)
    except Exception:
        continue
    if rec.get("session_id") == "security-wazuh-e2e-calib-02" and rec.get("report"):
        record = rec
assert record, "run2 研判记录未找到"
exp = f"研判报告节选:\n{record['report'][:1500]}"
print("[1] experience loaded, len:", len(exp))

r = c.post("/secops/detection/forge",
           json={"experience_text": exp, "source_session_id": "security-wazuh-e2e-calib-02"})
forge = r.json()
print("[2] forge ->", r.status_code, "status:", forge.get("status"))
assert forge.get("status") == "ok", json.dumps(forge, ensure_ascii=False)[:800]

d = forge["drafts"][0]
print("    fid:", d["fid"], "| title:", d.get("title", ""))
print("--- Sigma YAML ---")
print(d.get("sigma_yaml", ""))

r = c.get("/secops/detection/drafts")
print("[3] drafts:", [(x["fid"], x["status"]) for x in r.json()["drafts"]])

r = c.post(f"/secops/detection/drafts/{d['fid']}/approve",
           json={"reviewer": "e2e-analyst", "note": "规则与研判证据一致"})
print("[4] approve ->", r.json())
assert r.json()["status"] == "approved"

print("\n=== Sigma 反哺 E2E 通过 ===")
sys.exit(0)
