"""E2E: 置信度校准闭环 + Sigma 反哺 (真实服务 + 真实 LLM).

流程:
 1. webhook /security 发 SSH 爆破告警 (真实 LLM 研判)
 2. 轮询 alert_history.jsonl 等研判落盘 (带 confidence)
 3. POST /secops/{sid}/disposition 登记人工处置 (resolved = 真威胁)
 4. GET /secops/calibration → 真实校准数字
 5. POST /secops/detection/forge (用研判报告经验, 真实 LLM) → Sigma 草稿
 6. GET /secops/detection/drafts + approve
"""
import json
import sys
import time

import httpx

BASE = "http://127.0.0.1:9900/api/v1"
HIST = "data/alert_history.jsonl"
SID = "security-wazuh-e2e-calib-02"
FP = "e2e-calib-02"

c = httpx.Client(base_url=BASE, timeout=30, trust_env=False)


def step(n, msg):
    print(f"[{n}] {msg}", flush=True)


# 1. 发告警 (webhook 路径 — 校准闭环的 confidence 落盘就在这条链上)
step(1, "webhook SSH 爆破告警")
r = c.post("/webhook/security", json={
    "source": "wazuh", "severity": "HIGH",
    "rule": "SSHD brute force attempting login",
    "description": ("Multiple failed SSH logins from 185.220.101.42 (Tor exit) "
                     "to prod-db-01, 47 failures in 5 min, rule 5710, no successful login"),
    "src_ip": "185.220.101.42", "dst_ip": "10.0.0.21", "agent": "prod-db-01",
    "fingerprint": FP,
})
step(1, f"webhook -> {r.status_code} {r.json()}")
assert r.status_code == 202 or r.json().get("status") == "accepted", r.text

# 2. 轮询落盘 (真实 LLM 研判 1-3 分钟)
step(2, "轮询研判落盘 (真实 LLM)…")
record = None
deadline = time.time() + 420
while time.time() < deadline:
    try:
        for line in open(HIST, encoding="utf-8").read().splitlines():
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("session_id") == SID and rec.get("verdict"):
                record = rec
                break
    except FileNotFoundError:
        pass
    if record:
        break
    time.sleep(10)
assert record, "420s 内未等到研判落盘"
step(2, f"落盘: verdict={record['verdict']} confidence={record.get('confidence')} "
        f"events={record.get('event_count')}")

# 3. 人工处置登记 (resolved = 人工确认真威胁)
step(3, "登记人工处置 resolved")
r = c.post(f"/secops/{SID}/disposition", json={"action": "resolved", "note": "E2E 校准验证"})
step(3, f"disposition -> {r.status_code} {r.json()}")
assert r.status_code == 200

# 4. 校准报告 (真实数字)
step(4, "校准报告")
r = c.get("/secops/calibration")
cal = r.json()
step(4, json.dumps(cal, ensure_ascii=False, indent=1)[:1200])
assert r.status_code == 200
assert cal["status"] == "ok", cal
assert cal["sample_count"] >= 1
assert "ece" in cal["metrics"] and "brier" in cal["metrics"]

# 5. Sigma 锻造 (真实 LLM): 用本次研判报告做经验
step(5, "锻造 Sigma 规则草稿 (真实 LLM)…")
exp = (f"研判报告节选:\n{record.get('report','')[:1500]}")
r = c.post("/secops/detection/forge", json={"experience_text": exp, "source_session_id": SID},
           timeout=180)
forge = r.json()
step(5, f"forge -> {r.status_code} status={forge.get('status')}")
if forge.get("drafts"):
    d = forge["drafts"][0]
    step(5, f"草稿 fid={d['fid']} title={d.get('title','')}")
    print("--- Sigma YAML ---")
    print(d.get("sigma_yaml", "")[:1500])
assert forge.get("status") == "ok", forge

# 6. 草稿列表 + 审批
step(6, "草稿列表 + 人工审批")
r = c.get("/secops/detection/drafts")
drafts = r.json()["drafts"]
step(6, f"drafts={[(d['fid'], d['status']) for d in drafts]}")
fid = forge["drafts"][0]["fid"]
r = c.post(f"/secops/detection/drafts/{fid}/approve",
           json={"reviewer": "e2e-analyst", "note": "规则与研判证据一致"})
step(6, f"approve -> {r.status_code} {r.json()}")
assert r.json()["status"] == "approved"

print("\n=== E2E 全链路通过: 校准闭环 + Sigma 反哺 ===")
sys.exit(0)
