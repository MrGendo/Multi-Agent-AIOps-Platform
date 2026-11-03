"""安全告警分析模块评测执行器.

串行跑评测集 (防 LLM 限流), 逐案例收集 SSE 事件流的关键结论, 与 expected 对照打分,
输出结构化结果 JSON + 控制台摘要。只读评测, 不改任何生产代码。
"""
import asyncio
import json
import re
import sys
import time
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:9900/api/v1"
SET_PATH = Path(__file__).parent / "secops_eval_set.json"
OUT_PATH = Path(__file__).parent / "secops_eval_results.json"
RAW_PATH = Path(__file__).parent / "secops_eval_raw_events.jsonl"

EMAIL_CASES = {"E01", "E02"}


async def run_case(client, case):
    """跑单案例, 返回收集的事件关键数据."""
    is_email = case["id"] in EMAIL_CASES
    url = f"{BASE}/secops/email/triage" if is_email else f"{BASE}/secops/triage"
    body = ({"raw_email": case["input"], "note": ""} if is_email
            else {"query": case["input"], "session_id": f"eval-{case['id']}"})
    t0 = time.time()
    events = []
    try:
        async with client.stream("POST", url, json=body, timeout=300.0) as resp:
            if resp.status_code != 200:
                return {"http": resp.status_code, "events": [], "elapsed": round(time.time() - t0, 1)}
            buf = ""
            async for chunk in resp.aiter_text():
                buf += chunk
                # SSE 块分隔兼容 \r\n\r\n (sse-starlette) 与 \n\n
                while (m := re.search(r"\r?\n\r?\n", buf)):
                    block, buf = buf[:m.start()], buf[m.end():]
                    ev_name = next((l[6:].strip() for l in block.splitlines() if l.startswith("event:")), None)
                    data = next((l[5:].strip() for l in block.splitlines() if l.startswith("data:")), None)
                    if not data:
                        continue
                    try:
                        ev = json.loads(data)
                        # 告警接口: type 平铺在 data; 邮件接口: 事件名只在 event: 行
                        ev["_etype"] = ev.get("type") or ev_name
                        events.append(ev)
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        return {"http": f"EXC:{type(e).__name__}", "events": events, "elapsed": round(time.time() - t0, 1)}
    return {"http": 200, "events": events, "elapsed": round(time.time() - t0, 1)}


def grade(case, run):
    """对照 expected 打分 (宽松口径: 事件存在性 + 关键字段)."""
    evs = run["events"]
    by_type = {}
    for e in evs:
        # 告警接口字段嵌套在 data; 邮件接口平铺在顶层 — 统一 merge
        merged = {**(e.get("data") or {}), **{k: e[k] for k in ("stage", "message", "result") if k in e},
                  "type": e.get("type")}
        by_type.setdefault(e.get("_etype") or e.get("type"), merged)
    # 原始事件存档, 供事后重算评分
    RAW_PATH.write_text(json.dumps(evs, ensure_ascii=False), encoding="utf-8")
    exp = case["expected"]
    g = {}

    if case["id"] in EMAIL_CASES:
        rep = by_type.get("report", {})
        result = rep.get("result") or {}
        g["classification"] = result.get("classification")
        g["confidence"] = result.get("confidence")
        g["phishing_type"] = result.get("phishing_type")
        g["indicators_n"] = len(result.get("indicators") or [])
        g["det_signals_n"] = len(result.get("deterministic_signals") or [])
        g["status"] = result.get("status")
        g["pass_cls"] = g["classification"] == exp["classification"]
        g["pass_type"] = (exp.get("phishing_type") or [g["phishing_type"]])[0] == g["phishing_type"] if exp.get("phishing_type") else None
        g["seq_ok"] = [e.get("stage") for e in evs if e.get("stage")]  # 原始序供核对
        return g

    # 告警研判案例
    dom = by_type.get("domain_classified", {})
    tri = by_type.get("triage", {})
    scout = by_type.get("scout", {})
    ana = by_type.get("analyst", {})
    rep = by_type.get("report", {})
    comp = by_type.get("complete", {})

    iocs = {}
    if "iocs" in scout:
        iocs = {k: v for k, v in (scout["iocs"] or {}).items() if isinstance(v, list) and v}
    ioc_flat = " ".join(str(x) for v in iocs.values() for x in v)

    g["domain"] = dom.get("domain")
    g["alert_type"] = tri.get("alert_type")
    g["severity"] = tri.get("severity")
    # verdict 双源: 深查路径 analyst 事件, 快速通道 (初筛拦截) complete 事件
    g["verdict"] = ana.get("verdict") or comp.get("verdict")
    g["fast_path"] = "analyst" if ana.get("verdict") else ("complete" if comp.get("verdict") else None)
    g["confidence"] = ana.get("confidence")
    g["response_mode"] = (rep.get("response_mode") or ana.get("response_mode")
                          or (rep.get("meta") or {}).get("response_mode"))
    g["iocs_found"] = iocs
    # MITRE 映射渲染在 report markdown 文本内 (T#### 技术号)
    g["mitre_raw"] = " ".join(sorted(set(re.findall(r"T\d{4}", str(rep.get("report") or "")))))
    g["report_len"] = len((rep.get("report") or "") + (rep.get("message") or ""))
    g["has_report"] = g["report_len"] > 200

    _benign_exp = set(exp["verdict"]) & {"benign", "false_positive"}
    g["pass_domain"] = (g["domain"] == exp["domain"]) or (bool(_benign_exp) and g["domain"] in ("security", "ops"))
    g["pass_verdict"] = g["verdict"] in exp["verdict"]
    missing = [i for i in exp["ioc_must"] if i.lower() not in ioc_flat.lower()]
    g["pass_ioc"] = not missing
    g["ioc_missing"] = missing
    if exp.get("mitre_hint") and g["verdict"] not in ("benign", "false_positive"):
        g["pass_mitre"] = exp["mitre_hint"].lower() in g["mitre_raw"].lower()
    # 序列完整: 五阶段深查 或 快速通道(triage 拦截 + report + complete 终态)
    g["pass_seq"] = (all(t in by_type for t in ("triage", "scout", "analyst", "report"))
                     or ("report" in by_type and "complete" in by_type))
    return g


async def main():
    only = sys.argv[1:] or None
    cases = json.loads(SET_PATH.read_text(encoding="utf-8"))["cases"]
    if only:
        cases = [c for c in cases if c["id"] in only]
    results = []
    async with httpx.AsyncClient(trust_env=False) as client:  # 绕过系统代理, 本地服务直连
        for case in cases:
            print(f"[{case['id']}] {case['label']} ... ", flush=True)
            run = await run_case(client, case)
            g = grade(case, run)
            ok = all(v for k, v in g.items() if k.startswith("pass_") and v is not None)
            results.append({"id": case["id"], "label": case["label"], "format": case["format"],
                            "expected": case["expected"], "elapsed": run["elapsed"],
                            "http": run["http"], "n_events": len(run["events"]), **g})
            mark = "PASS" if ok else "FAIL"
            print(f"    -> {mark} ({run['elapsed']}s) verdict={g.get('verdict') or g.get('classification')} "
                  f"conf={g.get('confidence')}", flush=True)
    OUT_PATH.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # 控制台摘要
    print("\n===== 摘要 =====")
    for r in results:
        flags = " ".join(f"{k.replace('pass_', '')}:{'✓' if v else '✗'}" for k, v in r.items()
                         if k.startswith("pass_") and v is not None)
        print(f"{r['id']} [{r['format']}] {r['label'][:28]:30s} {flags}")


if __name__ == "__main__":
    asyncio.run(main())
