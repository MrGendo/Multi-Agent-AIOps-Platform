"""\u544a\u8b66 Webhook \u63a5\u6536\u63a5\u53e3 \u2014 \u5bf9\u63a5 Prometheus Alertmanager \u6807\u51c6\u534f\u8bae.

\u8fd9\u662f AIOps Agent \u4ece "\u6f14\u793a\u6a21\u5f0f" \u5347\u7ea7\u4e3a "\u751f\u4ea7\u6a21\u5f0f" \u7684\u5173\u952e\u63a5\u53e3:
  - \u624b\u52a8\u6a21\u5f0f: \u4eba\u5728\u524d\u7aef\u8f93\u5165\u544a\u8b66\u6587\u672c \u2192 SSE \u6d41\u51fa\u8bca\u65ad\u62a5\u544a
  - \u81ea\u52a8\u6a21\u5f0f (\u672c\u6587\u4ef6): Alertmanager POST \u6807\u51c6 JSON \u2192 \u540e\u53f0\u5f02\u6b65\u8df3\u8bca\u65ad \u2192 \u5199\u5165 history

\u4e3a\u4ec0\u4e48\u4e0d\u8d70 SSE?
  Alertmanager webhook \u8981\u6c42 5s \u5185\u8fd4\u56de 200, \u7136\u540e\u8c03\u7528\u65b9\u4e0d\u518d\u5173\u5fc3\u3002
  AIOps \u8bca\u65ad\u4e00\u8dd1 30-90s, \u5fc5\u987b\u540e\u53f0\u5f02\u6b65\u8dd1, \u7ed3\u679c\u843d\u76d8\u4f9b\u540e\u7eed\u67e5\u8be2.

\u4e3a\u4ec0\u4e48\u8981\u843d\u76d8 alert_history.jsonl?
  \u8ba9\u4f60\u80fd\u4e8b\u540e\u770b\u5230 "AIOps \u81ea\u52a8\u8dd1\u4e86\u4ec0\u4e48", \u8bc1\u660e\u5168\u81ea\u52a8\u4e0d\u662f\u5077\u61d2.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, BackgroundTasks
from loguru import logger
from pydantic import BaseModel, Field

import app.services.aiops_service as aiops_service

router = APIRouter(prefix="/webhook", tags=["webhook"])


# ============================================================
# Alertmanager v4 webhook payload
#   \u89c4\u8303: https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
# ============================================================
class AlertmanagerAlert(BaseModel):
    """\u5355\u6761 firing/resolved \u544a\u8b66."""

    status: str = Field(default="firing", description="firing | resolved")
    labels: Dict[str, Any] = Field(
        default_factory=dict,
        description="\u544a\u8b66\u6807\u7b7e (alertname / severity / instance \u7b49)",
    )
    annotations: Dict[str, Any] = Field(
        default_factory=dict,
        description="\u63cf\u8ff0\u4fe1\u606f (summary / description / runbook_url)",
    )
    startsAt: str = Field(default="", description="\u544a\u8b66\u5f00\u59cb\u65f6\u95f4 ISO8601")
    endsAt: str = Field(default="", description="\u544a\u8b66\u7ed3\u675f\u65f6\u95f4 (resolved \u624d\u6709)")
    generatorURL: str = Field(default="", description="\u539f\u59cb\u544a\u8b66\u89c4\u5219 URL")
    fingerprint: str = Field(default="", description="\u544a\u8b66\u6307\u7eb9 (\u7528\u4e8e\u53bb\u91cd)")


class AlertmanagerPayload(BaseModel):
    """Alertmanager v4 webhook \u5b8c\u6574 payload."""

    version: str = Field(default="4")
    groupKey: str = Field(default="")
    truncatedAlerts: int = Field(default=0)
    status: str = Field(default="firing")
    receiver: str = Field(default="")
    groupLabels: Dict[str, Any] = Field(default_factory=dict)
    commonLabels: Dict[str, Any] = Field(default_factory=dict)
    commonAnnotations: Dict[str, Any] = Field(default_factory=dict)
    externalURL: str = Field(default="")
    alerts: List[AlertmanagerAlert] = Field(default_factory=list)


# ============================================================
# History \u843d\u76d8
# ============================================================
HISTORY_DIR = Path(__file__).resolve().parents[3] / "data"
HISTORY_FILE = HISTORY_DIR / "alert_history.jsonl"


def _ensure_history_dir():
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def _append_history(record: Dict[str, Any]) -> None:
    """\u8ffd\u5199\u4e00\u6761 history \u8bb0\u5f55 (JSONL \u683c\u5f0f, \u7b80\u5355\u53ef\u9760)."""
    _ensure_history_dir()
    with HISTORY_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ============================================================
# \u544a\u8b66 \u2192 \u81ea\u7136\u8bed\u8a00 query (\u4f9b LangGraph \u7406\u89e3)
# ============================================================
def _format_alert_as_query(alert: AlertmanagerAlert) -> str:
    """\u628a\u7ed3\u6784\u5316\u544a\u8b66\u6e32\u67d3\u6210\u4e00\u6bb5\u4eba\u53ef\u8bfb\u3001LLM \u53ef\u7406\u89e3\u7684\u63cf\u8ff0."""
    name = alert.labels.get("alertname", "UnknownAlert")
    severity = alert.labels.get("severity", "warning")
    instance = alert.labels.get("instance", "")
    service = alert.labels.get("service", "")
    summary = alert.annotations.get("summary", "")
    description = alert.annotations.get("description", "")
    runbook = alert.annotations.get("runbook_url", "")

    instance_text = instance or "(\u672a\u6307\u5b9a)"
    parts = [
        f"[{severity.upper()}] {name} \u544a\u8b66\u89e6\u53d1",
        f"\u5b9e\u4f8b: {instance_text}",
    ]
    if service:
        parts.append(f"\u670d\u52a1: {service}")
    if summary:
        parts.append(f"\u6458\u8981: {summary}")
    if description:
        parts.append(f"\u63cf\u8ff0: {description}")
    if alert.startsAt:
        parts.append(f"\u5f00\u59cb\u65f6\u95f4: {alert.startsAt}")
    if runbook:
        parts.append(f"\u5e94\u6025\u624b\u518c: {runbook}")
    parts.append("\u8bf7\u4f60\u4f5c\u4e3a OnCall \u5de5\u7a0b\u5e08, \u8bca\u65ad\u4e0a\u8ff0\u544a\u8b66\u6839\u56e0\u5e76\u7ed9\u51fa\u5904\u7f6e\u5efa\u8bae.")
    return "\n".join(parts)


# ============================================================
# \u540e\u53f0\u8dd1\u8bca\u65ad
# ============================================================
async def _run_diagnosis_background(
    query: str,
    session_id: str,
    alert_meta: Dict[str, Any],
) -> None:
    """\u540e\u53f0\u8dd1 aiops_service.stream_diagnose, \u6536\u96c6\u5b8c\u6574\u4e8b\u4ef6\u6d41 \u2192 \u843d\u76d8.

    \u6ce8\u610f: \u8fd9\u4e0d\u662f SSE, \u4e5f\u4e0d\u62a5\u9519\u7ed9\u8c03\u7528\u65b9.
    \u7ed3\u679c\u5168\u90e8\u5199\u8fdb HISTORY_FILE, \u5931\u8d25\u4e5f\u8981\u5199 (\u4f9b\u4e8b\u540e\u8c03\u67e5).
    """
    started_at = datetime.now(timezone.utc).isoformat()
    events: List[Dict[str, Any]] = []
    final_report = ""
    selected_skill = ""
    error_msg = ""

    logger.info(
        f"[webhook] \u540e\u53f0\u542f\u52a8\u8bca\u65ad session={session_id} "
        f"alert={alert_meta.get('alertname')}"
    )

    try:
        async for ev in aiops_service.stream_diagnose(query, session_id=session_id):
            events.append(ev)
            ev_type = ev.get("type", "")
            if ev_type == "skill_selected":
                selected_skill = ev.get("data", {}).get("skill", "")
            elif ev_type == "report":
                final_report = ev.get("data", {}).get("report", "")
    except asyncio.CancelledError:
        error_msg = "cancelled"
        raise
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.exception(f"[webhook] \u8bca\u65ad\u5f02\u5e38: {e}")

    finished_at = datetime.now(timezone.utc).isoformat()

    record = {
        "session_id": session_id,
        "alert": alert_meta,
        "query": query,
        "started_at": started_at,
        "finished_at": finished_at,
        "selected_skill": selected_skill,
        "report": final_report,
        "event_count": len(events),
        "error": error_msg,
    }
    _append_history(record)
    skill_text = selected_skill or "(\u672a\u9009\u4e2d)"
    logger.info(
        f"[webhook] \u8bca\u65ad\u5b8c\u6210 session={session_id} "
        f"skill={skill_text} "
        f"events={len(events)} report_len={len(final_report)}"
    )


# ============================================================
# \u8def\u7531
# ============================================================
@router.post(
    "/alertmanager",
    summary="Alertmanager \u544a\u8b66\u63a5\u6536 (\u5168\u81ea\u52a8\u6a21\u5f0f)",
    description=(
        "\u63a5\u6536 Prometheus Alertmanager \u6807\u51c6 webhook payload, "
        "\u540e\u53f0\u5f02\u6b65\u542f\u52a8 AIOps \u8bca\u65ad\u3002"
        "\u7acb\u5373\u8fd4\u56de 200 (Alertmanager \u8981\u6c42 5s \u5185\u54cd\u5e94), "
        "\u8bca\u65ad\u8fc7\u7a0b\u5728\u540e\u53f0\u8dd1, \u7ed3\u679c\u5199\u5165 data/alert_history.jsonl. "
        "\u53ef\u901a\u8fc7 GET /webhook/history \u67e5\u770b\u540e\u53f0\u8dd1\u8fc7\u7684\u8bca\u65ad."
    ),
)
async def alertmanager_webhook(
    payload: AlertmanagerPayload,
    background: BackgroundTasks,
):
    triggered: List[str] = []
    skipped: List[str] = []
    for idx, alert in enumerate(payload.alerts):
        if alert.status != "firing":
            skipped.append(alert.labels.get("alertname", f"unknown_{idx}"))
            continue

        alertname = alert.labels.get("alertname", f"alert_{idx}")
        instance = alert.labels.get("instance", "unknown")
        # session_id \u5e26\u4e0a fingerprint \u4fbf\u4e8e\u53bb\u91cd
        fingerprint = alert.fingerprint or f"{alertname}-{instance}-{alert.startsAt}"
        session_id = f"alertmanager-{alertname}-{fingerprint[:12]}"

        query = _format_alert_as_query(alert)
        alert_meta = {
            "alertname": alertname,
            "severity": alert.labels.get("severity", ""),
            "instance": instance,
            "summary": alert.annotations.get("summary", ""),
            "fingerprint": fingerprint,
            "startsAt": alert.startsAt,
        }
        background.add_task(
            _run_diagnosis_background, query, session_id, alert_meta
        )
        triggered.append(session_id)

    logger.info(
        f"[webhook] \u6536\u5230 {len(payload.alerts)} \u6761 alert, "
        f"\u89e6\u53d1 {len(triggered)} \u6761\u8bca\u65ad, \u8df3\u8fc7 {len(skipped)} \u6761(non-firing)"
    )
    return {
        "status": "accepted",
        "received": len(payload.alerts),
        "triggered": triggered,
        "skipped": skipped,
    }


@router.get(
    "/history",
    summary="\u67e5\u770b webhook \u540e\u53f0\u8dd1\u8fc7\u7684\u8bca\u65ad",
    description="\u8fd4\u56de\u6700\u8fd1 N \u6761\u540e\u53f0\u8bca\u65ad\u8bb0\u5f55, \u6309\u65f6\u95f4\u500d\u5e8f.",
)
async def get_history(limit: int = 20):
    if not HISTORY_FILE.exists():
        return {"count": 0, "items": []}

    records: List[Dict[str, Any]] = []
    with HISTORY_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue

    records = list(reversed(records))[:limit]
    return {"count": len(records), "items": records}


@router.delete(
    "/history",
    summary="\u6e05\u7a7a webhook \u8bca\u65ad\u5386\u53f2 (\u6f14\u793a\u7528)",
)
async def clear_history():
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()
    return {"status": "cleared"}
