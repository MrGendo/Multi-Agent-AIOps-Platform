"""app.api.v1.webhook: 告警模型解析 + _format_alert_as_query 渲染测试 (离线)."""

from __future__ import annotations

from app.api.v1.webhook import (
    AlertmanagerAlert,
    AlertmanagerPayload,
    _format_alert_as_query,
)


def _alert(**overrides) -> AlertmanagerAlert:
    base = {
        "status": "firing",
        "labels": {
            "alertname": "HighCPUUsage",
            "severity": "critical",
            "instance": "db-01:9100",
            "service": "mysql",
        },
        "annotations": {
            "summary": "CPU 使用率超过 90%",
            "description": "CPU iowait 持续过高",
            "runbook_url": "https://runbook.example/cpu",
        },
        "startsAt": "2026-08-27T08:00:00Z",
        "fingerprint": "abc123def456",
    }
    base.update(overrides)
    return AlertmanagerAlert(**base)


def test_alert_defaults():
    a = AlertmanagerAlert()
    assert a.status == "firing"
    assert a.labels == {}
    assert a.annotations == {}
    assert a.fingerprint == ""


def test_payload_parses_nested_alerts():
    payload = AlertmanagerPayload(
        version="4",
        status="firing",
        alerts=[_alert().model_dump(), _alert(status="resolved").model_dump()],
    )
    assert payload.version == "4"
    assert len(payload.alerts) == 2
    assert payload.alerts[0].status == "firing"
    assert payload.alerts[1].status == "resolved"
    assert payload.alerts[0].fingerprint == "abc123def456"


def test_format_query_contains_key_fields():
    q = _format_alert_as_query(_alert())
    assert "[CRITICAL] HighCPUUsage" in q
    assert "db-01:9100" in q
    assert "mysql" in q
    assert "CPU 使用率超过 90%" in q
    assert "2026-08-27T08:00:00Z" in q
    assert "https://runbook.example/cpu" in q
    assert "OnCall" in q  # 结尾指令


def test_format_query_omits_optional_fields():
    a = AlertmanagerAlert(
        labels={"alertname": "SimpleAlert"},
    )
    q = _format_alert_as_query(a)
    assert "[WARNING] SimpleAlert" in q  # severity 缺省 warning
    assert "服务:" not in q  # 无 service
    assert "摘要:" not in q
    assert "开始时间:" not in q
    assert "应急手册:" not in q
    assert "实例: (未指定)" in q


def test_format_query_severity_uppercased():
    a = _alert(labels={"alertname": "X", "severity": "warning"})
    assert "[WARNING] X" in _format_alert_as_query(a)


def test_firing_vs_resolved_status():
    assert _alert(status="firing").status == "firing"
    assert _alert(status="resolved").status == "resolved"
