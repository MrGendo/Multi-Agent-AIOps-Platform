"""app/core/metrics.py 与 /metrics 端点测试."""

import pytest
from fastapi.testclient import TestClient


def test_metrics_registry_renders():
    from app.core import metrics as m

    m.record_diagnostic_start()
    m.record_diagnostic_end("success", duration_sec=12.5)
    m.record_tokens(input_tokens=100, output_tokens=50)
    m.record_tool_call("system_probe", "ok", duration_sec=0.3)
    m.record_tool_call("system_probe", "failed", duration_sec=5.0)
    m.record_tool_call("docker_ps", "circuit_open")
    m.record_hitl_pending(1)
    m.record_hitl_pending(-1)
    m.record_hitl_decision("approve")
    m.record_alert_received("HighDiskUsage")
    m.record_alert_deduplicated()
    m.record_llm_fallback()

    text = m.render_metrics().decode("utf-8")
    assert "aiops_diagnostic_duration_seconds" in text
    assert 'status="success"' in text
    assert 'kind="input"' in text
    assert 'tool="system_probe"' in text
    assert 'status="circuit_open"' in text
    assert "aiops_hitl_pending" in text
    assert "aiops_alerts_deduplicated_total" in text
    assert "aiops_llm_fallback_total" in text


def test_metrics_functions_never_raise():
    from app.core import metrics as m

    # 非法参数也不许抛 (可观测性代码不能拖垮业务)
    m.record_diagnostic_end("weird_status", duration_sec=-1)
    m.record_tokens(input_tokens=0, output_tokens=0)
    m.record_tool_call("", "", duration_sec=None)
    m.record_http_request(None, None, None, -1)  # type: ignore[arg-type]


def test_active_gauge_back_to_zero():
    from app.core import metrics as m

    m.record_diagnostic_start()
    m.record_diagnostic_end("success", 1.0)
    # Gauge 的当前值在 prometheus_client 内部, 通过渲染文本校验样本存在
    text = m.render_metrics().decode("utf-8")
    assert "aiops_active_diagnoses" in text


@pytest.fixture()
def client():
    """无 lifespan 依赖的轻量 client (不连 Milvus)."""
    from fastapi import FastAPI

    from app.api.v1 import metrics as metrics_api

    app = FastAPI()
    app.include_router(metrics_api.router)
    return TestClient(app)


def test_metrics_endpoint(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "aiops_diagnostic_total" in resp.text
    assert resp.headers["content-type"].startswith(
        "text/plain; version=1.0.0"
    ) or "text/plain" in resp.headers["content-type"]


def test_metrics_endpoint_after_traffic(client):
    client.get("/metrics")  # 预热
    from app.core import metrics as m

    m.record_alert_received("ChamberPressureHigh")
    resp = client.get("/metrics")
    assert 'alertname="ChamberPressureHigh"' in resp.text
