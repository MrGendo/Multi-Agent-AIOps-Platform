"""雷池 SafeLine + CEF 适配器离线单测 (格式源自官方仓库 Go 结构体/CEF 规范)."""

from __future__ import annotations

from app.security.cef_adapter import adapt_cef_text, is_cef_text, parse_cef
from app.security.device_adapters import detect_and_normalize
from app.security.safeline_adapter import adapt_safeline_event, adapt_safeline_payload


# ============================================================
# SafeLine 雷池
# ============================================================
class TestSafeLine:
    def test_bare_event(self):
        # 字段组合取自 chaitin/SafeLine mcp_server internal/api/analyze Event struct
        ev = {
            "id": 1024, "ip": "45.33.32.156", "protocol": 6,
            "host": "shop.example.com", "dst_port": 443,
            "start_at": 1789700000, "end_at": 1789700600,
            "deny_count": 233, "pass_count": 3,
            "finished": False, "country": "美国", "province": "", "city": "洛杉矶",
        }
        p = adapt_safeline_event(ev)
        assert p.source == "safeline"
        assert p.src_ip == "45.33.32.156"
        assert p.severity == "HIGH"  # deny 233 >> pass 3
        assert "shop.example.com" in p.rule
        assert "拦截 233" in p.description
        assert "洛杉矶" in p.description

    def test_all_pass_low(self):
        p = adapt_safeline_event({"id": 1, "ip": "1.1.1.1", "host": "h", "deny_count": 0, "pass_count": 50})
        assert p.severity == "LOW"

    def test_api_response_wrapper(self):
        body = {"code": 200, "message": "ok", "data": {"nodes": [
            {"id": 7, "ip": "2.2.2.2", "host": "w", "deny_count": 12, "pass_count": 1}
        ], "total": 1}}
        p = adapt_safeline_payload(body)
        assert p is not None and p.src_ip == "2.2.2.2"

    def test_not_safeline(self):
        assert adapt_safeline_payload({"foo": "bar"}) is None
        # 通用 schema 形态不误判 (无 deny_count/pass_count 指纹)
        assert adapt_safeline_payload({"source": "x", "severity": "HIGH", "rule": "r"}) is None

    def test_via_webhook_detect(self):
        # webhook 入口: 裸雷池事件应被识别 (不再落到通用 schema)
        ev = {"ip": "3.3.3.3", "host": "a.b", "dst_port": 80, "deny_count": 5, "pass_count": 0}
        p = detect_and_normalize(ev)
        assert p is not None and p.source == "safeline"


# ============================================================
# CEF
# ============================================================
class TestCEF:
    def test_standard_line(self):
        line = (
            "CEF:0|Security|threat|1.0|100|Suspicious SQL Injection|8|"
            "src=45.33.32.156 dst=10.0.0.8 request=/search?q=1%%27+UNION+SELECT outcome=blocked"
        )
        p = adapt_cef_text(line)
        assert p is not None
        assert p.src_ip == "45.33.32.156"
        assert p.dst_ip == "10.0.0.8"
        assert p.severity == "HIGH"  # CEF 8
        assert "SQL Injection" in p.rule
        assert p.source == "cef:Security:threat"

    def test_syslog_prefix_stripped(self):
        line = (
            "<134>Sep 18 11:00:01 fw01 corp: "
            "CEF:0|Vendor|NDR|2.1|301|Port scan detected|5|src=198.51.100.7 dst=10.1.1.1"
        )
        p = adapt_cef_text(line)
        assert p is not None and p.src_ip == "198.51.100.7"
        assert p.severity == "MEDIUM"  # CEF 5

    def test_severity_mapping(self):
        assert adapt_cef_text("CEF:0|a|b|c|1|n|10|x=y").severity == "CRITICAL"
        assert adapt_cef_text("CEF:0|a|b|c|1|n|9|x=y").severity == "CRITICAL"
        assert adapt_cef_text("CEF:0|a|b|c|1|n|7|x=y").severity == "HIGH"
        assert adapt_cef_text("CEF:0|a|b|c|1|n|4|x=y").severity == "MEDIUM"
        assert adapt_cef_text("CEF:0|a|b|c|1|n|2|x=y").severity == "LOW"

    def test_escaped_values(self):
        line = r"CEF:0|V|EDR|1|42|Malware detected|9|src=1.2.3.4 file=C:\Users\Public\x.exe hash=abc"
        p = adapt_cef_text(line)
        assert p is not None
        assert p.src_ip == "1.2.3.4"
        assert "Malware" in p.rule

    def test_non_cef_returns_none(self):
        assert adapt_cef_text("plain text alert") is None
        assert adapt_cef_text("") is None

    def test_via_webhook_text_wrapper(self):
        # syslog 转发器把 CEF 行塞进 text 字段
        body = {"text": "<134>fw: CEF:0|NDR|sensor|3.0|77|Data exfil|8|src=9.9.9.9 dst=8.8.4.4"}
        p = detect_and_normalize(body)
        assert p is not None
        assert p.src_ip == "9.9.9.9"
        assert p.severity == "HIGH"

    def test_parse_cef_structure(self):
        d = parse_cef("CEF:0|V|P|1.0|5|Name|3|k1=v1 k2=v2")
        assert d is not None
        assert d["vendor"] == "V" and d["name"] == "Name"
        assert d["extension"] == {"k1": "v1", "k2": "v2"}
