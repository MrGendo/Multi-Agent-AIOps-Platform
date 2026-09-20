"""跨域反向提示 (AIOps → SecOps) 离线单测."""

from __future__ import annotations

from app.agents.security_signals import scan_security_signals


def test_mining_signal_hit():
    r = scan_security_signals("根因: 主机被植入挖矿程序 kdevtmpfsi, CPU 打满")
    assert r is not None
    assert any("挖矿" in m for m in r["matched"])
    assert "安全研判" in r["hint"]


def test_webshell_and_reverse_shell():
    r = scan_security_signals("webshell 上传 + reverse shell 反弹确认")
    assert r is not None
    assert len(r["matched"]) >= 2


def test_case_insensitive():
    assert scan_security_signals("detected REVERSE SHELL to 1.2.3.4") is not None
    assert scan_security_signals("C2 beacon") is not None


def test_clean_report_no_hint():
    assert scan_security_signals("根因: Redis 内存配置不足导致 OOM, 建议调大 maxmemory") is None
    assert scan_security_signals("") is None
    assert scan_security_signals("数据库连接池耗尽, 属容量问题") is None


def test_payload_shape():
    r = scan_security_signals("疑似后门程序 /tmp/.bd")
    assert r is not None
    assert set(r.keys()) == {"matched", "hint"}
    assert isinstance(r["matched"], list)
