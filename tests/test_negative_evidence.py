"""负证据早停 (软预检) 测试: 目标查不到时诚实止损, 不误杀真实故障."""

from app.agents.negative_evidence import (
    NegativeEvidence,
    build_nonexistence_report,
    count_negative_evidence,
    should_stop_for_nonexistence,
)


# ---------- 证据扫描 ----------

def test_strong_markers_counted_per_step():
    steps = [
        ("探测3306", "Connection refused: 无监听"),   # 强 x1
        ("探测域名", "no such host: api.foo.example"),  # 强 x1
        ("查服务", "NXDOMAIN 域名不存在"),              # 强 x1
    ]
    neg = count_negative_evidence(steps)
    assert neg.strong == 3 and neg.weak == 0
    assert should_stop_for_nonexistence(neg) is True


def test_single_step_multiple_markers_counts_once():
    # 同一步同一目标多个强标记只计 1 次 (防单步刷满阈值)
    steps = [("一步", "Connection refused + no such host + NXDOMAIN 全中 (api.foo)")]
    neg = count_negative_evidence(steps)
    # 单目标 → weight 1
    assert neg.strong == 1
    assert should_stop_for_nonexistence(neg) is False


def test_single_step_multi_target_weights():
    # 一步并行探测多个不同目标全失败 (Executor 并行批常见形态) → 目标级折算, 上限 2
    steps = [(
        "并行探测",
        "api.foo.example.com DNS 解析失败 no such host; "
        "db.foo.example.com DNS 解析失败 no such host; "
        "10.1.2.3:3306 connection refused",
    )]
    neg = count_negative_evidence(steps)
    assert neg.strong == 2  # 折算但封顶 2
    assert should_stop_for_nonexistence(neg) is False  # 单步不触发, 需另一步佐证


def test_step_weight_capped():
    # 单步 5 个目标全失败也只计 2; 配合第二步佐证后触发
    hosts = "; ".join(f"h{i}.foo.example no such host" for i in range(5))
    neg = count_negative_evidence([("大批量", hosts)])
    assert neg.strong == 2
    neg2 = count_negative_evidence([("大批量", hosts), ("复核 api.foo", "no such host again api.foo.example")])
    assert neg2.strong == 3
    assert should_stop_for_nonexistence(neg2) is True



def test_strong_plus_weak_threshold():
    steps = [
        ("s1", "连接被拒绝"),
        ("s2", "no such host"),
        ("s3", "404 not found"),
        ("s4", "查询超时 timeout"),
    ]
    neg = count_negative_evidence(steps)
    assert neg.strong == 2 and neg.weak == 2
    assert should_stop_for_nonexistence(neg) is True


def test_below_threshold_no_stop():
    steps = [
        ("s1", "连接被拒绝"),
        ("s2", "CPU 使用率 83%, 内存 60%"),  # 正常结果, 不计
    ]
    neg = count_negative_evidence(steps)
    assert should_stop_for_nonexistence(neg) is False


def test_weak_only_never_stops():
    # 只有弱证据 (超时/404) 不触发 — 可能是网络抖动, 不是不存在
    steps = [("s1", "timeout"), ("s2", "404"), ("s3", "查不到数据"), ("s4", "无数据")]
    neg = count_negative_evidence(steps)
    assert neg.strong == 0 and neg.weak == 4
    assert should_stop_for_nonexistence(neg) is False


def test_normal_positive_run_no_negatives():
    steps = [
        ("s1", "CPU 13.1%, 磁盘 2.1%, 一切正常"),
        ("s2", "MySQL Threads_connected=10 正常"),
    ]
    neg = count_negative_evidence(steps)
    assert neg.strong == 0 and neg.weak == 0


# ---------- 报告生成 ----------

def test_report_is_honest_no_fabricated_root_cause():
    neg = NegativeEvidence()
    neg.strong_steps = [("探测 3306", "connection refused"), ("DNS 查询", "no such host")]
    neg.weak_steps = [("HTTP 探测", "timeout")]
    report = build_nonexistence_report("api.foo.example 超时", neg, "network_diagnosis", "2026-09-08 16:00:00")
    assert "疑似不存在" in report
    assert "connection refused" in report          # 负向证据如实列出
    assert "无需按故障 SOP 处置" in report           # 明确不是目标内部故障
    assert "host:port" in report                    # 引导补地址重试


# ---------- replanner 接线 ----------

async def test_replanner_stops_on_negative_evidence(monkeypatch):
    """3 步强负证据 → replan_node 不调 LLM 直接早停收尾."""
    import asyncio

    from app.agents import replanner as rp

    state = {
        "input": "api.foo.example 订单服务超时",
        "plan": ["继续深挖第 4 步", "继续深挖第 5 步"],
        "past_steps": [
            ("探测 A 记录", "no such host, 域名不存在"),
            ("TCP 443", "Connection refused"),
            ("查注册中心", "服务不存在: api.foo 未注册"),
        ],
        "iteration": 3,
        "selected_skill": "network_diagnosis",
        "tried_skills": [],
        "reroute_count": 0,
    }

    called = {"llm": False}

    async def no_llm(*a, **k):  # noqa: ANN002, ANN003
        called["llm"] = True
        raise AssertionError("负证据早停不应走到 LLM 调用")

    monkeypatch.setattr(rp, "ainvoke_structured", no_llm)
    monkeypatch.setattr(rp, "get_chat_llm", lambda **k: object())

    out = await rp.replan_node(state)
    assert called["llm"] is False
    assert "疑似不存在" in out["response"]
    reasons = [t.get("reason") for t in out["transition_history"]]
    assert any("negative_evidence_stop" in r for r in reasons)


async def test_replanner_normal_path_unaffected(monkeypatch):
    """无负证据时 replan_node 行为不变 (走 LLM 正常决策)."""
    from app.agents import replanner as rp
    from app.agents.state import Act
    from app.core.structured import ainvoke_structured  # noqa: F401  (确认可导入)

    state = {
        "input": "本机 CPU 高",
        "plan": ["查进程", "汇总"],
        "past_steps": [
            ("查进程", "Top 进程: Chrome 30%, 正常采集完成"),
        ],
        "iteration": 1,
        "selected_skill": "host_resource_diagnosis",
        "tried_skills": [],
        "reroute_count": 0,
    }

    async def fake_structured(**kw):  # noqa: ANN003
        return Act(is_finished=True, response="# 报告\nCPU 高由 Chrome 导致")

    monkeypatch.setattr(rp, "ainvoke_structured", fake_structured)
    monkeypatch.setattr(rp, "get_chat_llm", lambda **k: object())
    out = await rp.replan_node(state)
    # 正常路径: LLM 决策生效 (draft 内容进最终报告), 无负证据早停 transition
    assert "Chrome" in (out.get("response") or "")
    reasons = [t.get("reason") for t in out.get("transition_history", [])]
    assert not any("negative_evidence" in (r or "") for r in reasons)
