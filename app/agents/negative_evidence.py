"""负证据早停 (软预检): 目标查不到时诚实止损, 不再无限挖掘.

与 precheck (硬门) 的分工:
  - precheck (硬门, 图最前端): 只拦「本机可硬证伪」的目标 (TCP RST x2), 0 token 短路。
  - negative_evidence (软门, Replanner 内): 远端/无地址目标过了硬门后, 专家在执行中
    踩到连续的「连接被拒/域名不存在/查无此物」时, 提前收尾并如实报告
    「关键探测一致失败, 目标疑似不存在/不可达」, 而不是烧完剩余预算绕着找解释。

判定刻意保守 (防误杀真实故障):
  - 强证据: connection refused / 连接被拒绝 / 无监听 / no such host / NXDOMAIN /
    域名无法解析 —— 直接指向「目标不存在」
  - 弱证据: not found / 404 / 无数据 / 查不到 / 超时 —— 也可能是权限、网络、配置问题
  - 触发阈值: ≥3 个不同步骤踩强证据, 或 ≥2 步强 + ≥2 步弱; 其余情况照常 Replan
"""

from __future__ import annotations

import re
from typing import List, Tuple

# 直接指向「目标不存在」的硬信号 (不区分大小写匹配)
_STRONG_MARKERS = (
    "connection refused",
    "连接被拒绝",
    "无监听",
    "no listener",
    "no such host",
    "name or service not known",
    "nxdomain",
    "域名不存在",
    "无法解析该域名",
    "服务不存在",
    "未知的主机",
)

# 模糊信号: 可能是不存在, 也可能是权限/网络/配置
_WEAK_MARKERS = (
    "not found",
    "404",
    "无数据",
    "查不到",
    "未找到",
    "timeout",
    "超时",
    "无法连接",
    "connection failed",
)


class NegativeEvidence:
    """跨步骤汇总的负证据统计 (按不同步骤计数, 单步多标记不重复计)."""

    def __init__(self) -> None:
        self.strong_steps: List[Tuple[str, str]] = []   # (步骤名, 命中标记)
        self.weak_steps: List[Tuple[str, str]] = []

    @property
    def strong(self) -> int:
        return len(self.strong_steps)

    @property
    def weak(self) -> int:
        return len(self.weak_steps)

    def samples(self) -> List[str]:
        out = []
        for step, marker in (self.strong_steps + self.weak_steps)[:8]:
            out.append(f"- `{step[:60]}` → 命中「{marker}」")
        return out


def count_negative_evidence(past_steps: List[Tuple[str, str]]) -> NegativeEvidence:
    """扫描已执行步骤的结果文本, 按步骤聚合负证据.

    计数粒度: 单步只计 1 次 (防单步刷满阈值)。但 Executor 一步常并行探测多个
    目标 (dns_lookup + check_port + http_check 同步返回), 结果里同一标记命中
    多个不同 host 时, 说明是「目标级」缺失而非单工具抖动 —— 按目标数补计,
    每步上限 2 (阈值 3, 单步不足以触发, 必须有另一步佐证 — 防并行批一步全黑直接误停)。
    """
    neg = NegativeEvidence()
    for step, result in past_steps or []:
        text = (result or "").lower()
        if not text:
            continue
        for marker in _STRONG_MARKERS:
            if marker in text:
                # 目标级折算: 该标记伴随的不同 IPv4/域名/主机:端口 出现次数
                targets = set(re.findall(r"[a-z0-9][a-z0-9.\-]*(?:\.[a-z]{2,}|\.\d+)(?::\d+)?", text))
                # 排除标记词本身被误算 (如 refused 不是主机名)
                targets = {t for t in targets if len(t) > 3 and marker not in t}
                weight = min(2, max(1, len(targets)))
                for _ in range(weight):
                    neg.strong_steps.append((step or "(未命名步骤)", marker))
                break
        else:
            for marker in _WEAK_MARKERS:
                if marker in text:
                    neg.weak_steps.append((step or "(未命名步骤)", marker))
                    break  # 单步只计一次弱
    return neg


def should_stop_for_nonexistence(neg: NegativeEvidence) -> bool:
    """触发阈值 (保守): ≥3 步强, 或 ≥2 步强 + ≥2 步弱."""
    return neg.strong >= 3 or (neg.strong >= 2 and neg.weak >= 2)


def build_nonexistence_report(
    user_input: str,
    neg: NegativeEvidence,
    skill: str,
    current_time: str,
) -> str:
    """诚实止损报告: 说清测了什么、全部失败、目标疑似不存在, 不编造根因."""
    lines = [
        "# 故障诊断报告（提前止损：目标疑似不存在）",
        "",
        f"**生成时间**: {current_time}",
        f"**执行专家**: {skill or 'generic_oncall'}",
        "",
        "## 一、问题概述",
        f"- 现象: {user_input.strip()[:200]}",
        "- 诊断结论: **多个关键探测一致失败，诊断目标疑似不存在或不可达**，已提前止损。",
        "",
        "## 二、关键证据（全部为负向结果）",
        "",
        *neg.samples(),
        "",
        "## 三、分析",
        "上述探测覆盖了该故障域的核心验证路径（连接/解析/存在性），结果一致指向目标本身缺失，",
        "而非目标内部的故障。此时继续深挖只会消耗预算并产生臆测性结论，故停止。",
        "",
        "## 四、建议（按顺序确认）",
        "1. **确认目标地址是否正确**：告警中的 host/port/服务名是否拼写正确、是否是预期的那套环境。",
        "2. **确认服务是否真的部署**：目标实例可能从未部署 / 已下线 / 正在迁移。",
        "3. **补充信息后重新发起**：提供正确的 `host:port` 或服务名，我将重新完整诊断。",
        "",
        "## 五、结论",
        "目标不存在/不可达的可能性极高；这不是一次目标内部的故障，无需按故障 SOP 处置。",
    ]
    return "\n".join(lines)
