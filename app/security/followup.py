"""取证引导生成器 — 无法判定时告诉分析师去哪台设备做什么.

借鉴 OpenTriage playbook 的「下一步取证步骤」理念, 落成结构化
FollowUpGuidance: 当 verdict=inconclusive 或置信度不足时, 按
alert_type + 已有 IOC 给出「设备 → 操作 → 能拿到什么证据」清单,
直接渲染进研判报告与对话上下文.
"""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class GuidanceStep(BaseModel):
    """单条取证建议: 在什么设备上做什么操作能拿到什么."""

    device: str = Field(..., description="目标设备/系统, 如 WAF / 堡垒机 / 域控")
    action: str = Field(..., description="具体操作, 含查询语句或路径")
    evidence: str = Field(..., description="该操作能拿到的关键证据")
    priority: str = Field(default="high", description="high / medium / low")


class FollowUpGuidance(BaseModel):
    """无法判定时的取证引导集."""

    reason: str = Field(..., description="为什么当前证据不足")
    steps: List[GuidanceStep] = Field(default_factory=list)
    hint: str = Field(default="", description="拿到证据后怎么办 (贴回对话继续研判)")


# alert_type → 取证步骤模板 (device/action/evidence)
_TEMPLATES: Dict[str, List[Dict[str, str]]] = {
    "brute_force": [
        {
            "device": "目标主机 (SSH: /var/log/auth.log 或 secure; Windows: 事件查看器 4625/4624)",
            "action": "grep 'Failed password' auth.log | grep '<SRC_IP>' | tail -50; 并检查同窗口是否有 'Accepted password' (成功登录!)",
            "evidence": "失败次数精确值、被尝试的账户名、**是否存在成功登录** (决定是否已失陷)",
        },
        {
            "device": "WAF / 边界防火墙",
            "action": "查询 <SRC_IP> 近 24h 全部会话记录 (不只 SSH, 看是否还碰了 WEB/RDP/SMB 端口)",
            "evidence": "攻击者是否多协议横跨扫描, 攻击面广度",
        },
        {
            "device": "威胁情报平台 (VirusTotal / 微步 / OTX)",
            "action": "查询 <SRC_IP> 信誉: 是否已知爆破源/代理/僵尸网络节点",
            "evidence": "IP 归属与恶意标签, 提升或排除外部情报置信度",
        },
    ],
    "web_attack": [
        {
            "device": "WAF / Nginx / Apache 访问日志",
            "action": "提取 <SRC_IP> 的原始 HTTP 请求 (URI/UA/Body), 确认 payload 是否真实到达应用层",
            "evidence": "攻击 payload 全文、是否被 WAF 拦截、响应码 (200=可能成功利用)",
        },
        {
            "device": "目标应用服务器",
            "action": "检查应用错误日志与数据库审计日志同窗口的慢查询/异常 SQL",
            "evidence": "注入是否真实执行、数据是否被读取",
        },
        {
            "device": "CDN / 负载均衡",
            "action": "查 <SRC_IP> 会话的 Referer 与 Cookie, 判断是扫描器还是定向攻击",
            "evidence": "攻击定向性 (随机扫描 vs 盯住特定接口)",
        },
    ],
    "malware": [
        {
            "device": "终端 EDR / 主机",
            "action": "查询 <HASH> 的进程树、网络外连、持久化项 (计划任务/注册表/启动项)",
            "evidence": "样本是否真实执行、外连 C2 地址、持久化方式",
        },
        {
            "device": "威胁情报平台",
            "action": "查询 <HASH> 与外连域名/IOC 的家族归属",
            "evidence": "恶意家族判定与已知 TTP",
        },
        {
            "device": "网络设备 (流量镜像/全流量审计)",
            "action": "提取该主机近 24h 对外流量 Top 目的地址与端口",
            "evidence": "C2 心跳特征、数据外传量",
        },
    ],
    "phishing": [
        {
            "device": "邮件网关 / 邮件服务器",
            "action": "检索发件人 <DOMAIN> 的全部往来邮件, 确认收件人范围与附件/链接",
            "evidence": "钓鱼范围、是否有内网用户点击",
        },
        {
            "device": "代理服务器 / 上网行为管理",
            "action": "查询内网用户对 <DOMAIN>/<URL> 的访问记录",
            "evidence": "谁点击了钓鱼链接、点击时间",
        },
        {
            "device": "终端 EDR",
            "action": "检查点击用户主机的浏览器下载记录与新进程",
            "evidence": "是否落地恶意载荷",
        },
    ],
    "privilege_escalation": [
        {
            "device": "目标主机",
            "action": "审计 sudo 日志 / Windows 4672 (特殊登录) 事件; 检查 <CVE> 对应组件版本",
            "evidence": "提权是否成功、当前账户权限实际等级",
        },
        {
            "device": "堡垒机 / 审计系统",
            "action": "回放该会话的操作录像, 确认 chmod/su 等命令上下文",
            "evidence": "是管理员误操作还是攻击者在提权",
        },
    ],
    "data_exfiltration": [
        {
            "device": "流量审计 / DLP",
            "action": "提取该主机对外传输的流量明细 (目的/端口/量/时间分布), 判别是否压缩加密特征",
            "evidence": "外传数据量与目的地, 是否匹配已知 C2 通道",
        },
        {
            "device": "文件服务器 / DLP",
            "action": "检查敏感目录访问日志与大文件读取记录",
            "evidence": "被读取的数据范围 (决定泄露影响面)",
        },
    ],
    "network_scan": [
        {
            "device": "IDS / 流量",
            "action": "提取 <SRC_IP> 扫描的端口与目标清单, 判断是全段扫描还是定向探测",
            "evidence": "侦察范围与后续可能的攻击目标",
        },
        {
            "device": "CMDB / 资产系统",
            "action": "核对被扫目标上部署的业务与暴露面",
            "evidence": "哪些资产值得优先加固",
        },
    ],
    "anomaly": [
        {
            "device": "相关主机 / 应用日志",
            "action": "按告警时间窗提取该资产的认证/进程/网络日志",
            "evidence": "异常行为的完整上下文",
        },
        {
            "device": "SIEM (如有)",
            "action": "以 <SRC_IP> 和目标资产为轴做关联检索 (同 IP 其他告警)",
            "evidence": "散点告警是否能拼成攻击链",
        },
    ],
}


def build_followup_guidance(
    alert_type: str,
    iocs: Dict[str, List[str]] | None,
    reason: str = "",
    confidence: float = 0.0,
) -> FollowUpGuidance | None:
    """按告警类型生成取证引导; IOC 占位符 (<SRC_IP>/<HASH>/<DOMAIN>) 自动填充."""
    steps_raw = _TEMPLATES.get((alert_type or "").strip().lower())
    if not steps_raw:
        steps_raw = _TEMPLATES["anomaly"]

    iocs = iocs or {}
    ips = iocs.get("ips") or []
    hashes = iocs.get("hashes") or []
    domains = iocs.get("domains") or []
    urls = iocs.get("urls") or []
    cves = iocs.get("cves") or []

    replace_map = {
        "<SRC_IP>": (ips[0] if ips else "源IP"),
        "<HASH>": (hashes[0] if hashes else "样本哈希"),
        "<DOMAIN>": (domains[0] if domains else "可疑域名"),
        "<URL>": (urls[0] if urls else "可疑URL"),
        "<CVE>": (cves[0] if cves else "相关CVE"),
    }

    steps = []
    for i, s in enumerate(steps_raw):
        action = s["action"]
        for k, v in replace_map.items():
            action = action.replace(k, v)
        steps.append(
            GuidanceStep(
                device=s["device"],
                action=action,
                evidence=s["evidence"],
                priority="high" if i == 0 else ("medium" if i == 1 else "low"),
            )
        )

    why = reason or "当前证据不足以支撑确定性判定"
    return FollowUpGuidance(
        reason=f"{why} (当前置信度 {confidence:.0%})",
        steps=steps,
        hint=(
            "取证后在下方对话框粘贴结果 (如 auth.log 片段 / WAF 记录 / 情报查询截图文本), "
            "系统会基于新证据继续研判并更新结论; 对话结束后结论将沉淀为研判经验, "
            "同类告警下次自动参考。"
        ),
    )


def render_guidance_markdown(guidance: FollowUpGuidance | None) -> str:
    """把取证引导渲染成报告可用的 Markdown 段落."""
    if not guidance:
        return ""
    lines = ["## 下一步取证建议 (当前无法确定判定)", "", f"**原因**: {guidance.reason}", ""]
    for i, s in enumerate(guidance.steps, 1):
        prio = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(s.priority, "⚪")
        lines += [
            f"### {i}. {prio} 在 {s.device}",
            f"- **操作**: {s.action}",
            f"- **能拿到**: {s.evidence}",
            "",
        ]
    lines += [f"> 💡 {guidance.hint}", ""]
    return "\n".join(lines)


def needs_guidance(verdict: str, confidence: float, threshold: float = 0.6) -> bool:
    """判定是否需要取证引导: 无法判定或低置信度."""
    if verdict in ("inconclusive", ""):
        return True
    return confidence < threshold
