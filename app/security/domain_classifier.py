"""统一事件入口的域分类器: security (安全研判) vs ops (运维诊断).

路由策略 (与 app/agents/skill_router.py 同构, 方向相反 — 那里是 LLM 主路 +
规则兜底, 这里是规则快路径 + LLM 慢路径):
  1. 纯关键词规则快路径: 免费、零延迟, 明确命中直接定域
  2. LLM 慢路径: 规则无法判定 (两类词都未命中) 时走 router 模型结构化分类
  3. LLM 失败兜底: fail-open 到 ops 域 — 运维域是存量主路径, 混入安全告警
     也不会丢 (ops 图仍可诊断), 反之安全域误吞运维工单会烧调查 token

安全词优先级纪律: 两类关键词命中数打平时归 security — 宁严勿漏.
"""

from __future__ import annotations

from loguru import logger

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness
from app.security.state import DomainChoice, SecOpsState

# ============================================================
# 模块级关键词表 (小写; 匹配前文本统一 lower)
# ============================================================
_SECURITY_KEYWORDS: tuple[str, ...] = (
    # 攻击通用
    "攻击", "attack", "入侵", "intrusion", "失陷", "妥协", "compromise",
    "黑客", "hacker", "恶意", "恶意软件", "malware", "木马", "trojan",
    "后门", "backdoor", "远控", "webshell",
    # 暴力破解 / 凭据
    "暴力破解", "brute force", "brute_force", "暴力尝试", "暴力", "弱口令",
    "撞库", "拖库", "credential stuffing",
    # 勒索 / 挖矿 / 僵尸网络
    "勒索", "ransomware", "挖矿", "mining", "僵尸网络", "botnet", "c2",
    "肉鸡",
    # 数据窃取
    "数据泄露", "数据泄漏", "exfiltration", "窃取", "拖走",
    # 钓鱼
    "钓鱼", "phishing", "鱼叉",
    # 注入 / Web 攻击
    "注入", "injection", "sqli", "sql注入", "xss", "webattack", "web attack",
    "命令执行", "command execution", "rce", "ssrf", "csrf",
    # 扫描 / 探测
    "扫描", "scanning", "端口扫描", "port scan", "探测",
    # 漏洞利用
    "cve", "漏洞利用", "exploit", "0day", "零日",
    # 提权 / 横向移动
    "提权", "横向移动", "lateral movement", "privilege escalation", "escalation",
    # 账号异常
    "异常登录", "异地登录", "非工作时间登录",
    # 流量攻击
    "ddos", "cc攻击", "洪水攻击", "flood",
)

_OPS_KEYWORDS: tuple[str, ...] = (
    # 稳定性
    "宕机", "不可用", "超时", "timeout", "重启", "崩溃", "crash", "hang",
    # 资源水位
    "cpu", "内存", "磁盘", "inode", "水位", "oom", "out of memory",
    "泄漏", "leak", "load", "负载", "饱和", "扩容",
    # 性能
    "latency", "延迟", "慢查询", "slow query", "卡顿", "gc", "jvm",
    "fullgc", "5xx", "4xx", "错误率", "error rate",
    # 中间件 / 连接
    "连接池", "数据库连接", "redis", "mysql", "kafka", "队列积压", "积压",
    # 变更
    "发布", "回滚", "rollout", "rollback", "变更", "灰度", "限流", "降级",
    # 容器
    "pod", "k8s", "kubernetes", "容器", "deployment",
)

_VALID_DOMAINS = ("security", "ops")


# ============================================================
# 规则快路径
# ============================================================
def _hit_keywords(normalized: str, keywords: tuple[str, ...]) -> list[str]:
    """返回在文本中命中的关键词列表 (去重, 每个词最多记一次)."""
    return [kw for kw in keywords if kw in normalized]


def classify_domain_rule(text: str) -> tuple[str, str]:
    """纯规则域分类 (快路径, 不调 LLM).

    Returns:
        (domain, reason):
          - ("security", reason): 安全词命中数 >= 运维词命中数 (平局归安全, 宁严勿漏)
          - ("ops", reason):      运维词命中数严格更多
          - ("", "no keyword hit"): 两类词均未命中, 需 LLM 判定
    """
    normalized = (text or "").lower()
    sec_hits = _hit_keywords(normalized, _SECURITY_KEYWORDS)
    ops_hits = _hit_keywords(normalized, _OPS_KEYWORDS)

    if not sec_hits and not ops_hits:
        return "", "no keyword hit"

    if len(sec_hits) >= len(ops_hits):
        if len(sec_hits) == len(ops_hits):
            reason = (
                f"安全/运维关键词命中数持平 ({len(sec_hits)}:{len(ops_hits)}), "
                f"宁严勿漏归安全域; 安全命中: {', '.join(sec_hits[:5])}"
            )
        else:
            reason = (
                f"安全关键词命中 {len(sec_hits)} 个 (如 {', '.join(sec_hits[:5])}), "
                f"多于运维命中 {len(ops_hits)} 个"
            )
        return "security", reason

    reason = (
        f"运维关键词命中 {len(ops_hits)} 个 (如 {', '.join(ops_hits[:5])}), "
        f"多于安全命中 {len(sec_hits)} 个"
    )
    return "ops", reason


# ============================================================
# LLM 慢路径
# ============================================================
def _build_domain_messages(text: str) -> list[dict[str, str]]:
    system = (
        "你是 AIOps 平台统一事件入口的域分类器, 判断事件文本属于哪个业务域, 只输出 json.\n"
        "- security: 安全攻击类事件 (暴力破解/恶意软件/入侵/数据泄露/Web攻击/"
        "异常登录/挖矿/C2/钓鱼/勒索 等)\n"
        "- ops: 运维故障类事件 (宕机/超时/资源水位/发布变更/数据库/中间件/"
        "网络不通/性能退化 等)\n"
        "拿不准时优先 ops (运维域是存量主路径, 误分不丢事件)."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": f"事件文本:\n{text.strip() or '(空)'}"},
    ]


def _normalize_domain(raw: str) -> str:
    """LLM 返回的 domain 归一到白名单 (security/ops), 非法值 fail-open 到 ops."""
    domain = (raw or "").strip().lower()
    if domain in _VALID_DOMAINS:
        return domain
    if "security" in domain or "安全" in domain:
        return "security"
    if "ops" in domain or "运维" in domain:
        return "ops"
    return "ops"


async def classify_domain(text: str) -> dict:
    """域分类统一入口: 规则快路径优先, 未命中走 LLM, LLM 失败 fail-open 到 ops.

    Returns:
        {"domain": "security"|"ops", "confidence": float, "reason": str}
    """
    domain, reason = classify_domain_rule(text)
    if domain:
        logger.info(f"[DomainClassifier] 规则快路径命中: domain={domain} | {reason[:120]}")
        return {"domain": domain, "confidence": 0.9, "reason": reason}

    # 慢路径: router 模型结构化分类
    try:
        harness = get_agent_harness()
        router_model = harness.router_model()
        llm = get_chat_llm(model=router_model, temperature=0, timeout=30, max_retries=1)
        choice: DomainChoice = await ainvoke_structured(
            llm=llm,
            schema_cls=DomainChoice,
            messages=_build_domain_messages(text),
            model_name=router_model,
        )
        domain = _normalize_domain(choice.domain)
        confidence = choice.confidence if isinstance(choice.confidence, (int, float)) else 0.5
        llm_reason = choice.reason or f"LLM 判定 ({router_model})"
        logger.info(
            f"[DomainClassifier] LLM 判定: domain={domain} confidence={confidence} | {llm_reason[:120]}"
        )
        return {"domain": domain, "confidence": float(confidence), "reason": llm_reason}
    except Exception as e:
        # fail-open 到运维域: 运维是存量主路径, 兜底不丢事件
        logger.exception(f"[DomainClassifier] LLM 域分类失败, fail-open 到 ops 域: {e}")
        return {"domain": "ops", "confidence": 0.3, "reason": "LLM 失败规则兑底默认运维域"}


# ============================================================
# LangGraph 节点
# ============================================================
async def domain_classifier_node(state: SecOpsState) -> dict:
    """统一入口节点: 写入 domain / domain_confidence / domain_reason.

    幂等: state 已带非空 domain 时直接透传, 不重复分类 (支持子图重入).
    """
    existing = state.get("domain") or ""
    if existing.strip():
        return {
            "domain": existing,
            "domain_confidence": state.get("domain_confidence", 0.9),
            "domain_reason": state.get("domain_reason", "已有域分类, 幂等透传"),
        }

    text = state.get("input", "")
    result = await classify_domain(text)
    return {
        "domain": result["domain"],
        "domain_confidence": result["confidence"],
        "domain_reason": result["reason"],
    }
