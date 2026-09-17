"""SecOps 研判多轮对话服务.

围绕一条告警的研判工作台:
  - 研判产出报告后, 分析师可继续对话补充取证结果 (贴 auth.log/WAF 记录等)
  - 每轮对话携带完整研判上下文 + 历史对话, 基于新证据更新判定
  - verdict 变更走安全审计纪律 (结论必须引用证据)
  - 会话持久化 data/secops_sessions/*.json; 结束时若有新证据贡献,
    连同最终判定一起提炼为研判经验入库 (multi-evidence pattern)

设计边界:
  - 对话只更新「判定与建议」, 永不触发处置动作 (安全铁律不变)
  - LLM 失败 fail-soft: 该轮回复降级为提示, 不破坏会话
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger
from pydantic import BaseModel, Field

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness

SESSIONS_DIR = Path(__file__).resolve().parents[2] / "data" / "secops_sessions"

VERDICTS = ("benign", "suspicious", "malicious", "inconclusive")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# 常见非法 verdict 别名 → 四态归一 (LLM 偶发自造词的防线)
_VERDICT_ALIASES = {
    "true_positive": "malicious",
    "confirmed": "malicious",
    "attack": "malicious",
    "真阳性": "malicious",
    "攻击确认": "malicious",
    "确认攻击": "malicious",
    "恶意": "malicious",
    "false_positive": "benign",
    "误报": "benign",
    "良性": "benign",
    "可疑": "suspicious",
    "证据不足": "inconclusive",
    "无法判定": "inconclusive",
}


def normalize_verdict(raw: str, fallback: str = "inconclusive") -> str:
    """归一 LLM 输出的 verdict 到四态; 无法识别时返回 fallback."""
    v = (raw or "").strip().lower()
    if v in VERDICTS:
        return v
    return _VERDICT_ALIASES.get(v, fallback)


class DialogueTurn(BaseModel):
    role: str = Field(..., description="user / assistant")
    content: str = Field(...)
    ts: float = Field(default_factory=time.time)


class VerdictUpdate(BaseModel):
    """对话轮产出的判定更新 (LLM 结构化输出)."""

    reply: str = Field(..., description="给分析师的回复: 分析了新证据什么、改变了什么判断")
    verdict: str = Field(..., description="更新后的四态判定 (不变则原样)")
    severity: str = Field(default="", description="更新后的严重度 (不变则原样)")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_used: List[str] = Field(default_factory=list, description="本轮引用的关键证据 (必须真实来自对话)")
    needs_more_evidence: bool = Field(default=False, description="是否仍需补充取证")
    next_steps: List[str] = Field(default_factory=list, description="下一步取证建议 (如仍不充分)")


def _ensure_dir() -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


class TriageSession:
    """单条告警的研判会话 (内存态 + 磁盘持久化)."""

    def __init__(
        self,
        session_id: str,
        alert_text: str,
        report: str = "",
        verdict: str = "",
        severity: str = "",
        response_mode: str = "",
        iocs: Optional[Dict[str, List[str]]] = None,
        alert_type: str = "",
    ):
        self.session_id = session_id
        self.alert_text = alert_text
        self.report = report
        self.verdict = verdict
        self.severity = severity
        self.response_mode = response_mode
        self.iocs = iocs or {}
        self.alert_type = alert_type
        self.turns: List[DialogueTurn] = []
        self.evidence_contribs: List[str] = []  # 用户补充的取证材料汇总
        self.verdict_updates: List[Dict[str, Any]] = []
        self.created_at = time.time()
        self.updated_at = time.time()

    # ---------- 持久化 ----------
    def save(self) -> None:
        _ensure_dir()
        path = SESSIONS_DIR / f"{self.session_id}.json"
        path.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "alert_text": self.alert_text,
            "alert_type": self.alert_type,
            "report": self.report,
            "verdict": self.verdict,
            "severity": self.severity,
            "response_mode": self.response_mode,
            "iocs": self.iocs,
            "turns": [t.model_dump() for t in self.turns],
            "evidence_contribs": self.evidence_contribs,
            "verdict_updates": self.verdict_updates,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TriageSession":
        s = cls(
            session_id=d["session_id"],
            alert_text=d.get("alert_text", ""),
            report=d.get("report", ""),
            verdict=d.get("verdict", ""),
            severity=d.get("severity", ""),
            response_mode=d.get("response_mode", ""),
            iocs=d.get("iocs") or {},
            alert_type=d.get("alert_type", ""),
        )
        s.turns = [DialogueTurn(**t) for t in d.get("turns", [])]
        s.evidence_contribs = d.get("evidence_contribs", [])
        s.verdict_updates = d.get("verdict_updates", [])
        s.created_at = d.get("created_at", time.time())
        s.updated_at = d.get("updated_at", time.time())
        return s


# ---------- 会话注册表 (进程内) ----------
_sessions: Dict[str, TriageSession] = {}


def create_session(alert_text: str, report: str, verdict: str, severity: str,
                   response_mode: str, iocs: Dict[str, List[str]], alert_type: str,
                   base_session_id: str = "") -> TriageSession:
    """研判完成后创建对话会话 (幂等: 同 base 已存在则返回)."""
    sid = f"dlg-{base_session_id}" if base_session_id else f"dlg-{uuid.uuid4().hex[:12]}"
    if sid in _sessions:
        return _sessions[sid]
    path = SESSIONS_DIR / f"{sid}.json"
    if path.exists():
        try:
            s = TriageSession.from_dict(json.loads(path.read_text(encoding="utf-8")))
            _sessions[sid] = s
            return s
        except Exception:
            pass
    s = TriageSession(sid, alert_text, report, verdict, severity, response_mode,
                      iocs, alert_type)
    _sessions[sid] = s
    s.save()
    return s


def get_session(session_id: str) -> Optional[TriageSession]:
    if session_id in _sessions:
        return _sessions[session_id]
    path = SESSIONS_DIR / f"{session_id}.json"
    if path.exists():
        try:
            s = TriageSession.from_dict(json.loads(path.read_text(encoding="utf-8")))
            _sessions[session_id] = s
            return s
        except Exception as exc:
            logger.warning(f"[SecDialogue] 会话文件损坏 {session_id}: {exc}")
    return None


def list_sessions(limit: int = 50) -> List[Dict[str, Any]]:
    """历史研判对话列表 (按更新时间倒序)."""
    _ensure_dir()
    items = []
    for path in SESSIONS_DIR.glob("*.json"):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            items.append({
                "session_id": d.get("session_id", path.stem),
                "alert_text": (d.get("alert_text") or "")[:80],
                "alert_type": d.get("alert_type", ""),
                "verdict": d.get("verdict", ""),
                "severity": d.get("severity", ""),
                "turns": len(d.get("turns", [])),
                "updated_at": d.get("updated_at", 0),
            })
        except Exception:
            continue
    items.sort(key=lambda x: x["updated_at"], reverse=True)
    return items[:limit]


# ---------- 对话轮 ----------
_SYSTEM_PROMPT = """你是安全研判工作台上的 SecOps Analyst, 正在与安全分析师围绕一条已初判的告警做多轮对话研判.

对话纪律 (必须遵守):
1. 分析师每轮可能粘贴新的取证材料 (日志片段/WAF 记录/情报结果/操作确认), 你必须明确指出新证据改变了什么判断、为什么.
2. evidence_used 只能列真实出现在对话或原始告警里的证据, 禁止编造.
3. **verdict 必须严格取以下四个值之一 (小写英文, 禁止其他写法如 true_positive/真阳性/攻击确认):**
   benign (良性/误报) | suspicious (可疑) | malicious (恶意/确认攻击) | inconclusive (证据不足)
   确认真实攻击时用 malicious, 不得自造新词.
4. verdict 变更必须由证据驱动: 无新证据时维持原判定, 有矛盾证据时如实说明冲突.
5. 证据仍不足时 needs_more_evidence=true 并在 next_steps 给出具体取证动作 (在什么设备上查什么).
6. reply 用简洁中文, 先给结论变化再给理由; 不确定就说不确定."""


def _build_dialogue_messages(session: TriageSession) -> List[Dict[str, str]]:
    transcript = "\n".join(
        f"[{'分析师' if t.role == 'user' else 'AI'}] {t.content[:1500]}" for t in session.turns[-12:]
    ) or "(尚无对话)"
    user = (
        f"# 原始告警\n{session.alert_text[:1500]}\n\n"
        f"# 初判报告\n{session.report[:2500]}\n\n"
        f"# 当前判定\nverdict={session.verdict} severity={session.severity} mode={session.response_mode}\n\n"
        f"# 已提取 IOC\n{json.dumps(session.iocs, ensure_ascii=False)[:600]}\n\n"
        f"# 对话记录 (最近 12 轮)\n{transcript}\n\n"
        "基于以上上下文与最新一轮分析师输入, 给出回复与判定更新."
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


async def dialogue_turn(session: TriageSession, user_input: str) -> Dict[str, Any]:
    """处理一轮对话: 记录 → LLM 带全上下文研判 → 更新会话 → 持久化."""
    session.turns.append(DialogueTurn(role="user", content=user_input))
    # 用户输入视为潜在证据贡献 (结束沉淀时汇总)
    if len(user_input) > 40:  # 短句是提问不是证据
        session.evidence_contribs.append(user_input[:800])

    try:
        harness = get_agent_harness()
        model = harness.router_model()
        llm = get_chat_llm(model=model, temperature=0.1, timeout=120, max_retries=3)
        update: VerdictUpdate = await ainvoke_structured(
            llm=llm,
            schema_cls=VerdictUpdate,
            messages=_build_dialogue_messages(session),
            model_name=model,
        )
    except Exception as exc:
        logger.warning(f"[SecDialogue] 对话 LLM 失败 (fail-soft): {exc}")
        reply = (
            "本轮研判服务暂不可用, 你的输入已记录。请稍后重发, "
            "或继续补充取证材料一并粘贴。"
        )
        session.turns.append(DialogueTurn(role="assistant", content=reply))
        session.updated_at = time.time()
        session.save()
        return {"reply": reply, "verdict": session.verdict, "severity": session.severity,
                "confidence": 0.0, "evidence_used": [], "needs_more_evidence": True,
                "next_steps": [], "llm_failed": True}

    # verdict/severity 白名单归一: 先走别名表, 仍不合法保持原值 (不虚构变更)
    new_verdict = normalize_verdict(update.verdict, fallback=session.verdict)
    new_severity = update.severity if update.severity in SEVERITIES else session.severity

    verdict_changed = new_verdict != session.verdict
    session.verdict = new_verdict
    session.severity = new_severity
    session.turns.append(DialogueTurn(role="assistant", content=update.reply))
    session.verdict_updates.append({
        "verdict": new_verdict,
        "confidence": update.confidence,
        "evidence_used": update.evidence_used,
        "ts": time.time(),
    })
    session.updated_at = time.time()
    session.save()

    logger.info(
        f"[SecDialogue] {session.session_id} turn={len(session.turns) // 2} "
        f"verdict={new_verdict}{' (变更!)' if verdict_changed else ''} "
        f"conf={update.confidence:.2f}"
    )
    return {
        "reply": update.reply,
        "verdict": new_verdict,
        "severity": new_severity,
        "confidence": update.confidence,
        "evidence_used": update.evidence_used,
        "needs_more_evidence": update.needs_more_evidence,
        "next_steps": update.next_steps,
        "verdict_changed": verdict_changed,
    }


async def close_session(session: TriageSession) -> Dict[str, Any]:
    """结束会话: 有证据贡献时把「对话补充证据 + 最终判定」沉淀为经验入库."""
    result = {"consolidated": False, "reason": ""}
    if not session.evidence_contribs:
        result["reason"] = "无补充证据, 无需沉淀"
        session.updated_at = time.time()
        session.save()
        return result

    try:
        from app.security.consolidation import consolidate_triage_report

        # 构造增强版报告: 初判报告 + 对话取证贡献 + 最终判定
        evidence_text = "\n---\n".join(session.evidence_contribs)
        final_report = (
            f"{session.report}\n\n"
            f"## 分析师对话补充的取证证据\n{evidence_text[:3000]}\n\n"
            f"## 对话后最终判定\nverdict={session.verdict} severity={session.severity}\n"
        )
        await consolidate_triage_report(
            session.session_id, session.alert_text, final_report, session.verdict
        )
        result["consolidated"] = True
        session.updated_at = time.time()
        session.save()
        return result
    except Exception as exc:
        logger.warning(f"[SecDialogue] 结束沉淀失败 (fail-soft): {exc}")
        result["reason"] = str(exc)
        return result
