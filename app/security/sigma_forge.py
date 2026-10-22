"""Sigma 检测规则反哺 (Detection Feedback Loop) — 研判经验 → 检测规则草稿.

动机: consolidation 把研判经验沉淀进向量库, 但闭环止步于「下次研判更准」.
真实 SOC 的飞轮是 检测 → 研判 → 经验 → 再检测: 一条被证实为真实攻击的
研判 (人工 resolved), 其攻击特征应该反哺成新的检测规则, 让同类攻击下次
在「告警阶段」就被抓到, 而不是每次都烧一遍研判 token.

实现:
  1. 召回 secops_experience 经验 (向量库, 可选; 无库时直接用入参经验文本)
  2. LLM 结构化提炼 SigmaRuleDraft (Pydantic 契约, 见下)
  3. 渲染为合法 Sigma YAML (Sigma 是检测规则的事实标准, pySigma 兼容结构:
     title/id/status/description/references/logsource/detection/condition/
     falsepositives/level/tags)
  4. 落盘 data/sigma_drafts/<fid>.yaml + meta, 状态机 draft → approved

纪律 (与高危响应人工审批同源的边界):
  - 默认 draft_only: 系统只产「草稿」, 永不自动下发设备 — 检测规则改一行
    condition 就能改变全网的告警面, 这是确定性影响, 必须人签字
  - approve 端点只改状态标记, 不触碰任何设备 (下发由人用 Sigma 工具链做)
  - LLM 失败 fail-soft: 返回明确错误, 不输出半成品规则
  - condition/detection 引用的 selector 名必须存在 (渲染时校验, 防编造)
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import yaml
from loguru import logger
from pydantic import BaseModel, Field, model_validator

from app.core.llm import get_chat_llm
from app.core.structured import ainvoke_structured
from app.runtime.agent_harness import get_agent_harness

_DRAFTS_DIR = Path(__file__).resolve().parents[2] / "data" / "sigma_drafts"

_SIGMA_LEVELS = ("informational", "low", "medium", "high", "critical")


class SigmaSelector(BaseModel):
    """Sigma detection selector (一组匹配条件)."""

    name: str = Field(description="selector 名称, 如 selection_main / filter_benign")
    conditions: Dict[str, List[str]] = Field(
        description=(
            "字段 → 值列表 (字段名用目标日志源的字段, 如 "
            "event.action / win.eventid / CommandLine). 值可含通配符 *"
        )
    )

    @model_validator(mode="before")
    @classmethod
    def _coerce_conditions(cls, data: Any) -> Any:
        """真实 LLM 会漂移出非契约形态 (E2E 实测):

        conditions 给成裸字符串 "selection_xxx" / "EventID=4625" 单句 /
        {field: "v"} 标量值 — 全部归一成 {field: [values]}.
        归一不了的丢该键 (宁缺勿编), 整个 conditions 空则给兜底键.
        """
        if isinstance(data, dict):
            cond = data.get("conditions")
            if isinstance(cond, str):
                # "EventID=4625 AND IpAddress=185.*" → 拆 k=v 对
                pairs: Dict[str, List[str]] = {}
                for part in re.split(r"\s*(?:,|;|\band\b|\bAND\b)\s*", cond):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        k, v = k.strip(), v.strip().strip("'\"")
                        if k and v:
                            pairs[k] = [v]
                data = {**data, "conditions": pairs or {"field": [cond.strip()]}}
            elif isinstance(cond, dict):
                fixed: Dict[str, List[str]] = {}
                for k, v in cond.items():
                    if isinstance(v, (list, tuple)):
                        vals = [str(x) for x in v if str(x).strip()]
                    elif isinstance(v, str) and v.strip():
                        vals = [v.strip()]
                    else:
                        vals = []
                    if vals:
                        fixed[str(k)] = vals
                data = {**data, "conditions": fixed or {"field": ["*"]}}
        return data


class SigmaRuleDraft(BaseModel):
    """LLM 提炼的 Sigma 规则草稿 (渲染前的结构化契约)."""

    title: str = Field(description="规则标题, 说清检测什么行为")
    description: str = Field(description="检测逻辑与依据 (对应哪条研判经验)")
    logsource: Dict[str, str] = Field(
        description=(
            "Sigma logsource 块: category/product/service 至少一项 "
            "(如 {'category': 'process_creation'})"
        )
    )
    selectors: List[SigmaSelector] = Field(
        description="detection 块的匹配条件, 1-4 个 selector"
    )
    condition: str = Field(
        description=(
            "布尔组合表达式, 只能引用 selectors 里定义过的名称, 如 "
            "'selection_main and not filter_benign'"
        )
    )
    falsepositives: List[str] = Field(
        default_factory=list,
        description="已知误报场景 (来自研判历史中的人工误报标记最好)",
    )
    level: str = Field(description="Sigma 等级: informational/low/medium/high/critical")
    references: List[str] = Field(
        default_factory=list, description="参考链接 (MITRE 技术/研判 session)"
    )


class ForgeRequest(BaseModel):
    """锻造请求: 从经验文本直接生成 (无向量库依赖的入口)."""

    experience_text: str = Field(
        default="",
        description="研判经验原文 (攻击模式+IOC+判定逻辑). 留空则自动从经验库召回最近经验",
    )
    source_session_id: str = Field(default="", description="来源研判会话 (溯源用)")
    limit: int = Field(default=3, ge=1, le=5, description="无 experience_text 时召回的经验条数")


def _sanitize_selector_name(name: str) -> str:
    """selector 名归一到合法标识符 (LLM 可能给中文名/带空格)."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", (name or "").strip())
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"sel_{cleaned}"
    return cleaned


def _sanitize_field_name(field: str) -> str:
    """字段名含空格/冒号时 YAML 需要引号 — 统一清成点分字段名."""
    return re.sub(r"[^a-zA-Z0-9_.\[\]]", "_", (field or "").strip()) or "field"


def render_sigma_yaml(draft: SigmaRuleDraft) -> str:
    """结构化草稿 → 合法 Sigma YAML (确定性渲染, 不经 LLM)."""
    # 原始名 → 归一名映射 (condition 里的引用也要跟着归一, 中文名/带空格名同理)
    name_map: Dict[str, str] = {}
    selectors: Dict[str, Dict[str, List[str]]] = {}
    for s in draft.selectors:
        clean = _sanitize_selector_name(s.name)
        # 防两个原始名归一后撞名
        base_name, i = clean, 2
        while clean in selectors:
            clean = f"{base_name}_{i}"
            i += 1
        name_map[s.name] = clean
        selectors[clean] = {
            _sanitize_field_name(f): vals for f, vals in (s.conditions or {}).items()
        }

    condition = (draft.condition or "").strip()
    # 先把 condition 里出现的原始 selector 名 (含中文/空格) 替换为归一名
    for raw_name, clean in sorted(name_map.items(), key=lambda kv: -len(kv[0])):
        if raw_name and raw_name != clean:
            condition = condition.replace(raw_name, clean)
    # condition 引用的 selector 必须存在 (防 LLM 编造引用)
    valid_names = set(selectors.keys())
    referenced = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", condition)) - {
        "and", "or", "not", "of", "all", "1", "them",
    }
    unknown = referenced - valid_names
    for u in sorted(unknown):
        # 未知引用替换为首个 selector (保守) 并标注 — 不让渲染出非法规则
        first = sorted(valid_names)[0] if valid_names else "selection"
        condition = re.sub(rf"\b{re.escape(u)}\b", first, condition)

    rule: Dict[str, Any] = {
        "title": draft.title,
        "id": str(hashlib.md5(f"{draft.title}|{condition}".encode()).hexdigest()),
        "status": "experimental",
        "description": draft.description,
        "references": draft.references or [],
        "logsource": draft.logsource,
        "detection": {
            **selectors,
            "condition": condition,
        },
        "falsepositives": draft.falsepositives or ["unknown"],
        "level": draft.level if draft.level in _SIGMA_LEVELS else "medium",
    }
    return yaml.safe_dump(rule, allow_unicode=True, sort_keys=False, width=100)


def _fingerprint(draft: SigmaRuleDraft) -> str:
    """草稿指纹 (title+logsource+condition) — 同经验重复锻造幂等去重."""
    raw = f"{draft.title}|{sorted(draft.logsource.items())}|{draft.condition}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


async def forge_from_experience(req: ForgeRequest) -> Dict[str, Any]:
    """从研判经验生成 Sigma 规则草稿 (主流程, fail-soft 不抛异常)."""
    experience = (req.experience_text or "").strip()

    if not experience:
        # 无入参经验 → 向量召回最近的 secops_experience
        try:
            from app.core.vector_store import get_vector_store

            from app.security.consolidation import SECOPS_EXP_SOURCE

            docs = get_vector_store().similarity_search(
                "真实攻击 研判经验 威胁模式", k=req.limit,
                expr=f"source == '{SECOPS_EXP_SOURCE}'",
            )
            blocks = []
            for d in docs:
                title = (d.metadata or {}).get("h1") or "历史研判"
                verdict = (d.metadata or {}).get("verdict") or ""
                tag = f" [判定: {verdict}]" if verdict else ""
                blocks.append(f"- {title}{tag}: {d.page_content[:400]}")
            experience = "\n".join(blocks)
        except Exception as exc:
            logger.debug(f"[SigmaForge] 经验召回失败 (fail-soft): {exc}")

    if not experience:
        return {
            "status": "no_experience",
            "message": "无可用研判经验 (入参为空且经验库无内容/不可用), 无法锻造规则",
            "drafts": [],
        }

    # ---- LLM 结构化提炼 ----
    try:
        harness = get_agent_harness()
        model = harness.planner_model()
        llm = get_chat_llm(model=model, temperature=0.1, timeout=120, max_retries=2)
        system_prompt = (
            "你是检测工程专家 (Detection Engineer). 任务: 把安全研判经验转成 "
            "Sigma 检测规则草稿. 要求: 只用经验里真实出现过的字段与值, 不得编造 "
            "未见过的 IOC/字段; logsource 要与经验的告警来源匹配; condition 只能 "
            "引用你定义的 selector; 已知误报场景写进 falsepositives. 输出必须是 "
            "结构化 SigmaRuleDraft."
        )
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"研判经验:\n{experience}\n\n"
                    f"来源会话: {req.source_session_id or '经验库召回'}"
                ),
            },
        ]
        draft = await ainvoke_structured(
            llm=llm, schema_cls=SigmaRuleDraft, messages=messages, model_name=model
        )
    except Exception as e:
        logger.warning(f"[SigmaForge] LLM 提炼失败 (fail-soft): {e}")
        return {
            "status": "llm_failed",
            "message": f"规则提炼失败: {type(e).__name__}: {e}",
            "drafts": [],
        }

    # ---- 渲染 + 落盘 (draft 状态) ----
    fid = _fingerprint(draft)
    yaml_text = render_sigma_yaml(draft)
    meta = {
        "fid": fid,
        "status": "draft",
        "title": draft.title,
        "level": draft.level,
        "source_session_id": req.source_session_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "sigma_yaml": yaml_text,
    }
    try:
        _DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
        existing = _DRAFTS_DIR / f"{fid}.yaml"
        if existing.exists():
            meta["status"] = "duplicate"
            meta["message"] = "同指纹草稿已存在 (title+logsource+condition), 未重复落盘"
        else:
            # YAML 文件本体: Sigma 规则 + 头部元数据块 (status 由 meta 文件管理)
            body = yaml.safe_load(yaml_text)
            body["_meta"] = {k: meta[k] for k in ("fid", "status", "created_at", "source_session_id")}
            existing.write_text(
                yaml.safe_dump(body, allow_unicode=True, sort_keys=False, width=100),
                encoding="utf-8",
            )
    except Exception as e:
        logger.warning(f"[SigmaForge] 草稿落盘失败: {e}")
        return {"status": "persist_failed", "message": str(e), "drafts": [meta]}

    return {
        "status": "ok",
        "message": (
            "已生成 Sigma 检测规则草稿 (draft 状态, 未下发任何设备). "
            "人工审核通过后调用 approve 端点标记."
        ),
        "drafts": [meta],
    }


def list_drafts() -> Dict[str, Any]:
    """列出全部规则草稿 (draft/approved 状态机)."""
    try:
        if not _DRAFTS_DIR.exists():
            return {"status": "ok", "drafts": []}
        out = []
        for p in sorted(_DRAFTS_DIR.glob("*.yaml")):
            try:
                body = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                m = body.get("_meta") or {}
                out.append({
                    "fid": m.get("fid") or p.stem,
                    "status": m.get("status", "draft"),
                    "title": body.get("title", ""),
                    "level": body.get("level", ""),
                    "created_at": m.get("created_at", ""),
                    "source_session_id": m.get("source_session_id", ""),
                })
            except Exception:
                continue
        return {"status": "ok", "drafts": out}
    except Exception as exc:
        logger.debug(f"[SigmaForge] 草稿列表失败 (fail-soft): {exc}")
        return {"status": "error", "message": str(exc), "drafts": []}


def approve_draft(fid: str, reviewer: str = "", note: str = "") -> Dict[str, Any]:
    """人工审批: draft → approved (只改标记, 绝不触碰设备)."""
    path = _DRAFTS_DIR / f"{fid}.yaml"
    if not path.exists():
        return {"status": "not_found", "message": f"草稿不存在: {fid}"}
    try:
        body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        meta = body.get("_meta") or {}
        if meta.get("status") == "approved":
            return {"status": "already_approved", "fid": fid, "message": "已审批过 (幂等)"}
        meta.update({
            "status": "approved",
            "approved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "reviewer": reviewer or "human",
            "review_note": note,
        })
        body["_meta"] = meta
        path.write_text(
            yaml.safe_dump(body, allow_unicode=True, sort_keys=False, width=100),
            encoding="utf-8",
        )
        return {
            "status": "approved",
            "fid": fid,
            "message": "已标记 approved (仅状态标记 — 下发设备由人用 Sigma 工具链执行, 本系统不自动下发)",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc), "fid": fid}
