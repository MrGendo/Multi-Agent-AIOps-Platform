"""链接沙箱验证 (urlscan.io L1) — 第三方代访, 本方网络零接触.

OPSEC 边界 (与 email_triage 的"绝不自动访问"纪律衔接):
  - httpx 只请求 urlscan.io 域, 绝不直接访问待测 URL — 隔离访问由沙箱完成
  - 只验证前 limit 条 URL (域名去重): 控制额度消耗与"烧一次性链接"影响面
  - 全路径 fail-soft: 无 key/超额/超时/网络错误 → 单条记 error/skipped,
    绝不抛异常阻断主研判流

验证内容 (v2, 语义层 — 针对"合法域下恶意内容"的评分盲区):
  - 数值字段: verdicts/page (score/域名年龄/落地 URL)
  - DOM 静态检测: 密码表单存在性 + form action 域比对 (零 LLM 确定性层)
  - 截图视觉判定: LLM 判"页面声称身份/是否索取凭据/是否仿冒" —
    基础设施信号失效时, 页面语义仍是钓鱼的本质特征

urlscan 流程: POST /api/v1/scan/ 拿 uuid → 轮询 GET /api/v1/result/{uuid}/
(扫描异步, 数秒到数十秒) → 拉 DOM (需 API-Key) + 截图 (公开) → 提炼判定.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from loguru import logger
from pydantic import BaseModel, Field, model_validator

from app.config import settings

_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
_DOM_URL = "https://urlscan.io/dom/{uuid}/"
_SHOT_URL = "https://urlscan.io/screenshots/{uuid}.png"
_POLL_INTERVAL_SEC = 2.0
_TOTAL_BUDGET_SEC = 70.0   # 单条 URL 提交+轮询+语义增强总预算 (须 ≤ 研判等待窗 75s)
_DOM_MAX_BYTES = 300_000   # DOM 截断 (钓鱼页 DOM 可能巨大, 只做表单检测够用)
_SHOT_MAX_BYTES = 3_000_000


def _domain_of(url: str) -> str:
    try:
        return (urlparse(url if "//" in url else f"http://{url}").hostname or "").lower()
    except Exception:
        return ""


def sandbox_key() -> str:
    """沙箱启用判定统一入口 — 启用规则只在这一处 (review: 此前三处重复,
    规则变更需改三处)."""
    return (settings.urlscan_api_key or "").strip()


def _sandbox_unreachable(url: str) -> bool:
    """私网/回环/无点内网主机名 — urlscan 扫描器在公网侧永远访问不到, 提交
    只会得到 score=0 的假"干净", 必须前置跳过 (真实端到端发现的假阴性边界)."""
    host = _domain_of(url)
    if not host:
        return False
    if host == "localhost" or "." not in host:
        # 无点单标签主机名 (fileserver/dc01 类内网名) 同样公网不可达
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False   # 普通域名, 沙箱可达


# ============================================================
# DOM 静态检测 (确定性层, 零 LLM)
# ============================================================

_PASSWORD_INPUT_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
_FORM_TAG_RE = re.compile(r"<form[^>]*>", re.I)
_FORM_ACTION_RE = re.compile(r"action\s*=\s*[\"']?([^\"'\s>]+)", re.I)


def detect_credential_form(dom: str, page_url: str) -> Dict[str, Any]:
    """DOM → 密码表单检测: 密码框存在性 + form action 目标域.

    钓鱼页的本质行为是"骗你输密码" — 这个特征不随基础设施 (合法域名/
    新证书/干净 ASN) 变化, 是对 urlscan score 盲区的确定性补充.
    """
    empty = {"has_password": None, "form_action": None, "action_domain": None, "cross_domain": None}
    if not dom:
        return empty
    has_pw = bool(_PASSWORD_INPUT_RE.search(dom))
    action = None
    for form in _FORM_TAG_RE.findall(dom):
        m = _FORM_ACTION_RE.search(form)
        if m:
            action = m.group(1)
            break
    action_domain = None
    cross = None
    if action:
        abs_action = action if "//" in action else urljoin(page_url, action)
        action_domain = _domain_of(abs_action)
        page_domain = _domain_of(page_url)
        if action_domain and page_domain:
            cross = action_domain != page_domain
    return {
        "has_password": has_pw,
        "form_action": action,
        "action_domain": action_domain,
        "cross_domain": cross,
    }


# ============================================================
# 截图视觉判定 (LLM 语义层)
# ============================================================

class LandingPageJudgement(BaseModel):
    """落地页截图的结构化判定."""

    claimed_identity: str = Field(description="页面声称的身份/机构/品牌 (如「广州大学统一身份认证」); 无明确声称写「未声称」")
    credential_form: bool = Field(default=False, description="页面是否在索取凭据 (密码/验证码/身份证号等)")
    submits_to: str = Field(default="(未见表单)", description="表单提交目标域名或按钮跳转目标")
    impersonation: str = Field(
        description="impersonating(仿冒既有机构/品牌) / suspicious(可疑但不确定) / legitimate(正常页面) / unclear(无法判定)"
    )
    impersonation_target: str = Field(default="无", description="仿冒对象 (机构/品牌名); 非仿冒写「无」")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(default="", description="一句话判定依据")

    @model_validator(mode="before")
    @classmethod
    def _normalize_impersonation(cls, data: Any) -> Any:
        """LLM 自造词防线 (与 email_triage 枚举归一同款纪律)."""
        if isinstance(data, dict):
            raw = str(data.get("impersonation") or "").strip().lower()
            aliases = {
                "impersonating": "impersonating", "仿冒": "impersonating", "冒充": "impersonating",
                "phishing": "impersonating", "suspicious": "suspicious", "可疑": "suspicious",
                "legitimate": "legitimate", "正常": "legitimate", "benign": "legitimate",
                "unclear": "unclear", "不确定": "unclear", "": "unclear",
            }
            data = {**data, "impersonation": aliases.get(raw, "unclear")}
        return data


_JUDGE_PROMPT = """你是钓鱼页面取证分析员。这是沙箱 (urlscan.io) 代访某邮件内链接后的页面截图。
落地 URL: {url}
DOM 静态检测结果 (代码层验证过的事实): {form_hint}

请判定:
1. 页面声称自己是什么身份/机构/品牌 (看标题、logo、文案)
2. 是否在索取凭据 (密码框/验证码/证件号), 表单提交到哪
3. 是否在仿冒某个既有机构或品牌 (与大众熟知的外观/话术比对; 落地域与声称身份不符是最强信号)
只依据截图可见内容判定, 不要推测截图外的信息。输出结构化判定 (LandingPageJudgement)。"""


async def judge_landing_page(
    screenshot_b64: str, url: str, form_hint: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """截图 → 视觉 LLM 仿冒判定. 失败返回 None (fail-soft, 只留确定性检测)."""
    try:
        from langchain_core.messages import HumanMessage

        from app.core.llm import get_chat_llm
        from app.core.structured import ainvoke_structured
        from app.runtime.agent_harness import get_agent_harness

        harness = get_agent_harness()
        model = harness.router_model()
        llm = get_chat_llm(model=model, temperature=0, timeout=40, max_retries=1)
        msg = HumanMessage(content=[
            {"type": "text", "text": _JUDGE_PROMPT.format(url=url, form_hint=form_hint)},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{screenshot_b64}"}},
        ])
        judgement = await ainvoke_structured(
            llm=llm, schema_cls=LandingPageJudgement, messages=[msg], model_name=model,
        )
        return judgement.model_dump()
    except Exception as exc:
        logger.warning(f"[LinkVerify] 落地页视觉判定失败 (fail-soft): {exc}")
        return None


async def verify_urls(urls: List[str], limit: int = 3) -> List[Dict[str, Any]]:
    """并发验证前 limit 条 URL (域名去重). 返回逐条判定, 永不抛出.

    返回结构: {url, status: verified|error|skipped, malicious, score,
               categories, final_url, domain_age_days, screenshot,
               form (DOM 表单检测), judgement (视觉判定, 可缺)}
    """
    key = sandbox_key()
    if not key:
        return []   # 功能未启用, 调用方不发 verifying 事件
    picked, skipped_private = _pick_urls(urls, limit)
    if not picked:
        return skipped_private
    results = await asyncio.gather(*(_verify_one(u, key) for u in picked))
    return skipped_private + list(results)


async def verify_urls_bounded(
    urls: List[str], limit: int = 3, deadline_sec: float = 75.0
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """SSE 管线用: 等待窗内能完成多少算多少, 其余取消.

    返回 (verdicts, cancelled_urls) — 取消的由调用方以 link_report 后补告知;
    绝不让沙箱慢拖死研判 (窗口外 fail-soft 退化为无沙箱证据研判).
    """
    key = sandbox_key()
    if not key:
        return [], []
    picked, skipped_private = _pick_urls(urls, limit)
    if not picked:
        return skipped_private, []
    tasks = {asyncio.create_task(_verify_one(u, key)): u for u in picked}
    try:
        done, pending = await asyncio.wait(tasks, timeout=deadline_sec)
    except asyncio.CancelledError:
        # 调用方 (SSE 生成器) 被取消时必须级联取消子任务 — 否则客户端断连后
        # 沙箱轮询与视觉 LLM 调用在后台继续跑, 白烧额度 (review 实测复现的泄漏链)
        for t in tasks:
            t.cancel()
        raise
    # 微竞态收口: wait 返回后、cancel 前恰好完成的 pending 任务, 结果不该被误报为超时
    late_done = {t for t in pending if t.done() and not t.exception()}
    for t in pending:
        t.cancel()
    verdicts = skipped_private + [t.result() for t in (done | late_done) if not t.exception()]
    cancelled = [u for t, u in tasks.items() if t in pending and t not in late_done]
    return verdicts, cancelled


def _pick_urls(urls: List[str], limit: int) -> Tuple[List[str], List[Dict[str, Any]]]:
    """域名去重 (同域只烧一条额度) + 私网过滤 (沙箱不可达) + 截断."""
    picked: List[str] = []
    skipped_private: List[Dict[str, Any]] = []
    seen_domains = set()
    for u in urls:
        d = _domain_of(u)
        if not d or d in seen_domains:
            continue
        seen_domains.add(d)
        if _sandbox_unreachable(u):
            skipped_private.append({
                "url": u, "status": "skipped", "malicious": None,
                "score": None, "categories": [], "final_url": None,
                "domain_age_days": None, "screenshot": None,
                "error": "内网/回环地址, 公网沙箱不可达 — 请在内网环境人工验证",
            })
            continue
        picked.append(u)
        if len(picked) >= limit:
            break
    return picked, skipped_private


async def _verify_one(url: str, key: str) -> Dict[str, Any]:
    """单条 URL: 提交 → 轮询 → 提炼判定. 任何失败降级为 error/skipped."""
    base: Dict[str, Any] = {
        "url": url, "status": "skipped", "malicious": None,
        "score": None, "categories": [], "final_url": None,
        "domain_age_days": None, "screenshot": None,
    }
    headers = {"API-Key": key, "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            # ① 提交扫描 (visibility 可配; 429/超额在这里暴露)
            resp = await client.post(
                _SUBMIT_URL,
                json={"url": url, "visibility": settings.urlscan_visibility or "public"},
                headers=headers,
            )
            if resp.status_code == 429:
                base["status"] = "error"
                base["error"] = "urlscan 额度耗尽 (429)"
                return base
            resp.raise_for_status()
            uuid = (resp.json() or {}).get("uuid")
            if not uuid:
                base["status"] = "error"
                base["error"] = "urlscan 未返回 uuid"
                return base

            # ② 轮询结果: 404=还没扫完, 200=完成; 总预算内 3s 一次
            deadline = asyncio.get_event_loop().time() + _TOTAL_BUDGET_SEC
            while asyncio.get_event_loop().time() < deadline:
                await asyncio.sleep(_POLL_INTERVAL_SEC)
                r = await client.get(_RESULT_URL.format(uuid=uuid), headers=headers)
                if r.status_code == 404:
                    continue
                r.raise_for_status()
                data = r.json()
                verdict = _extract_verdict(base, uuid, data)
                # 语义增强: DOM 表单检测 + 截图视觉判定 (每步独立 fail-soft)
                await _enrich_semantics(client, key, uuid, verdict)
                return verdict

        base["status"] = "skipped"
        base["error"] = f"沙箱扫描超时 ({_TOTAL_BUDGET_SEC:.0f}s)"
        return base
    except Exception as exc:
        logger.warning(f"[LinkVerify] {url} 验证失败 (fail-soft): {exc}")
        base["status"] = "error"
        base["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        return base


def _extract_verdict(base: Dict[str, Any], uuid: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """从 urlscan result 提炼关键字段 (字段缺失容忍 — 以实测响应为准)."""
    verdicts = (data.get("verdicts") or {})
    overall = (verdicts.get("overall") or {})
    urlscan_v = (verdicts.get("urlscan") or {})
    page = (data.get("page") or {})

    base["status"] = "verified"
    if isinstance(urlscan_v.get("score"), (int, float)):
        base["score"] = urlscan_v["score"]
    # malicious: urlscan overall 判定优先, 缺失时用 score>0 推断
    if isinstance(overall.get("malicious"), bool):
        base["malicious"] = overall["malicious"]
    elif base["score"] is not None:
        base["malicious"] = base["score"] > 0
    cats = urlscan_v.get("categories") or overall.get("categories") or []
    base["categories"] = [str(c) for c in cats][:6]
    base["final_url"] = page.get("url")
    base["domain_age_days"] = page.get("domainAgeDays")
    base["screenshot"] = f"https://urlscan.io/screenshots/{uuid}.png"
    return base


async def _enrich_semantics(
    client: httpx.AsyncClient, key: str, uuid: str, verdict: Dict[str, Any]
) -> None:
    """语义增强: 拉 DOM 做表单检测 + 拉截图做视觉仿冒判定.

    每步独立 fail-soft — urlscan score 0 分的"合法域仿冒页"靠这两层兜住.
    """
    page_url = verdict.get("final_url") or verdict.get("url") or ""

    # ① DOM (需 API-Key; 免费档实测可得) → 密码表单静态检测
    dom = ""
    try:
        r = await client.get(_DOM_URL.format(uuid=uuid), headers={"API-Key": key}, timeout=15.0)
        if r.status_code == 200:
            dom = r.text[:_DOM_MAX_BYTES]
    except Exception as exc:
        logger.debug(f"[LinkVerify] DOM 拉取失败 (跳过表单检测): {exc}")
    verdict["dom_available"] = bool(dom)
    verdict["form"] = detect_credential_form(dom, page_url)

    # ② 截图 (公开) → 视觉 LLM 仿冒判定
    try:
        r = await client.get(_SHOT_URL.format(uuid=uuid), timeout=20.0)
        if r.status_code == 200 and len(r.content) <= _SHOT_MAX_BYTES:
            shot_b64 = base64.b64encode(r.content).decode("ascii")
            verdict["judgement"] = await judge_landing_page(shot_b64, page_url, verdict["form"])
        else:
            verdict["judgement"] = None
    except Exception as exc:
        logger.debug(f"[LinkVerify] 截图/视觉判定失败 (跳过): {exc}")
        verdict["judgement"] = None


def format_sandbox_evidence(verdicts: List[Dict[str, Any]]) -> str:
    """验证结论 → LLM 研判注入文本 (只取已验证事实, 跳过 error/skipped)."""
    lines = []
    for v in verdicts:
        if v.get("status") != "verified":
            continue
        parts = [v["url"]]
        form = v.get("form") or {}
        if form.get("has_password"):
            parts.append("页面含密码输入框")
        if form.get("action_domain"):
            tag = "异域" if form.get("cross_domain") else "同域"
            parts.append(f"表单提交至{tag} {form['action_domain']}")
        j = v.get("judgement") or {}
        if j:
            parts.append(f"页面声称「{j.get('claimed_identity', '?')}」")
            if j.get("impersonation") == "impersonating":
                parts.append(
                    f"视觉判定: 仿冒 {j.get('impersonation_target', '某机构')} "
                    f"(置信 {j.get('confidence', 0):.0%})"
                )
            elif j.get("impersonation") == "suspicious":
                parts.append("视觉判定: 可疑 (不足以定性)")
        lines.append("- " + ", ".join(parts))
    return "\n".join(lines)
