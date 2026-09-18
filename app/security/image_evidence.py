"""图片证据提取器 — 把取证截图变成文字证据进研判管线.

设计: 图片不直接进研判 LLM 的消息流, 而是先用视觉模型提取为
结构化文字描述 (读到的 IP/告警字段/日志内容), 再作为普通证据
进对话研判 — 五阶段管线/结构化输出/经验沉淀零改动.

已验证: GLM-5.3 (Anthropic 端点) 原生支持 image_url content block
(2026-09-17 实测 8x8 纯红 PNG 正确识别「红色」).
"""

from __future__ import annotations

import base64
import binascii
from typing import Optional

from loguru import logger

from app.core.llm import get_chat_llm
from app.runtime.agent_harness import get_agent_harness

# 支持的图片格式 (Anthropic 协议)
SUPPORTED_MIME = ("image/png", "image/jpeg", "image/gif", "image/webp")

# base64 上限 (~8MB 图片), 防 prompt 膨胀/超时
_MAX_B64_LEN = 8 * 1024 * 1024

_EXTRACT_PROMPT = """你是安全取证图片分析员。分析师上传了一张安全设备截图 (WAF/IDS 控制台、日志终端、EDR 进程树、拓扑图等)。

请把图片内容完整转写为文字证据, 供后续研判使用。要求:
1. 逐项列出你能读到的关键信息: IP 地址、域名、URL、哈希、CVE 编号、时间戳、告警/规则名、日志行原文、状态码等 — 原样抄录, 不要推测补全。
2. 如果是表格或列表, 按行转写。
3. 如果有拓扑/流量图, 描述节点与连线关系。
4. 看不清的部分明确标注 [不可辨认], 禁止编造。
5. 最后用一段话概括这张截图说明了什么事件。
直接输出转写文本, 不要寒暄。"""


def validate_image_b64(image_b64: str, mime: str = "image/png") -> tuple[bool, str]:
    """校验 base64 图片: 格式白名单 + 大小上限 + 合法 base64."""
    if mime not in SUPPORTED_MIME:
        return False, f"不支持的图片格式 {mime} (支持: {'/'.join(SUPPORTED_MIME)})"
    if not image_b64:
        return False, "图片数据为空"
    if len(image_b64) > _MAX_B64_LEN:
        return False, f"图片过大 (>{_MAX_B64_LEN // 1024 // 1024}MB), 请压缩后重试"
    try:
        base64.b64decode(image_b64, validate=True)
    except (binascii.Error, ValueError):
        return False, "非法的 base64 数据"
    return True, ""


async def extract_image_evidence(image_b64: str, mime: str = "image/png",
                                 note: str = "") -> str:
    """视觉模型读图 -> 文字证据. 失败返回空串 (fail-soft, 由调用方提示).

    Args:
        image_b64: 图片 base64 (不含 data: 前缀)
        mime: 图片 MIME 类型
        note: 分析师对图片的补充说明 (如「这是 WAF 拦截页」)
    """
    try:
        harness = get_agent_harness()
        model = harness.router_model()
        llm = get_chat_llm(model=model, temperature=0, timeout=120, max_retries=2)
        from langchain_core.messages import HumanMessage

        note_line = f"\n(分析师备注: {note})" if note else ""
        msg = HumanMessage(content=[
            {"type": "text", "text": _EXTRACT_PROMPT + note_line},
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}"}},
        ])
        resp = await llm.ainvoke([msg])
        content = getattr(resp, "content", resp)
        if isinstance(content, list):
            text = "".join(
                item.get("text", "") for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            )
        else:
            text = str(content)
        text = text.strip()
        logger.info(f"[ImageEvidence] 图片转写完成 ({len(text)} 字)")
        return text
    except Exception as exc:
        logger.warning(f"[ImageEvidence] 图片提取失败 (fail-soft): {exc}")
        return ""
