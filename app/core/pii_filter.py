"""PII/敏感数据脱敏处理器 (结构化日志与持久化前置过滤器).

为什么需要:
  诊断流程会把工具原始输出 (日志/报错) 写进日志与数据库, 其中可能混有
  密码、API Key、内网 IP。工业级系统要求日志管道全程脱敏, 防止一次
  排障泄露一批凭证。

用法:
  >>> from app.core.pii_filter import sanitize
  >>> sanitize("connect to mysql://root:SuperSecret@10.0.0.5:3306/db")
  'connect to mysql://root:***@10.0.0.***:3306/db'

设计:
  - 纯函数零依赖 (只 re), 导入无副作用, 方便单测与复用
  - 规则分三类: 凭证类 (打码保留前缀辨识)、IP 类 (末段打码)、通用 token 类
  - 兜底规则: SECRET_XXX=yyy / password="yyy" / token: yyy 等 key-value 形态
"""

from __future__ import annotations

import re

# ============================================================
# 凭证/密钥类: 保留前缀辨识信息, 值整体打码
# ============================================================
# AWS Access Key (AKIA... 20 位)
_RE_AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
# JWT (三段 base64url)
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
# 私钥块
_RE_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
# sk-/gsk_/ghp_ 等常见 API key 前缀
_RE_API_KEY = re.compile(r"\b(sk|gsk|ghp|gho|glpat|xoxb|xoxp)[-_][A-Za-z0-9]{16,}\b")
# Bearer 头
_RE_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")

# key=value / key: value 形态的敏感 key 兜底
# 注意: Python 3.11 起 global flags 必须在表达式最前面, 因此 (?i) 前置.
# 关键词允许标识符前后缀 (DB_PASSWORD / SECRET_MYSQL_PASS / auth-token 等).
# 注意: Python 3.11 起 global flags 必须在表达式最前面, 因此 (?i) 前置
_SENSITIVE_KEY_PATTERN = (
    r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"authorization|credential|private[_-]?key)"
)
_RE_KV_COLON = re.compile(
    r"(?i)\b([A-Za-z0-9_\-]*(?:" + _SENSITIVE_KEY_PATTERN + r")[A-Za-z0-9_\-]*)"
    r"(\s*[:=]\s*)([\"\']?)([^\s\"\'&,;)]+)"
)
_RE_KV_JSON = re.compile(
    r"(?i)([\"\\])(" + _SENSITIVE_KEY_PATTERN + r")([\"\\]\s*:\s*[\"\\])(.*?)([\"\\])"
)
# URL userinfo 凭证: scheme://user:password@host
_RE_URL_CREDS = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^:/@\s]+:)([^@\s]+)(@)")


def _mask_value(value: str) -> str:
    """值打码: 保留前 2 位辨识 + ***."""
    if not value:
        return value
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***"


# ============================================================
# IP 类: 保留网络段, 末段打码 (保留排障价值的同时降低精确暴露)
# ============================================================
_RE_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\b")
# 排除版本号形态 (如 1.2.3.4 版本字符串不常见, 但 0.0.0.0/127.0.0.1 这类
# 非敏感回环/通配地址跳过; 端口后面的 IP 更可能是服务地址)
_SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _mask_ipv4(text: str) -> str:
    def _repl(m: re.Match) -> str:
        full = m.group(0)
        head = m.group(1)
        if full in _SKIP_IPS:
            return full
        return f"{head}.***"

    return _RE_IPV4.sub(_repl, text)


# ============================================================
# 组合入口
# ============================================================
def sanitize(text: str) -> str:
    """对文本做 PII 脱敏, 返回新字符串. 永不抛异常."""
    if not text:
        return text
    try:
        # 1. 高危凭证 (整体替换, 不留原文)
        text = _RE_PRIVATE_KEY.sub("[REDACTED:PRIVATE-KEY]", text)
        text = _RE_AWS_KEY.sub("[REDACTED:AWS-KEY]", text)
        text = _RE_JWT.sub("[REDACTED:JWT]", text)
        text = _RE_API_KEY.sub(lambda m: f"[REDACTED:{m.group(1).upper()}-KEY]", text)
        text = _RE_BEARER.sub("Bearer [REDACTED]", text)
        text = _RE_URL_CREDS.sub(r"\1***\3", text)

        # 2. key=value 兜底
        text = _RE_KV_COLON.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask_value(m.group(4))}", text
        )
        text = _RE_KV_JSON.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask_value(m.group(4))}{m.group(5)}",
            text,
        )

        # 3. IP 末段打码
        text = _mask_ipv4(text)
        return text
    except Exception:
        # 脱敏失败绝不能影响业务, 返回原文本
        return text


def sanitize_mapping(mapping: dict) -> dict:
    """递归脱敏 dict 的所有字符串值 (浅拷贝, 不改原对象).

    key 本身命中敏感关键词时, 值直接整体打码 (无论值形态).
    """
    import re as _re

    sensitive_key = _re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"authorization|credential|private[_-]?key)"
    )
    out = {}
    for k, v in mapping.items():
        if isinstance(v, str):
            out[k] = "***" if sensitive_key.search(str(k)) else sanitize(v)
        elif isinstance(v, dict):
            out[k] = sanitize_mapping(v)
        else:
            out[k] = v
    return out
