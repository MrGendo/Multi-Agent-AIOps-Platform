"""IOC 提取器 (Indicator of Compromise).

纯正则实现, 零依赖 (借鉴 SentinelOps ioc_parser 的设计, 按项目风格重写):
  - IPv4 (可选过滤 RFC1918 私网段)
  - MD5/SHA1/SHA256 (长哈希优先, 短哈希从剩余文本中提取避免双计)
  - 域名 (常见 TLD 白名单)
  - CVE 编号
  - URL (并从域名结果中剔除 URL 主机, 避免重复)

用法:
    from app.security.ioc_extractor import extract_iocs
    iocs = extract_iocs("来自 203.0.113.42 的 SSH 暴力破解 ...")
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# ============================================================
# 正则模式
# ============================================================
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"']+")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|co|uk|ru|cn|de|fr|nl|xyz|info|biz|online|top|me|tv)\b"
)

# RFC1918 + 特殊地址 (可选过滤)
_PRIVATE_RANGES = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^255\.255\.255\.255$"),
]

# attacker 语境词 (该 IP 前最近的语境词决定其角色)
# 英文词用 \b 防子串误匹配 (on/to/by 等短词), 中文直接匹配
_ATTACKER_CONTEXT = re.compile(r"\b(?:from|by|src|source|attacker)\b|来自|攻击源|源")
# victim 语境词 (→ 受害者候选)
_VICTIM_CONTEXT = re.compile(r"\b(?:on|to|target|dst|victim)\b|受害|目标")

# 语境词扫描窗口: 只看 IP 前这段 (语境词通常紧邻 IP 之前)
_CONTEXT_WINDOW = 30


def _is_private_ip(ip: str) -> bool:
    """是否 RFC1918 私网/特殊地址."""
    return any(p.match(ip) for p in _PRIVATE_RANGES)


def extract_iocs(text: str, include_private_ips: bool = True) -> Dict[str, List[str]]:
    """从文本提取全部 IOC, 去重保序.

    Args:
        text: 告警原文 / 日志片段 / webhook 渲染文本
        include_private_ips: False 时过滤 RFC1918 私网地址

    Returns:
        {ips, hashes, domains, cves, urls} 五个列表
    """
    text = text or ""

    # --- IP ---
    ips = list(dict.fromkeys(_IPV4.findall(text)))
    if not include_private_ips:
        ips = [ip for ip in ips if not _is_private_ip(ip)]

    # --- 哈希: 长哈希优先, 提取后从文本移除再找短哈希 (避免 64 位串里截出 32 位) ---
    sha256 = list(dict.fromkeys(_SHA256.findall(text)))
    remaining = text
    for h in sha256:
        remaining = remaining.replace(h, " ")
    sha1 = list(dict.fromkeys(_SHA1.findall(remaining)))
    for h in sha1:
        remaining = remaining.replace(h, " ")
    md5 = list(dict.fromkeys(_MD5.findall(remaining)))
    hashes = sha256 + sha1 + md5

    # --- CVE / URL ---
    cves = [c.upper() for c in dict.fromkeys(_CVE.findall(text))]
    urls = list(dict.fromkeys(_URL.findall(text)))

    # --- 域名: 剔除 URL 主机, 避免与 URL 双计 ---
    url_hosts = set()
    for url in urls:
        parts = url.split("/")
        if len(parts) >= 3:
            url_hosts.add(parts[2])
    domains = [d for d in dict.fromkeys(_DOMAIN.findall(text)) if d not in url_hosts]

    return {"ips": ips, "hashes": hashes, "domains": domains, "cves": cves, "urls": urls}


def compute_anomaly_score(iocs: Dict[str, List[str]], text: str = "") -> float:
    """启发式异常分: 反映 IOC 密度, 不是威胁判定.

    计分 (借鉴 SentinelOps compute_anomaly_score, 权重对齐告警实践):
      每个 IP +0.15 (封顶 0.45) / 每个哈希 +0.20 (封顶 0.40) /
      每个 CVE +0.25 (封顶 0.50) / 每个域名 +0.10 (封顶 0.30)
    总分 clamp 到 1.0, 保留 3 位小数.
    """
    score = 0.0
    score += min(len(iocs.get("ips", [])) * 0.15, 0.45)
    score += min(len(iocs.get("hashes", [])) * 0.20, 0.40)
    score += min(len(iocs.get("cves", [])) * 0.25, 0.50)
    score += min(len(iocs.get("domains", [])) * 0.10, 0.30)
    return round(min(score, 1.0), 3)


def classify_ips(ips: List[str], alert_text: str) -> Tuple[List[str], List[str]]:
    """按告警语境把 IP 分为 (attacker_candidates, victim_candidates).

    规则: 找 IP 前最近 (≤30 字符) 的语境词 — attacker 词最近 → 攻击者候选;
    victim 词最近 → 受害者候选; 无语境词 → 默认攻击者候选
    (安全侧宁严勿漏: 拿不准的 IP 按攻击者对待, 处置建议里再人工甄别).
    """
    attacker: List[str] = []
    victim: List[str] = []
    text = alert_text or ""

    for ip in ips:
        idx = text.find(ip)
        role = "attacker"  # 找不到位置/无语境词 → 默认攻击者
        if idx >= 0:
            window = text[max(0, idx - _CONTEXT_WINDOW) : idx]
            # 各语境词在窗口内的最后出现位置, 谁离 IP 近听谁的
            last_attacker = -1
            for m in _ATTACKER_CONTEXT.finditer(window):
                last_attacker = m.start()
            last_victim = -1
            for m in _VICTIM_CONTEXT.finditer(window):
                last_victim = m.start()
            if last_victim > last_attacker:  # -1 时表示未出现
                role = "victim"
        (attacker if role == "attacker" else victim).append(ip)
    return attacker, victim
