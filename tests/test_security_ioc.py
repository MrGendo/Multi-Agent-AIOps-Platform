"""IOC 提取与威胁情报模块离线单测."""

from __future__ import annotations

import pytest

from app.security import ioc_extractor as ie
from app.security import threat_intel as ti


# ============================================================
# extract_iocs
# ============================================================
class TestExtractIocs:
    def test_mixed_text_extracts_all_fields(self):
        text = (
            "SSH brute-force from 203.0.113.42 to 10.0.0.5. "
            "Malware hash 44d88612fea8a8f36de82e1278abb02f (MD5). "
            "See https://evil.example.com/payload for detail. "
            "Related CVE-2023-38408 and domain c2-server.ru."
        )
        iocs = ie.extract_iocs(text)
        assert "203.0.113.42" in iocs["ips"]
        assert "10.0.0.5" in iocs["ips"]
        assert "44d88612fea8a8f36de82e1278abb02f" in iocs["hashes"]
        assert "CVE-2023-38408" in iocs["cves"]
        assert any("evil.example.com" in u for u in iocs["urls"])
        # 域名剔除了 URL 主机, 但保留独立域名
        assert "c2-server.ru" in iocs["domains"]
        assert all("evil.example.com" not in d for d in iocs["domains"])

    def test_dedup_preserves_order(self):
        text = "1.2.3.4 1.2.3.4 5.6.7.8 1.2.3.4"
        iocs = ie.extract_iocs(text)
        assert iocs["ips"] == ["1.2.3.4", "5.6.7.8"]

    def test_private_ip_filter(self):
        text = "attack from 8.8.8.8 and internal 192.168.1.10, 10.0.0.5"
        with_private = ie.extract_iocs(text, include_private_ips=True)
        without_private = ie.extract_iocs(text, include_private_ips=False)
        assert len(with_private["ips"]) == 3
        assert without_private["ips"] == ["8.8.8.8"]

    def test_hash_longest_first_no_double_count(self):
        sha256 = "a" * 64
        sha1 = "b" * 40
        md5 = "c" * 32
        text = f"{sha256} {sha1} {md5}"
        iocs = ie.extract_iocs(text)
        assert sha256 in iocs["hashes"]
        assert sha1 in iocs["hashes"]
        assert md5 in iocs["hashes"]
        # 每个哈希只出现一次 (64 位串不会截出 32 位双计)
        assert len(iocs["hashes"]) == 3

    def test_empty_text(self):
        iocs = ie.extract_iocs("")
        assert iocs == {"ips": [], "hashes": [], "domains": [], "cves": [], "urls": []}


# ============================================================
# compute_anomaly_score
# ============================================================
class TestAnomalyScore:
    def test_zero_when_no_iocs(self):
        assert ie.compute_anomaly_score({"ips": [], "hashes": [], "cves": [], "domains": []}) == 0.0

    def test_caps_per_category(self):
        # 10 个 IP 只能得 0.45 封顶
        iocs = {"ips": [f"1.2.3.{i}" for i in range(1, 11)], "hashes": [], "cves": [], "domains": []}
        score = ie.compute_anomaly_score(iocs)
        assert score == 0.45

    def test_clamp_to_1(self):
        iocs = {
            "ips": [f"1.2.3.{i}" for i in range(1, 11)],
            "hashes": ["a" * 32, "b" * 32, "c" * 32],
            "cves": ["CVE-2023-1", "CVE-2023-2", "CVE-2023-3"],
            "domains": ["a.com", "b.com", "c.com", "d.com"],
        }
        assert ie.compute_anomaly_score(iocs) == 1.0

    def test_three_decimals(self):
        iocs = {"ips": ["1.2.3.4"], "hashes": [], "cves": [], "domains": []}
        assert ie.compute_anomaly_score(iocs) == 0.15


# ============================================================
# classify_ips
# ============================================================
class TestClassifyIps:
    def test_attacker_context(self):
        text = "brute force from 203.0.113.42 targeting host"
        attacker, victim = ie.classify_ips(["203.0.113.42"], text)
        assert attacker == ["203.0.113.42"] and victim == []

    def test_victim_context(self):
        text = "attack landed on target host 10.0.0.5"
        attacker, victim = ie.classify_ips(["10.0.0.5"], text)
        assert victim == ["10.0.0.5"] and attacker == []

    def test_chinese_context(self):
        text = "检测到来自 203.0.113.42 的攻击, 受害主机 10.0.0.5"
        attacker, victim = ie.classify_ips(["203.0.113.42", "10.0.0.5"], text)
        assert "203.0.113.42" in attacker
        assert "10.0.0.5" in victim

    def test_no_context_defaults_to_attacker(self):
        text = "weird traffic 1.2.3.4"
        attacker, victim = ie.classify_ips(["1.2.3.4"], text)
        assert attacker == ["1.2.3.4"] and victim == []


# ============================================================
# enrich_iocs (mock 网络)
# ============================================================
class TestEnrichIocs:
    async def test_returns_formatted_snippets(self, monkeypatch):
        def fake_search(query, max_results):
            return [{"title": "t", "url": "http://s.example/x", "snippet": f"intel for {query}"}]

        monkeypatch.setattr(ti, "web_search", fake_search)
        iocs = {"ips": ["8.8.8.8"], "hashes": [], "cves": [], "domains": []}
        snippets = await ti.enrich_iocs(iocs)
        assert len(snippets) >= 1
        assert snippets[0].startswith("[8.8.8.8]")
        assert "(source: http://s.example/x)" in snippets[0]

    async def test_degrades_to_empty_on_failure(self, monkeypatch):
        def boom(query, max_results):
            raise RuntimeError("network down")

        monkeypatch.setattr(ti, "web_search", boom)
        iocs = {"ips": ["8.8.8.8"], "hashes": [], "cves": [], "domains": []}
        assert await ti.enrich_iocs(iocs) == []

    async def test_query_cap_8(self, monkeypatch):
        seen = []

        def fake_search(query, max_results):
            seen.append(query)
            return []

        monkeypatch.setattr(ti, "web_search", fake_search)
        iocs = {
            "ips": [f"1.2.3.{i}" for i in range(1, 12)],  # 11 个
            "hashes": [], "cves": [], "domains": [],
        }
        await ti.enrich_iocs(iocs)
        assert len(seen) == 8

    async def test_priority_cves_first(self, monkeypatch):
        seen = []

        def fake_search(query, max_results):
            seen.append(query)
            return []

        monkeypatch.setattr(ti, "web_search", fake_search)
        iocs = {
            "ips": ["9.9.9.9"],
            "hashes": ["a" * 32],
            "cves": ["CVE-2023-38408"],
            "domains": ["evil.example"],
        }
        await ti.enrich_iocs(iocs)
        # 查询词是 'threat intelligence {indicator}', 找回 indicator 的位置序
        order = [q.replace("threat intelligence ", "") for q in seen]
        assert order.index("CVE-2023-38408") < order.index("a" * 32) < order.index("9.9.9.9")


# ============================================================
# map_mitre
# ============================================================
class TestMapMitre:
    def test_static_mapping(self):
        assert ti.map_mitre("brute_force") == ["T1110"]

    def test_static_mapping_multiple(self):
        assert ti.map_mitre("privilege_escalation") == ["T1548", "T1068"]

    def test_unknown_type_empty(self):
        assert ti.map_mitre("unknown") == []
        assert ti.map_mitre("nonexistent_type") == []

    def test_regex_extraction_merge(self):
        result = ti.map_mitre("web_attack", "日志显示 T1190 与 T1133 利用痕迹")
        assert "T1190" in result
        assert "T1133" in result
        assert result.index("T1190") == 0  # 静态映射优先保序
