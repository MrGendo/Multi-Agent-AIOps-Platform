"""GET /api/v1/skills 与 /api/v1/skills/{name} 接口测试.

- 列表: 返回全部 Skill 元信息, 不含 playbook 全文
- 详情: 返回单个 Skill 含 playbook 全文; 未知 name 返回 404
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)  # 不带 with: 跳过 lifespan (API key / Milvus 连接)


def test_list_skills_returns_summaries_without_playbook():
    r = client.get("/api/v1/skills")
    assert r.status_code == 200
    body = r.json()
    assert body["code"] == "SUCCESS"
    skills = body["data"]["skills"]
    assert len(skills) >= 7  # 5 个初始 + database + k8s
    for s in skills:
        assert s["name"]
        assert s["display_name"]
        assert s["risk_level"] in ("low", "medium", "high")
        assert "playbook" not in s  # 列表不返回全文


def test_skill_detail_returns_playbook():
    r = client.get("/api/v1/skills/network_diagnosis")
    assert r.status_code == 200
    body = r.json()
    assert body["code"] == "SUCCESS"
    data = body["data"]
    assert data["name"] == "network_diagnosis"
    playbook = data["playbook"]
    assert isinstance(playbook, str) and len(playbook) > 100
    assert playbook.lstrip().startswith("#")  # Markdown 正文带标题


def test_skill_detail_404_for_unknown():
    r = client.get("/api/v1/skills/no_such_skill")
    assert r.status_code == 404
