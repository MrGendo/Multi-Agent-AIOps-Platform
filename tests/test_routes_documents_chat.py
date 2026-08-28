"""documents / chat / skills 路由测试 (离线, service 层 mock).

重点: documents 是写操作 (上传→Milvus 入库 / 删除), 有 admin token 门禁 —
测试锁定: 未配置 token 时写操作必须 403 (锁死), token 不匹配 403,
合法 token 放行到 service. chat/skills 是读操作, 锁定基本契约.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

import app.services.document_service as doc_service


@pytest.fixture()
def client():
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def admin_token(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "kb_admin_token", "test-admin-token", raising=False)
    return "test-admin-token"


def _fake_upload_result(**over: Any) -> Dict[str, Any]:
    base = {"source": "test.md", "chunks_indexed": 3, "chars": 512}
    base.update(over)
    return base


# ============================================================
# documents: admin token 门禁 (写操作安全)
# ============================================================
def test_upload_locked_without_token_config(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "kb_admin_token", "", raising=False)
    resp = client.post("/api/v1/documents/upload", files={"file": ("a.md", "# hi", "text/markdown")})
    assert resp.status_code == 403
    assert "锁定" in resp.json()["detail"]


def test_upload_rejects_wrong_token(client, admin_token):
    resp = client.post(
        "/api/v1/documents/upload",
        files={"file": ("a.md", "# hi", "text/markdown")},
        headers={"X-KB-Admin-Token": "wrong-token"},
    )
    assert resp.status_code == 403


async def test_upload_accepts_valid_token(client, admin_token, monkeypatch):
    from app.schemas.document import UploadResponse

    calls: List[Dict[str, Any]] = []

    async def fake_upload(file):  # noqa: ANN001
        raw = await file.read()
        calls.append({"filename": file.filename, "size": len(raw)})
        return UploadResponse(source=file.filename or "", chunks_indexed=2, bytes=len(raw))

    monkeypatch.setattr(doc_service, "upload_document", fake_upload)
    resp = client.post(
        "/api/v1/documents/upload",
        files={"file": ("note.md", "# 标题\n正文", "text/markdown")},
        headers={"X-KB-Admin-Token": admin_token},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["chunks_indexed"] == 2
    assert calls[0]["filename"] == "note.md"


def test_delete_rejects_wrong_token(client, admin_token):
    resp = client.delete(
        "/api/v1/documents/x.md",
        headers={"X-KB-Admin-Token": "nope"},
    )
    assert resp.status_code == 403


async def test_delete_with_valid_token(client, admin_token, monkeypatch):
    monkeypatch.setattr(doc_service, "delete_document", lambda source: 4)
    resp = client.delete(
        "/api/v1/documents/x.md",
        headers={"X-KB-Admin-Token": admin_token},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["deleted_chunks"] == 4


async def test_list_documents_no_token_needed(client, monkeypatch):
    """读操作不应要求 admin token."""
    monkeypatch.setattr(
        doc_service,
        "list_documents",
        lambda: [{"source": "a.md", "chunk_count": 3}],
    )
    resp = client.get("/api/v1/documents")
    assert resp.status_code == 200
    assert resp.json()["data"]["documents"][0]["source"] == "a.md"


# ============================================================
# skills: 只读契约
# ============================================================
def test_list_skills_returns_registered(client):
    resp = client.get("/api/v1/skills")
    assert resp.status_code == 200
    items = resp.json()["data"]["items"] if "items" in str(resp.json()["data"]) else resp.json()["data"]
    names = {s["name"] for s in (items if isinstance(items, list) else items.get("skills", []))}
    assert "generic_oncall" in names
    # 沙箱工具在 generic_oncall 白名单里 (缺陷 4 修复的回归锁定)
    generic = [s for s in (items if isinstance(items, list) else items.get("skills", [])) if s["name"] == "generic_oncall"][0]
    assert "execute_python_script" in generic["allowed_tools"]


# ============================================================
# chat: 会话历史读/删 (memory service mock)
# ============================================================
async def test_chat_history_roundtrip(client, monkeypatch):
    import app.api.v1.chat as chat_mod

    store = {"sess-1": {"messages": [{"role": "user", "content": "hi"}]}}

    class FakeMemory:
        async def load_session(self, session_id: str):  # noqa: ANN101
            return store.get(session_id, {"messages": []})

        async def is_available(self):  # noqa: ANN101
            return True

        async def clear_session(self, session_id: str):  # noqa: ANN101
            return store.pop(session_id, None) is not None

    fake = FakeMemory()
    monkeypatch.setattr(chat_mod, "chat_memory", fake, raising=False)

    resp = client.get("/api/v1/chat/sessions/sess-1/history")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["memory_enabled"] is True
    assert body["messages"], "历史应返回"
    assert body["session_id"] == "sess-1"

    resp2 = client.delete("/api/v1/chat/sessions/sess-1")
    assert resp2.status_code == 200
    assert "sess-1" not in store
