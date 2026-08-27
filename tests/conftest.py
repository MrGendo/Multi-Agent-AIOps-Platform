"""全局测试夹具.

测试约定 (见 CLAUDE.md):
  - 全部离线: 不访问 LLM / Milvus / Redis / MCP / 网络
  - LLM 一律 mock (monkeypatch ainvoke_structured / get_chat_llm)
  - SecretVault 相关测试必须 monkeypatch.chdir(tmp_path), 防止在仓库根创建 .secrets.json
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_cwd(tmp_path, monkeypatch):
    """每个测试都在临时目录中运行, 防止副作用文件 (如 .secrets.json) 污染仓库.

    注意: app.core.secret_manager 在模块导入时就会创建全局 vault 单例,
    因此涉及 SecretVault 的测试需要在该 fixture 生效后重新构造实例.
    """
    monkeypatch.chdir(tmp_path)
    yield
