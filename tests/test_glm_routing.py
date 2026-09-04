"""GLM (智谱) 模型路由测试: 模型名 glm* 前缀 → bigmodel base_url + key.

与 DeepSeek 路由同构. 离线: 只验证 ChatOpenAI 构造参数, 不发请求.
"""

from __future__ import annotations

import pytest

from app.config import settings
from app.core.llm import get_chat_llm


def test_glm_model_routes_to_bigmodel(monkeypatch):
    monkeypatch.setattr(settings, "glm_api_key", "test-glm-key", raising=False)
    monkeypatch.setattr(settings, "glm_use_coding_plan", False, raising=False)
    monkeypatch.setattr(settings, "dashscope_api_key", "ds-key", raising=False)

    llm = get_chat_llm(model="glm-4.7", temperature=0)
    assert llm.model_name == "glm-4.7"
    # base_url 指向智谱
    assert "bigmodel.cn" in str(llm.openai_api_base)
    # key 用 GLM 的, 不是 DashScope 的
    assert "ds-key" not in str(llm.openai_api_key.get_secret_value())


def test_glm_case_insensitive_prefix(monkeypatch):
    monkeypatch.setattr(settings, "glm_api_key", "k", raising=False)
    monkeypatch.setattr(settings, "glm_use_coding_plan", False, raising=False)
    llm = get_chat_llm(model="GLM-4.7-Flash")
    assert "bigmodel.cn" in str(llm.openai_api_base)


def test_glm_streaming_sets_stream_usage(monkeypatch):
    monkeypatch.setattr(settings, "glm_api_key", "k", raising=False)
    monkeypatch.setattr(settings, "glm_use_coding_plan", False, raising=False)
    llm = get_chat_llm(model="glm-4.7", streaming=True)
    assert llm.stream_usage is True


def test_non_glm_model_still_dashscope(monkeypatch):
    """回归: 非 glm 前缀模型不受影响, 仍走 DashScope."""
    monkeypatch.setattr(settings, "glm_api_key", "glm-key", raising=False)
    monkeypatch.setattr(settings, "glm_use_coding_plan", False, raising=False)
    monkeypatch.setattr(settings, "dashscope_api_key", "ds-key", raising=False)
    monkeypatch.setattr(settings, "dashscope_base_url", "https://dashscope.example/v1", raising=False)

    llm = get_chat_llm(model="qwen-max")
    assert "dashscope.example" in str(llm.openai_api_base)


def test_missing_glm_key_warns_not_raises(monkeypatch):
    """key 未配置: warning + 继续构造 (与 DeepSeek 路由行为一致), 请求时才 401."""
    monkeypatch.setattr(settings, "glm_api_key", "", raising=False)
    llm = get_chat_llm(model="glm-4.7")  # 不抛
    assert llm is not None
