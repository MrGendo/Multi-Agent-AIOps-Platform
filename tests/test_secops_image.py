"""图片证据模块离线单测."""

from __future__ import annotations

import base64

import pytest

from app.security import image_evidence as ie


def _tiny_png_b64() -> str:
    return base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 40).decode()


class TestValidate:
    def test_ok_png(self):
        ok, err = ie.validate_image_b64(_tiny_png_b64(), "image/png")
        assert ok, err

    def test_unsupported_mime(self):
        ok, err = ie.validate_image_b64(_tiny_png_b64(), "image/bmp")
        assert not ok and "不支持" in err

    def test_too_large(self):
        ok, err = ie.validate_image_b64("A" * (ie._MAX_B64_LEN + 1), "image/png")
        assert not ok and "过大" in err

    def test_bad_base64(self):
        ok, err = ie.validate_image_b64("!!!not-base64!!!", "image/png")
        assert not ok and "base64" in err

    def test_empty(self):
        ok, _ = ie.validate_image_b64("", "image/png")
        assert not ok


class TestExtract:
    async def test_extract_success(self, monkeypatch):
        async def fake_ainvoke(messages):
            class R:
                content = [{"type": "text", "text": "WAF 拦截记录: 源 1.2.3.4 SQL 注入"}]
            return R()

        class FakeLLM:
            async def ainvoke(self, messages):
                return await fake_ainvoke(messages)

        monkeypatch.setattr(ie, "get_chat_llm", lambda **kw: FakeLLM())
        out = await ie.extract_image_evidence(_tiny_png_b64(), note="WAF 截图")
        assert "WAF" in out and "1.2.3.4" in out

    async def test_extract_thinking_blocks_filtered(self, monkeypatch):
        async def fake_ainvoke(messages):
            class R:
                content = [
                    {"type": "thinking", "thinking": "internal"},
                    {"type": "text", "text": "转写结果"},
                ]
            return R()

        class FakeLLM:
            async def ainvoke(self, messages):
                return await fake_ainvoke(messages)

        monkeypatch.setattr(ie, "get_chat_llm", lambda **kw: FakeLLM())
        out = await ie.extract_image_evidence(_tiny_png_b64())
        assert out == "转写结果"

    async def test_extract_fail_soft(self, monkeypatch):
        def boom(**kw):
            raise RuntimeError("LLM down")

        monkeypatch.setattr(ie, "get_chat_llm", boom)
        assert await ie.extract_image_evidence(_tiny_png_b64()) == ""
