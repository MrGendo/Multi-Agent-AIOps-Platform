"""app.tools.sandbox_tool.execute_python_script 测试 (真实 subprocess, 安全代码).

覆盖: 正常输出 / stderr 回传 / 空输出 / SECRET_ 环境变量注入 / 超时路径.
超时用 monkeypatch 缩短 subprocess.run 的 timeout, 避免测试真的等 10 秒.
"""

from __future__ import annotations

import subprocess

import pytest

from app.tools import sandbox_tool
from app.tools.sandbox_tool import execute_python_script


def _run(code: str) -> str:
    # LangChain @tool 包装: .invoke({"code": ...})
    return execute_python_script.invoke({"code": code})


def test_normal_stdout():
    out = _run("print('hello sandbox')\nprint(1 + 1)")
    assert "hello sandbox" in out
    assert "2" in out


def test_stderr_appended():
    out = _run("import sys; print('to_stderr', file=sys.stderr)")
    assert "to_stderr" in out
    assert "[STDERR]" in out


def test_no_output_message():
    out = _run("x = 1")  # 无 print
    assert "执行完成" in out
    assert "退出码: 0" in out


def test_exception_traceback_returned():
    out = _run("raise ValueError('boom')")
    assert "ValueError" in out
    assert "boom" in out


def test_secret_env_injection(monkeypatch):
    # vault 是模块级单例, monkeypatch 其 get_all_secrets 返回假机密
    monkeypatch.setattr(
        sandbox_tool.vault,
        "get_all_secrets",
        lambda: {"MYSQL_ROOT_PWD": "s3cret_val", "REDIS_AUTH_TOKEN": "tok_abc"},
    )
    out = _run(
        "import os\n"
        "print(os.environ.get('SECRET_MYSQL_ROOT_PWD', 'MISSING'))\n"
        "print(os.environ.get('SECRET_REDIS_AUTH_TOKEN', 'MISSING'))"
    )
    assert "s3cret_val" in out
    assert "tok_abc" in out


def test_no_secret_prefix_for_plain_env(monkeypatch):
    monkeypatch.setattr(sandbox_tool.vault, "get_all_secrets", lambda: {})
    out = _run("import os; print('SECRET_X' in os.environ and 'HAS' or 'NONE')")
    assert "NONE" in out


def test_timeout_returns_friendly_message(monkeypatch):
    # 死循环脚本 + monkeypatch 把 10s 上限缩到 0.5s, 触发 TimeoutExpired 分支
    real_run = subprocess.run

    def fast_run(*args, **kwargs):
        kwargs["timeout"] = 0.5
        return real_run(*args, **kwargs)

    monkeypatch.setattr(sandbox_tool.subprocess, "run", fast_run)
    out = _run("import time; time.sleep(20)")
    assert "超时" in out


def test_temp_file_cleaned_up():
    import tempfile
    import os
    before = set(os.listdir(tempfile.gettempdir()))
    _run("print('cleanup check')")
    after = set(os.listdir(tempfile.gettempdir()))
    # 不应残留新的 .py 临时文件 (除并发测试的瞬时文件外, 断言无新增 sandbox 残留)
    new_py_files = [f for f in after - before if f.endswith(".py")]
    assert new_py_files == []


@pytest.mark.parametrize("code", ["print('a')", "for i in range(3): print(i)"])
def test_parametrized_smoke(code):
    out = _run(code)
    assert out.strip()
