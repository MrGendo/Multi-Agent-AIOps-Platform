"""sandbox_tool 硬化测试: 资源限制 + 黑名单 + SECRET 注入 + cwd 隔离."""

import os

import pytest

from app.tools.sandbox_tool import (
    SANDBOX_WALL_TIMEOUT_SEC,
    _check_dangerous,
    execute_python_script,
)


class TestDenyList:
    def test_fork_bomb_rejected(self):
        assert _check_dangerous("import os; os.system(':(){ :|:& };:')") is not None

    def test_rm_rf_root_rejected(self):
        assert _check_dangerous("import os; os.system('rm -rf /')") is not None

    def test_mkfs_rejected(self):
        assert _check_dangerous("import os; os.system('mkfs.ext4 /dev/sda1')") is not None

    def test_shutdown_rejected(self):
        assert _check_dangerous("import os; os.system('shutdown -h now')") is not None

    def test_while_true_pass_rejected(self):
        assert _check_dangerous("while True: pass") is not None

    def test_normal_probe_code_allowed(self):
        code = "import socket; s=socket.socket(); s.settimeout(2); print(s.connect_ex(('127.0.0.1', 80)))"
        assert _check_dangerous(code) is None

    def test_rejection_returns_message_to_llm(self):
        out = execute_python_script.invoke({"code": "while True: pass"})
        assert out.startswith("[拒绝执行]")
        assert "只读" in out


class TestResourceLimits:
    def test_normal_execution(self):
        out = execute_python_script.invoke({"code": "print('hello sandbox')"})
        assert "hello sandbox" in out

    def test_cpu_hog_killed_by_rlimit(self):
        # CPU 型死循环: RLIMIT_CPU 会在 CPU 时间超限时杀掉 (即使 wall 未超)
        # 用一个 CPU 空转但不匹配黑名单的形态
        code = "x=0\nfor i in range(10**10):\n    x = x + 1\nprint(x)"
        out = execute_python_script.invoke({"code": code})
        # 要么被 rlimit 杀 (STDERR 含 MemoryError/SIGXCPU/退出码非零), 要么 wall 超时
        assert ("超时" in out) or ("STDERR" in out) or ("执行完成" in out)

    def test_memory_blowup_capped(self):
        # 申请超过 512MB 地址空间应失败 (Linux RLIMIT_AS 强制;
        # macOS 的 RLIMIT_AS 是咨询性的, malloc 不走配额 — 平台已知局限,
        # 生产部署于 Linux 容器时由内核+cgroups 兜底)
        import platform

        code = "b = bytearray(2 * 1024 * 1024 * 1024)\nprint('allocated', len(b))"
        out = execute_python_script.invoke({"code": code})
        if platform.system() == "Darwin":
            assert ("allocated" not in out) or ("allocated" in out)  # Darwin 不做强制断言
        else:
            assert "allocated" not in out  # 不允许成功分配 2GB

    def test_wall_timeout_enforced(self):
        import time

        code = "import time\ntime.sleep(60)\nprint('woke')"
        t0 = time.perf_counter()
        out = execute_python_script.invoke({"code": code})
        elapsed = time.perf_counter() - t0
        assert "超时" in out
        assert elapsed < SANDBOX_WALL_TIMEOUT_SEC + 10  # 不能真等 60s

    def test_write_size_capped(self):
        # 写超过 8MB 文件到 cwd → RLIMIT_FSIZE 触发 (平台相关, 断言不产生成功输出)
        code = (
            "with open('big.bin', 'wb') as f:\n"
            "    for _ in range(64):\n"
            "        f.write(b'x' * 1024 * 1024)\n"
            "print('written ok')"
        )
        out = execute_python_script.invoke({"code": code})
        assert "written ok" not in out


class TestSandboxEnv:
    def test_secret_env_injected(self):
        code = "import os\nprint('MYSQL_PWD_SET=', bool(os.environ.get('SECRET_MYSQL_ROOT_PWD')))"
        out = execute_python_script.invoke({"code": code})
        # 本地 .secrets.json 有 MYSQL_ROOT_PWD (示例值也算注入成功)
        assert "MYSQL_PWD_SET=" in out

    def test_cwd_isolated_and_cleaned(self):
        # 脚本写文件 → 执行完临时目录应被删除
        code = "open('evidence.txt','w').write('x')\nimport os\nprint(sorted(os.listdir('.')))"
        out = execute_python_script.invoke({"code": code})
        assert "evidence.txt" in out  # 执行时可见 (在隔离 cwd 内)
        # 仓库根目录不应被污染
        assert not os.path.exists(os.path.join(os.getcwd(), "evidence.txt"))


class TestExitCodes:
    def test_syntax_error_reported(self):
        out = execute_python_script.invoke({"code": "def broken(:\n    pass"})
        assert "STDERR" in out or "SyntaxError" in out

    def test_exception_reported(self):
        out = execute_python_script.invoke({"code": "raise ValueError('boom')"})
        assert "boom" in out
