"""本地沙箱代码执行工具 (Sandbox Tool) — 硬化版.

提供一个受限环境供大模型动态编写并执行 Python 代码，用于常规工具无法覆盖的边缘场景探测。

硬化措施 (工业级改造, 纵深防御):
  1. 资源硬限制 (POSIX rlimit, 子进程级, 经 preexec_fn 注入):
     - RLIMIT_CPU     10s   CPU 时间 (防死循环空转; 与 wall-clock timeout 互补)
     - RLIMIT_AS      512MB 地址空间 (防内存耗尽型攻击)
     - RLIMIT_FSIZE   8MB   可写文件大小 (防日志/磁盘填充)
     - RLIMIT_CORE    0     禁止 core dump
  2. 危险模式黑名单 (best-effort 静态检查, 明显破坏性的一行代码直接拒绝):
     fork 炸弹 / rm -rf / mkfs / dd 写块设备 / 关机重启 等
  3. 独立临时工作目录 (cwd 隔离, 用后即焚)
  4. SECRET_ 前缀环境变量注入 (SecretVault, 明文不进 LLM 上下文)
  5. wall-clock 超时 10s (原有, 保底)

已知局限 (诚实标注):
  - RLIMIT 在 macOS 上 RLIMIT_AS 可能不生效 (malloc 不走 mmap 配额),
    Linux 上完整生效; 生产部署建议 Linux 容器
  - 黑名单是纵深防御的一层, 不是完备的语义分析; 更强隔离 (Docker 只读
    容器 + cgroups) 是演进方向, 见 docs/
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional

from langchain_core.tools import tool
from loguru import logger

from app.core.secret_manager import vault

# ============================================================
# 资源限制配置
# ============================================================
SANDBOX_CPU_TIME_SEC = int(os.environ.get("AIOPS_SANDBOX_CPU_SEC", "10"))
SANDBOX_MEMORY_MB = int(os.environ.get("AIOPS_SANDBOX_MEM_MB", "512"))
SANDBOX_FSIZE_MB = int(os.environ.get("AIOPS_SANDBOX_FSIZE_MB", "8"))
SANDBOX_WALL_TIMEOUT_SEC = int(os.environ.get("AIOPS_SANDBOX_TIMEOUT_SEC", "10"))

# 危险模式黑名单 (正则; 命中即拒绝执行, 返回明确错误给 LLM 重写)
_DENY_PATTERNS = [
    (re.compile(r"while\s+True\s*:\s*pass"), "疑似 CPU 空转死循环"),
    (re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:&\s*\}\s*;?\s*:"), "疑似 fork 炸弹"),
    (re.compile(r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/\b"), "疑似递归删除根目录"),
    (re.compile(r"shutil\.rmtree\s*\(\s*[\"']/[\"']?\s*[,)]"), "疑似递归删除根目录"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "疑似格式化文件系统"),
    (re.compile(r"\bdd\b[^>]*of=/dev/(sd|hd|nvme|disk)"), "疑似块设备覆写"),
    (re.compile(r"\b(shutdown|halt|poweroff|reboot)\s*(-[a-z]+\s+)*(now|0)?\b"), "疑似关机/重启"),
    (re.compile(r"os\.system\s*\(\s*[\"'].*rm\s+-rf"), "疑似 shell 递归删除"),
]
_DENY_PATTERNS = [(p, msg) for p, msg in _DENY_PATTERNS if p]


def _check_dangerous(code: str) -> Optional[str]:
    """静态黑名单检查, 命中返回原因 (供 LLM 修正), 未命中返回 None."""
    for pattern, message in _DENY_PATTERNS:
        if pattern.search(code):
            return message
    return None


def _make_preexec():
    """构造子进程 preexec_fn: 注入 rlimit 硬限制 (仅 POSIX)."""
    import resource

    def _apply_limits():
        # CPU 时间 (软=硬, 超限 SIGXCPU/SIGKILL)
        resource.setrlimit(resource.RLIMIT_CPU, (SANDBOX_CPU_TIME_SEC, SANDBOX_CPU_TIME_SEC))
        # 地址空间 (MB → bytes); macOS 可能忽略, Linux 生效
        as_bytes = SANDBOX_MEMORY_MB * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
        except (ValueError, OSError):
            pass  # 某些平台不支持, 跳过 (其余限制仍生效)
        # 可写文件大小
        fs_bytes = SANDBOX_FSIZE_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fs_bytes, fs_bytes))
        # 禁 core dump
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _apply_limits


def _run_sandboxed_python(script_path: str, workdir: str) -> subprocess.CompletedProcess:
    """在资源限制下执行脚本, POSIX 走 preexec_fn, 其他平台退化为普通 subprocess."""
    env = os.environ.copy()
    for k, v in vault.get_all_secrets().items():
        env[f"SECRET_{k}"] = v

    preexec = _make_preexec() if os.name == "posix" else None
    if preexec is not None:
        return subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=SANDBOX_WALL_TIMEOUT_SEC,
            env=env,
            cwd=workdir,
            preexec_fn=preexec,
        )
    return subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        timeout=SANDBOX_WALL_TIMEOUT_SEC,
        env=env,
        cwd=workdir,
    )


@tool
def execute_python_script(code: str) -> str:
    """在本地沙箱中动态执行 Python 脚本代码，并返回执行的控制台输出 (stdout / stderr)。

    【沙箱约束】
    - CPU 时间上限 10 秒、内存上限 512MB、可写文件上限 8MB、总超时 10 秒。
    - 禁止破坏性操作（删根/格式化/fork炸弹等会被静态检查直接拒绝）。
    - 工作目录为一次性临时目录，脚本产物不会持久保留。

    【警告】
    只有当你用尽了系统现有的监控和日志工具仍无法拿到数据时，才允许使用此工具动态编写代码探测。
    例如针对未覆盖的特定端口、特定协议的 MQ 状态或特定业务接口。严禁重复造轮子。
    代码应保持只读，不应包含破坏性操作。
    """
    logger.info(f"[sandbox_tool] LLM 请求执行一段 python 代码 (长度 {len(code)})")

    # 1. 静态黑名单 (纵深防御第一层)
    deny_reason = _check_dangerous(code)
    if deny_reason:
        logger.warning(f"[sandbox_tool] 拒绝执行: {deny_reason}")
        return f"[拒绝执行] {deny_reason}。请只编写只读探测代码。"

    temp_path = None
    workdir = None
    try:
        # 2. 一次性工作目录 (cwd 隔离)
        workdir = tempfile.mkdtemp(prefix="aiops_sandbox_")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8", dir=workdir
        ) as f:
            f.write(code)
            temp_path = f.name

        # 3. 资源受限执行
        result = _run_sandboxed_python(temp_path, workdir)

        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR]:\n{result.stderr}"

        if not output.strip():
            return f"执行完成，退出码: {result.returncode}，无控制台输出。"

        return output.strip()
    except subprocess.TimeoutExpired:
        logger.warning("[sandbox_tool] 脚本执行超时！")
        return "执行失败：脚本运行超时（上限 10 秒），可能存在死循环或网络长时阻塞。"
    except Exception as e:
        logger.exception(f"[sandbox_tool] 执行报错: {e}")
        return f"执行内部失败：{type(e).__name__}: {e}"
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        if workdir and os.path.isdir(workdir):
            shutil.rmtree(workdir, ignore_errors=True)
