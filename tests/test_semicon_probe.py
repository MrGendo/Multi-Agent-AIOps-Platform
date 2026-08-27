"""半导体探针 pytest 接入: 复用 scripts/verify_semicon_probe.py 作为单一事实来源.

以子进程方式执行验证脚本, 断言退出码 0; 失败时把脚本输出带进断言信息,
避免「测试红了但不知道哪项红」.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_semicon_probe.py"


def test_semicon_probe_verification_script_passes():
    assert SCRIPT.exists(), f"验证脚本缺失: {SCRIPT}"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"半导体探针验证失败 (exit={proc.returncode}):\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    # 全绿时应打出总结行
    assert "PASS: 全部断言通过" in proc.stdout
