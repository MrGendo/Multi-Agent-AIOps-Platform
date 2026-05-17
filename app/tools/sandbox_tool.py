"""本地沙箱代码执行工具 (Sandbox Tool).

提供一个受限环境供大模型动态编写并执行 Python 代码，用于常规工具无法覆盖的边缘场景探测。
"""

import os
import subprocess
import sys
import tempfile

from langchain_core.tools import tool
from loguru import logger

from app.core.secret_manager import vault


@tool
def execute_python_script(code: str) -> str:
    """在本地沙箱中动态执行 Python 脚本代码，并返回执行的控制台输出 (stdout / stderr)。
    
    【警告】
    只有当你用尽了系统现有的监控和日志工具仍无法拿到数据时，才允许使用此工具动态编写代码探测。
    例如针对未覆盖的特定端口、特定协议的 MQ 状态或特定业务接口。严禁重复造轮子。
    代码应保持只读，不应包含破坏性操作。
    """
    logger.info(f"[sandbox_tool] LLM 请求执行一段 python 代码 (长度 {len(code)})")
    
    temp_path = None
    try:
        # 使用 tempfile 保存生成的代码
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(code)
            temp_path = f.name
            
        # 构建包含机密的环境变量
        env = os.environ.copy()
        for k, v in vault.get_all_secrets().items():
            env[f"SECRET_{k}"] = v

        # 在独立的 subprocess 中执行当前机器的 python
        # 增加 timeout 限制，防止大模型写出死循环
        result = subprocess.run(
            [sys.executable, temp_path],
            capture_output=True,
            text=True,
            timeout=10,
            env=env
        )
        
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
