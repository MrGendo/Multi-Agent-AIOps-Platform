"""钥匙链工具 (Keychain Tool).

向大模型暴露当前系统支持的机密变量名列表，但不暴露任何明文。
"""

from typing import List

from langchain_core.tools import tool

from app.core.secret_manager import vault


@tool
def list_available_secrets() -> List[str]:
    """查看当前系统提供了哪些机密(账号/密码)的环境变量名。

    当你需要动态编写 Python 探测脚本连接数据库、Redis 或其他需要密码的组件时，
    请先使用此工具获取支持的变量名（如 MYSQL_ROOT_PWD），
    然后在代码中使用 os.environ.get("SECRET_MYSQL_ROOT_PWD") 获取密码（注意自动补充前缀 SECRET_），
    绝对不允许在代码中硬编码猜测的密码！
    """
    keys = vault.list_keys()
    if not keys:
        return ["当前系统没有配置任何机密凭据。"]
    return keys
