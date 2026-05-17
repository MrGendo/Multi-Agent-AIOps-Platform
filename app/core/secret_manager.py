"""机密保险箱 (Secret Vault).

用于安全地加载和提供机密数据（密码、Token 等）。
保证明文不会直接暴露给大模型，而是由底层执行器在运行时注入。
本 MVP 实现从根目录下的 `.secrets.json` 文件中读取机密。
"""

import json
import os
from typing import Dict, List

from loguru import logger

SECRETS_FILE = ".secrets.json"


class SecretVault:
    def __init__(self):
        self._secrets: Dict[str, str] = {}
        self._load_secrets()

    def _load_secrets(self):
        """加载机密"""
        if os.path.exists(SECRETS_FILE):
            try:
                with open(SECRETS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            self._secrets[k] = str(v)
                logger.info(f"[SecretVault] 成功从 {SECRETS_FILE} 加载 {len(self._secrets)} 个机密")
            except Exception as e:
                logger.error(f"[SecretVault] 解析 {SECRETS_FILE} 失败: {e}")
        else:
            # 如果文件不存在，自动创建一个示例文件
            example = {
                "MYSQL_ROOT_PWD": "example_password_123",
                "REDIS_AUTH_TOKEN": "example_redis_token"
            }
            try:
                with open(SECRETS_FILE, "w", encoding="utf-8") as f:
                    json.dump(example, f, indent=4)
                logger.info(f"[SecretVault] 创建了样例机密文件 {SECRETS_FILE}")
                for k, v in example.items():
                    self._secrets[k] = str(v)
            except Exception:
                pass

    def get_secret(self, key: str) -> str:
        """获取明文密码 (内部执行器使用)"""
        return self._secrets.get(key, "")

    def get_all_secrets(self) -> Dict[str, str]:
        """获取所有明文机密，用于沙箱环境变量注入"""
        return self._secrets.copy()

    def list_keys(self) -> List[str]:
        """仅返回可用机密的键名，供大模型工具使用"""
        return list(self._secrets.keys())


# 全局单例
vault = SecretVault()
