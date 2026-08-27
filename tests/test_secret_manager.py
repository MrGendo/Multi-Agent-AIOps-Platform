"""app.core.secret_manager.SecretVault 测试.

注意: SecretVault 读取 cwd 下的 .secrets.json, 文件不存在时会自动创建样例.
conftest 的 autouse fixture 已把每个测试 chdir 到 tmp_path, 不会污染仓库.
"""

from __future__ import annotations

import json

from app.core.secret_manager import SecretVault


def test_load_existing_secrets(tmp_path):
    secrets_file = tmp_path / ".secrets.json"
    secrets_file.write_text(
        json.dumps({"MYSQL_ROOT_PWD": "p@ss", "REDIS_AUTH_TOKEN": "tok123"}),
        encoding="utf-8",
    )
    vault = SecretVault()
    assert vault.get_secret("MYSQL_ROOT_PWD") == "p@ss"
    assert vault.get_secret("REDIS_AUTH_TOKEN") == "tok123"
    assert set(vault.list_keys()) == {"MYSQL_ROOT_PWD", "REDIS_AUTH_TOKEN"}


def test_missing_file_creates_example(tmp_path):
    vault = SecretVault()
    # 自动创建样例文件并加载
    assert (tmp_path / ".secrets.json").exists()
    data = json.loads((tmp_path / ".secrets.json").read_text(encoding="utf-8"))
    assert "MYSQL_ROOT_PWD" in data
    assert "REDIS_AUTH_TOKEN" in data
    assert vault.get_secret("MYSQL_ROOT_PWD") == "example_password_123"


def test_get_secret_missing_key_returns_empty(tmp_path):
    vault = SecretVault()
    assert vault.get_secret("NO_SUCH_KEY") == ""


def test_get_all_secrets_returns_copy(tmp_path):
    (tmp_path / ".secrets.json").write_text(
        json.dumps({"A": "1"}), encoding="utf-8"
    )
    vault = SecretVault()
    all_secrets = vault.get_all_secrets()
    all_secrets["A"] = "mutated"
    assert vault.get_secret("A") == "1"  # 原值不受外部修改影响


def test_corrupt_json_degrades_gracefully(tmp_path):
    (tmp_path / ".secrets.json").write_text("{ not valid json !!", encoding="utf-8")
    vault = SecretVault()  # 不应抛异常
    assert vault.list_keys() == []


def test_non_dict_json_ignored(tmp_path):
    (tmp_path / ".secrets.json").write_text('["a", "b"]', encoding="utf-8")
    vault = SecretVault()
    assert vault.list_keys() == []


def test_values_coerced_to_str(tmp_path):
    (tmp_path / ".secrets.json").write_text(
        json.dumps({"PORT": 3306, "ENABLED": True}), encoding="utf-8"
    )
    vault = SecretVault()
    assert vault.get_secret("PORT") == "3306"
    assert vault.get_secret("ENABLED") == "True"
