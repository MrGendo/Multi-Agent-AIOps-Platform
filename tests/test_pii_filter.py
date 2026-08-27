"""app/core/pii_filter.py 测试: 敏感数据脱敏."""

from app.core.pii_filter import sanitize, sanitize_mapping


class TestCredentialMasking:
    def test_mysql_password_in_url(self):
        out = sanitize("connect mysql://root:SuperSecret99@10.0.0.5:3306/db")
        assert "SuperSecret99" not in out
        assert "10.0.0." in out  # 网络段保留
        assert "3306" in out

    def test_password_kv_colon(self):
        out = sanitize("password: MyP@ssw0rd123")
        assert "MyP@ssw0rd123" not in out

    def test_password_kv_equals(self):
        out = sanitize("export DB_PASSWORD=hunter2hunter2")
        assert "hunter2hunter2" not in out

    def test_json_style(self):
        out = sanitize('{"api_key": "sk-abcdefgh1234567890"}')
        assert "sk-abcdefgh1234567890" not in out

    def test_api_key_prefix(self):
        out = sanitize("key is sk-abcdefghijklmnop12345678")
        assert "sk-abcdefghijklmnop12345678" not in out

    def test_aws_key(self):
        out = sanitize("creds AKIAIOSFODNN7EXAMPLE lost")
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "REDACTED" in out

    def test_jwt(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
        )
        out = sanitize(f"Authorization: Bearer {token}")
        assert token not in out

    def test_bearer_header(self):
        out = sanitize("Authorization: Bearer abc123def456ghi789xyz000")
        assert "abc123def456ghi789xyz000" not in out

    def test_secret_env_var(self):
        out = sanitize("SECRET_MYSQL_PASS=RealPasswordHere")
        assert "RealPasswordHere" not in out

    def test_private_key_block(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7x9z...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        out = sanitize(text)
        assert "MIIEpAIBAAKCAQEA7x9z" not in out


class TestIPMasking:
    def test_internal_ip_masked(self):
        out = sanitize("node 192.168.1.23 down")
        assert "192.168.1.23" not in out
        assert "192.168.1." in out

    def test_loopback_untouched(self):
        assert sanitize("listen on 127.0.0.1:9900") == "listen on 127.0.0.1:9900"

    def test_wildcard_untouched(self):
        assert sanitize("bind 0.0.0.0") == "bind 0.0.0.0"


class TestSafety:
    def test_empty_and_none(self):
        assert sanitize("") == ""

    def test_normal_text_unchanged(self):
        text = "CPU usage 92% on node-3, check process list"
        assert sanitize(text) == text

    def test_never_raises(self):
        # sanitize 对任何输入都不抛异常 (内部已兜底)
        assert isinstance(sanitize("x" * 100000), str)

    def test_sanitize_mapping(self):
        data = {"query": "login password: Str0ngPass!99", "nested": {"token": "abc123def456"}, "count": 5}
        out = sanitize_mapping(data)
        assert "Str0ngPass!99" not in out["query"]
        assert "abc123def456" not in out["nested"]["token"]
        assert out["count"] == 5
