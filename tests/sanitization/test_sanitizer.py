"""
Sanitization and secret leak prevention tests for Linux Server Audit.
Deliberately injects realistic fake secrets and verifies zero leakage.
"""

import pytest
from serveraudit.core.sanitizer import Sanitizer, SanitizerConfig, SanitizationProfile

# Realistic deliberate fake secrets for security verification
FAKE_SECRETS = {
    "password": "SuperSecretPassword123!",
    "api_key": "sk_live_fake_secret_api_key_999999",
    "bearer_token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakepayload.fakesignature",
    "db_url": "postgres://admin_user:DatabasePasswordSecret99@10.0.0.5:5432/production_db",
    "redis_url": "redis://:SuperSecretRedisPass@127.0.0.1:6379/0",
    "private_key": """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3fakekeymaterialdeliberatefakeRSAsecret...
-----END RSA PRIVATE KEY-----""",
    "openssh_privkey": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----""",
    "argon2_hash": "$argon2id$v=19$m=65536,t=3,p=4$fakeHashMaterialForTesting$fakeHashValue",
    "sha512_hash": "$6$salt1234$fakeHashedShadowPasswordEntryMaterialStringForTest123",
}


def test_private_profile_secret_redaction():
    """Verify private profile redacts all credentials, tokens, URLs, and private keys."""
    sanitizer = Sanitizer(SanitizerConfig.from_profile(SanitizationProfile.PRIVATE))

    test_payload = {
        "server_name": "nodezero",
        "DATABASE_URL": FAKE_SECRETS["db_url"],
        "REDIS_URL": FAKE_SECRETS["redis_url"],
        "API_KEY": FAKE_SECRETS["api_key"],
        "config": {
            "DB_PASSWORD": FAKE_SECRETS["password"],
            "auth_header": f"Authorization: {FAKE_SECRETS['bearer_token']}",
            "embedded_ssh": FAKE_SECRETS["private_key"],
            "embedded_openssh": FAKE_SECRETS["openssh_privkey"],
            "shadow_entry": f"root:{FAKE_SECRETS['sha512_hash']}:19000:0:99999:7:::",
            "argon_entry": FAKE_SECRETS["argon2_hash"],
        },
        "env_vars": [
            f"POSTGRES_PASSWORD={FAKE_SECRETS['password']}",
            f"API_TOKEN={FAKE_SECRETS['api_key']}",
            "SAFE_VAR=hello_world",
        ],
    }

    sanitized = sanitizer.sanitize(test_payload)

    # Convert entire sanitized structure to string for comprehensive leakage search
    sanitized_str = str(sanitized)

    # Assert NO fake secret value is present in any form
    assert FAKE_SECRETS["password"] not in sanitized_str, "Cleartext password leaked!"
    assert FAKE_SECRETS["api_key"] not in sanitized_str, "API key leaked!"
    assert "DatabasePasswordSecret99" not in sanitized_str, "Database password leaked from URL!"
    assert "SuperSecretRedisPass" not in sanitized_str, "Redis password leaked from URL!"
    assert "fakepayload.fakesignature" not in sanitized_str, "Bearer token leaked!"
    assert "BEGIN RSA PRIVATE KEY" not in sanitized_str, "RSA private key leaked!"
    assert "BEGIN OPENSSH PRIVATE KEY" not in sanitized_str, "OpenSSH private key leaked!"
    assert FAKE_SECRETS["sha512_hash"] not in sanitized_str, "SHA512 password hash leaked!"
    assert FAKE_SECRETS["argon2_hash"] not in sanitized_str, "Argon2 password hash leaked!"

    # Verify non-secret safe content is preserved
    assert sanitized["server_name"] == "nodezero"
    assert "SAFE_VAR=hello_world" in sanitized["env_vars"]


def test_public_profile_ip_and_mac_masking():
    """Verify public/shareable profile masks internal IPs, MACs, and hardware serials."""
    sanitizer = Sanitizer(SanitizerConfig.from_profile(SanitizationProfile.PUBLIC))

    test_payload = {
        "hostname": "nodezero",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "private_ip": "192.168.1.15",
        "public_ip": "203.0.113.195",
        "serial_number": "WD-WCC4N0123456",
        "uuid": "4c4c4544-004a-4d10-8032-b2c04f4a3433",
        "nested": {
            "device": "/dev/sda",
            "serial": "SAMSUNGS59BNC0M123",
            "ip_route": "default via 192.168.1.1 dev eth0",
        },
    }

    sanitized = sanitizer.sanitize(test_payload)
    sanitized_str = str(sanitized)

    # Assert MAC address was masked
    assert "00:1A:2B:3C:4D:5E" not in sanitized_str
    assert "00:1A:2B:xx:xx:xx" in sanitized_str

    # Assert IP addresses were masked
    assert "192.168.1.15" not in sanitized_str
    assert "203.0.113.195" not in sanitized_str

    # Assert serial numbers and UUIDs were redacted
    assert "WD-WCC4N0123456" not in sanitized_str
    assert "SAMSUNGS59BNC0M123" not in sanitized_str
    assert "4c4c4544-004a-4d10-8032-b2c04f4a3433" not in sanitized_str
