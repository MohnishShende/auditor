"""
The `public` profile is what people paste into forums and AI assistants, so it must not
leak the hostname, IPv6 addresses or private (RFC 1918) IPv4 addresses. Found on a real host:
the hostname appeared hundreds of times in a "public" audit.json, in manifest.json (which
was never sanitized) and in the folder name; IPv6 addresses and 172.16.0.0/12 were unmasked.
"""

import json
from unittest.mock import patch

import pytest

from serveraudit.cli.audit import AuditOrchestrator, hostnames_to_mask
from serveraudit.core.sanitizer import Sanitizer, SanitizerConfig, SanitizationProfile


def _public(hosts=()):
    cfg = SanitizerConfig.from_profile(SanitizationProfile.PUBLIC)
    cfg.known_hostnames = set(hosts)
    return Sanitizer(cfg)


# ---------------------------------------------------------------- hostname

@pytest.mark.parametrize("text", [
    "nodezero",
    "Server: NodeZero.local",
    "/home/nodezero/.ssh",
    "audits/nodezero-2026-11-08T041819",
    "nodezero.example.com:8080",
    "user@nodezero",
])
def test_known_hostname_is_masked_everywhere_in_public_profile(text):
    out = _public({"nodezero"}).sanitize(text)
    assert "nodezero" not in out.lower()
    assert "[REDACTED_HOST]" in out


def test_hostname_is_masked_in_nested_data_and_other_text_is_untouched():
    data = {"metadata": {"hostname": "nodezero"}, "ssh": {"files": ["/etc/ssh/nodezero.conf"]},
            "note": "nodezeroish stays? no: part of a longer word", "other": "docker bridge"}
    out = _public({"nodezero"}).sanitize(data)
    assert out["metadata"]["hostname"] == "[REDACTED_HOST]"
    assert "nodezero" not in json.dumps(out["ssh"]).lower()
    assert out["other"] == "docker bridge"
    # a longer identifier that merely contains the name as a prefix is not a hostname hit
    assert "nodezeroish" in out["note"]


def test_generic_hostnames_are_never_masked():
    assert _public({"localhost"}).sanitize("connect to localhost:5432") == "connect to localhost:5432"


def test_private_profile_keeps_the_hostname():
    cfg = SanitizerConfig.from_profile(SanitizationProfile.PRIVATE)
    cfg.known_hostnames = {"nodezero"}
    assert Sanitizer(cfg).sanitize("nodezero") == "nodezero"


def test_hostnames_to_mask_includes_short_and_full_name_and_skips_generic():
    assert hostnames_to_mask("web01.corp.example") == {"web01.corp.example", "web01"}
    assert hostnames_to_mask("nodezero") == {"nodezero"}
    assert hostnames_to_mask("localhost") == set()
    assert hostnames_to_mask("") == set()


# -------------------------------------------------------------------- IPv6

@pytest.mark.parametrize("addr,first", [
    ("2001:db8:85a3::8a2e:370:7334", "2001"),
    ("fe80::1c2d:3eff:fe4f:5a6b", "fe80"),
    ("fd12:3456:789a::1", "fd12"),
    ("2a00:1450:4001:81b::200e", "2a00"),
])
def test_ipv6_addresses_are_masked_but_keep_the_first_group(addr, first):
    out = _public().sanitize(f"inet6 {addr}/64 scope global")
    assert addr not in out
    assert f"{first}:x:x:x:x:x:x:x/64" in out


def test_ipv6_with_zone_id_is_masked():
    out = _public().sanitize("fe80::1c2d:3eff:fe4f:5a6b%eno1")
    assert "1c2d" not in out and "%eno1" in out


@pytest.mark.parametrize("text", ["listening on ::1", "bind ::", "time 10:17:00", "Mon 12:30:45 UTC",
                                  "ratio 3:1", "std::string and a::b::c"])
def test_non_identifying_colon_text_is_left_alone(text):
    assert _public().sanitize(text) == text


def test_mac_addresses_are_still_masked_the_old_way_not_as_ipv6():
    assert _public().sanitize("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:xx:xx:xx"


def test_ipv6_is_not_masked_in_private_profile():
    cfg = SanitizerConfig.from_profile(SanitizationProfile.PRIVATE)
    assert Sanitizer(cfg).sanitize("fe80::1c2d:3eff:fe4f:5a6b") == "fe80::1c2d:3eff:fe4f:5a6b"


# ------------------------------------------------------------ 172.16.0.0/12

def test_rfc1918_172_range_is_masked_like_the_other_private_ranges():
    out = _public().sanitize("docker 172.17.0.2 gw 172.20.1.1 edge 172.31.255.254")
    assert "172.17.x.x" in out and "172.20.x.x" in out and "172.31.x.x" in out
    assert "0.2" not in out and "1.1" not in out


def test_172_outside_the_private_range_is_treated_as_public():
    assert _public().sanitize("172.32.0.1") == "xxx.xxx.xxx.xxx"


# ------------------------------------------------- whole bundle, end to end

def test_public_audit_bundle_does_not_contain_the_hostname(tmp_path):
    fake = "secret-host-01.corp.example"
    with patch("serveraudit.cli.audit.platform.node", return_value=fake):
        snap = AuditOrchestrator(profile="public", output_dir=str(tmp_path), quiet=True).run_audit()
    assert "secret-host-01" not in snap.name.lower()
    for f in snap.iterdir():
        if f.name == "checksums.sha256":
            continue
        assert "secret-host-01" not in f.read_text(encoding="utf-8").lower(), f.name
    assert json.loads((snap / "manifest.json").read_text())["hostname"] == "[REDACTED_HOST]"


def test_private_audit_bundle_keeps_the_hostname(tmp_path):
    fake = "secret-host-01.corp.example"
    with patch("serveraudit.cli.audit.platform.node", return_value=fake):
        snap = AuditOrchestrator(profile="private", output_dir=str(tmp_path), quiet=True).run_audit()
    assert "secret-host-01" in snap.name
    assert json.loads((snap / "manifest.json").read_text())["hostname"] == fake
