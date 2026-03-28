#!/usr/bin/env python3
"""
Test script for MTProto checker
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from checker import MTProtoChecker, TelegramNotifier, parse_proxy_url, _parse_secret


def test_mtproto_checker():
    """Test MTProtoChecker with invalid proxy"""
    print("Testing MTProtoChecker with invalid proxy...")

    checker = MTProtoChecker("invalid.host.example.com", 443, "0123456789abcdef0123456789abcdef")
    is_alive, error = asyncio.run(checker.check(timeout=3.0))

    assert not is_alive, "Invalid proxy should fail"
    assert error is not None, "Error message should be present"
    print(f"✓ MTProtoChecker correctly detected invalid proxy: {error}")


def test_secret_parsing():
    """Test secret type detection (mirrors MKultra's logic)"""
    print("Testing secret parsing...")

    mode, ts = _parse_secret("0123456789abcdef0123456789abcdef")
    assert mode == "standard", f"Expected standard, got {mode}"

    mode, ts = _parse_secret("dd0123456789abcdef0123456789abcdef")
    assert mode == "dd", f"Expected dd, got {mode}"

    mode, ts = _parse_secret("ee9b43b87555bf9464e02bdcd2db8932b07777772e736974652e636f6d")
    assert mode == "ee", f"Expected ee, got {mode}"
    assert ts == "9b43b87555bf9464e02bdcd2db8932b07777772e736974652e636f6d"

    print("✓ Secret parsing works correctly")


def test_telegram_notifier_validation():
    """Test TelegramNotifier instantiation"""
    print("Testing TelegramNotifier instantiation...")

    notifier = TelegramNotifier("test_token", "test_chat_id")
    assert notifier.bot_token == "test_token"
    assert notifier.chat_id == "test_chat_id"
    assert "test_token" in notifier.base_url

    print("✓ TelegramNotifier instantiation works")


def test_proxy_url_parsing():
    """Test PROXY_URL parsing"""
    print("Testing PROXY_URL parsing...")

    parsed, error = parse_proxy_url("tg://proxy?server=example.com&port=443&secret=dd00112233")
    assert error is None, f"Should parse valid tg:// URL, got error: {error}"
    assert parsed['host'] == 'example.com'
    assert parsed['port'] == 443
    assert parsed['secret'] == 'dd00112233'

    parsed, error = parse_proxy_url("https://t.me/proxy?server=test.com&port=8443&secret=ee001122")
    assert error is None, f"Should parse valid https:// URL, got error: {error}"
    assert parsed['host'] == 'test.com'
    assert parsed['port'] == 8443
    assert parsed['secret'] == 'ee001122'

    parsed, error = parse_proxy_url("t.me/proxy?server=test.com&port=443&secret=abc123")
    assert error is None, f"Should parse t.me URL, got error: {error}"
    assert parsed['host'] == 'test.com'

    parsed, error = parse_proxy_url("invalid://url")
    assert error is not None, "Should fail on invalid URL"

    parsed, error = parse_proxy_url("tg://proxy?server=test.com")
    assert error is not None, "Should fail on missing parameters"

    print("✓ PROXY_URL parsing works correctly")


def test_env_validation():
    """Test environment variable validation"""
    print("Testing environment validation...")

    import subprocess

    clean_env = {k: v for k, v in os.environ.items()
                 if k not in ['BOT_TOKEN', 'CHAT_ID', 'PROXY_HOST', 'PROXY_PORT', 'PROXY_SECRET', 'PROXY_URL']}

    result = subprocess.run(
        [sys.executable, 'checker.py'],
        capture_output=True,
        text=True,
        env=clean_env
    )

    assert result.returncode == 1, "Should exit with error when env vars missing"
    output = result.stdout + result.stderr
    assert ("Missing" in output or "Error" in output), f"Should show error message, got: {output}"

    print("✓ Environment validation works")


def _load_real_env():
    """Load .real.test.env if it exists. Returns dict or None."""
    env_path = os.path.join(os.path.dirname(__file__) or ".", ".real.test.env")
    if not os.path.isfile(env_path):
        return None
    values = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip()
    return values


def test_real_proxy():
    """Test against a real proxy defined in .real.test.env"""
    env = _load_real_env()
    if env is None:
        print("⏭  Skipped (no .real.test.env file)")
        return

    proxy_url = env.get("PROXY_URL", "")
    if not proxy_url or "CHANGE_ME" in proxy_url:
        print("⏭  Skipped (.real.test.env has placeholder values)")
        return

    print(f"Testing real proxy from .real.test.env ...")
    parsed, err = parse_proxy_url(proxy_url)
    assert err is None, f"Failed to parse PROXY_URL: {err}"

    checker = MTProtoChecker(parsed["host"], parsed["port"], parsed["secret"])
    is_alive, detail = asyncio.run(checker.check(timeout=10.0))

    print(f"  Host:   {parsed['host']}:{parsed['port']}")
    print(f"  Alive:  {is_alive}")
    if detail:
        print(f"  Detail: {detail}")

    assert is_alive, f"Real proxy should be alive, got: {detail}"
    print("✓ Real proxy is alive")


def main():
    """Run all tests"""
    print("=" * 60)
    print("MTProto Proxy Checker Tests")
    print("=" * 60)
    print()

    tests = [
        ("secret_parsing", test_secret_parsing),
        ("telegram_notifier", test_telegram_notifier_validation),
        ("proxy_url_parsing", test_proxy_url_parsing),
        ("env_validation", test_env_validation),
        ("invalid_proxy", test_mtproto_checker),
        ("real_proxy", test_real_proxy),
    ]

    failed = 0
    for name, test in tests:
        try:
            test()
            print()
        except Exception as e:
            print(f"✗ {name} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
            print()

    print("=" * 60)
    if failed == 0:
        print("All tests passed! ✓")
        return 0
    else:
        print(f"{failed} test(s) failed ✗")
        return 1


if __name__ == '__main__':
    sys.exit(main())
