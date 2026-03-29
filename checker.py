#!/usr/bin/env python3
"""
MTProto Proxy Health Checker

Checks MTProto proxy availability via real Telethon-based handshake
(based on MKultra's MK_XRAYchecker) and sends Telegram notifications.
"""

import asyncio
import json
import logging
import os
import re
import socket
import sys
import time
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Telethon imports (with graceful fallback)
# ---------------------------------------------------------------------------
try:
    from telethon import TelegramClient, connection, functions, utils
    from telethon.client.telegrambaseclient import (
        DEFAULT_DC_ID, DEFAULT_IPV4_IP, DEFAULT_IPV6_IP, DEFAULT_PORT,
    )
    from telethon.tl.alltlobjects import LAYER

    TELETHON_AVAILABLE = True
    TELETHON_IMPORT_ERROR = ""
except Exception as exc:
    TelegramClient = None
    connection = None
    functions = None
    utils = None
    DEFAULT_DC_ID = DEFAULT_IPV4_IP = DEFAULT_IPV6_IP = DEFAULT_PORT = LAYER = None
    TELETHON_AVAILABLE = False
    TELETHON_IMPORT_ERROR = str(exc)

try:
    from mtproto_faketls import ConnectionTcpMTProxyFakeTLS

    FAKETLS_AVAILABLE = True
    FAKETLS_IMPORT_ERROR = ""
except Exception as exc:
    ConnectionTcpMTProxyFakeTLS = None
    FAKETLS_AVAILABLE = False
    FAKETLS_IMPORT_ERROR = str(exc)

# ---------------------------------------------------------------------------
# Constants — mirrors MKultra's MK_XRAYchecker
# ---------------------------------------------------------------------------
HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]+$")
STANDARD_SECRET_HEX_LEN = 32
DD_SECRET_HEX_LEN = 34
DEFAULT_DC_PROBE_LIMIT = 3

TELEGRAM_DC_OPTIONS = [
    {"dc_id": 4, "host": "149.154.167.91", "port": 443},
    {"dc_id": 2, "host": "149.154.167.51", "port": 443},
    {"dc_id": 1, "host": "149.154.175.53", "port": 443},
    {"dc_id": 3, "host": "149.154.175.100", "port": 443},
    {"dc_id": 5, "host": "149.154.171.5", "port": 443},
]

# Public Telegram Desktop API credentials (used for probe only)
DEFAULT_API_ID = 2040
DEFAULT_API_HASH = "b18441a1ff607e10a989891a5462e627"

QUIET_TELETHON_LOGGER_NAME = "mtproto_proxy_checker.telethon"


# ---------------------------------------------------------------------------
# Telethon logging suppression (from MKultra)
# ---------------------------------------------------------------------------
def _setup_telethon_logging():
    for name in ("telethon", "telethon.network", "telethon.client", QUIET_TELETHON_LOGGER_NAME):
        logger = logging.getLogger(name)
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False
        logger.disabled = True
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Application logger
# ---------------------------------------------------------------------------
log = logging.getLogger("checker")
log.setLevel(logging.INFO)
if not log.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    log.addHandler(_handler)

if TELETHON_AVAILABLE:
    _setup_telethon_logging()


def _get_quiet_telethon_logger():
    logger = logging.getLogger(QUIET_TELETHON_LOGGER_NAME)
    logger.setLevel(logging.CRITICAL)
    logger.propagate = False
    logger.disabled = True
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    return logger


# ---------------------------------------------------------------------------
# Telegram Notifier
# ---------------------------------------------------------------------------
class TelegramNotifier:
    """Send messages via Telegram Bot API (direct HTTPS, no proxy)."""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"

    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        url = f"{self.base_url}/sendMessage"
        data = {"chat_id": self.chat_id, "text": text, "parse_mode": parse_mode}
        try:
            encoded_data = urlencode(data).encode("utf-8")
            req = Request(url, data=encoded_data, method="POST")
            with urlopen(req, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))
                return result.get("ok", False)
        except Exception as e:
            log.error("Failed to send Telegram message: %s", e)
            return False


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------
def parse_proxy_url(url: str) -> tuple[Optional[dict], Optional[str]]:
    """
    Parse MTProto proxy URL.
    Supports: tg://proxy?...  /  https://t.me/proxy?...  /  t.me/proxy?...
    Returns (proxy_dict, error_message).
    """
    url = url.strip()
    if url.lower().startswith("t.me/proxy?"):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if parsed.scheme == "tg":
            if parsed.netloc != "proxy":
                return None, "Invalid tg:// URL format"
        elif parsed.scheme in ("http", "https"):
            if parsed.netloc != "t.me" or parsed.path != "/proxy":
                return None, "Invalid https URL format"
        else:
            return None, "Unsupported URL scheme"

        params = parse_qs(parsed.query)
        server = params.get("server", [None])[0]
        port_str = params.get("port", [None])[0]
        secret = params.get("secret", [None])[0]

        if not server:
            return None, "Missing server parameter"
        if not port_str:
            return None, "Missing port parameter"
        if not secret:
            return None, "Missing secret parameter"

        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                return None, "Port out of range (1-65535)"
        except ValueError:
            return None, "Invalid port number"

        return {"host": server.strip(), "port": port, "secret": secret.strip()}, None
    except Exception as e:
        return None, f"Failed to parse URL: {e}"


# ---------------------------------------------------------------------------
# DC ranking helper (from MKultra)
# ---------------------------------------------------------------------------
def rank_telegram_dcs(timeout: float = 1.5, limit: int = DEFAULT_DC_PROBE_LIMIT):
    """Rank Telegram DCs by TCP connect latency."""
    ranked, fallback = [], []
    for dc in TELEGRAM_DC_OPTIONS:
        dc_copy = dict(dc)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((dc["host"], dc["port"]))
            dc_copy["probe_ms"] = round((time.perf_counter() - started) * 1000)
            ranked.append(dc_copy)
        except Exception:
            dc_copy["probe_ms"] = None
            fallback.append(dc_copy)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    ranked.sort(key=lambda d: d.get("probe_ms", 10**9))
    ordered = ranked + fallback
    return ordered[:limit] if limit and limit > 0 else ordered


# ---------------------------------------------------------------------------
# Secret parsing helper (from MKultra)
# ---------------------------------------------------------------------------
def _parse_secret(secret: str) -> tuple[str, str]:
    """Return (secret_mode, telethon_secret) for a hex secret string."""
    s = secret.lower()
    if len(s) == STANDARD_SECRET_HEX_LEN:
        mode = "standard"
        # Telethon strips dd/ee prefix — uppercase keeps the bytes intact
        telethon_secret = secret.upper() if s.startswith(("dd", "ee")) else s
    elif len(s) == DD_SECRET_HEX_LEN and s.startswith("dd"):
        mode = "dd"
        telethon_secret = secret.upper()
    elif len(s) > DD_SECRET_HEX_LEN and s.startswith("ee"):
        mode = "ee"
        telethon_secret = s[2:]
    else:
        mode = "unknown"
        telethon_secret = s
    return mode, telethon_secret


# ---------------------------------------------------------------------------
# Telethon probe helpers (from MKultra's _connect_sender_only / _invoke_probe)
# ---------------------------------------------------------------------------
async def _connect_sender_only(client, timeout, dc_candidate=None):
    """Low-level: connect the sender through the proxy to a given DC."""
    if dc_candidate:
        await utils.maybe_async(
            client.session.set_dc(
                int(dc_candidate["dc_id"]),
                str(dc_candidate["host"]),
                int(dc_candidate["port"]),
            )
        )
        await utils.maybe_async(client.session.save())
    elif (
        not client.session.server_address
        or (":" in client.session.server_address) != client._use_ipv6
    ):
        await utils.maybe_async(
            client.session.set_dc(
                DEFAULT_DC_ID,
                DEFAULT_IPV6_IP if client._use_ipv6 else DEFAULT_IPV4_IP,
                DEFAULT_PORT,
            )
        )
        await utils.maybe_async(client.session.save())

    conn = client._connection(
        client.session.server_address,
        client.session.port,
        client.session.dc_id,
        loggers=client._log,
        proxy=client._proxy,
        local_addr=client._local_addr,
    )
    await asyncio.wait_for(client._sender.connect(conn), timeout=timeout)
    client.session.auth_key = client._sender.auth_key
    await utils.maybe_async(client.session.save())


async def _invoke_probe_request(client, timeout):
    """Send GetConfigRequest through the proxy to verify full MTProto path."""
    client.session.auth_key = client._sender.auth_key
    await utils.maybe_async(client.session.save())

    client._init_request.query = functions.help.GetConfigRequest()
    request = client._init_request
    if client._no_updates:
        request = functions.InvokeWithoutUpdatesRequest(request)

    return await asyncio.wait_for(
        client._sender.send(functions.InvokeWithLayerRequest(LAYER, request)),
        timeout=timeout,
    )


def _format_probe_error(exc):
    msg = str(exc).strip()
    return f"{exc.__class__.__name__}: {msg}" if msg else exc.__class__.__name__


# ---------------------------------------------------------------------------
# MTProtoChecker — Telethon-based, mirrors MKultra's _probe_mtproto_async
# ---------------------------------------------------------------------------
class MTProtoChecker:
    """
    Check MTProto proxy by establishing a real Telethon connection
    through it to a Telegram DC, exactly like MKultra's MK_XRAYchecker.

    Supports standard, dd-obfuscated, and ee-FakeTLS secrets.
    """

    def __init__(self, host: str, port: int, secret: str,
                 api_id: int = DEFAULT_API_ID,
                 api_hash: str = DEFAULT_API_HASH):
        self.host = host
        self.port = port
        self.secret = secret.strip()
        self.api_id = api_id
        self.api_hash = api_hash

        self.secret_mode, self.telethon_secret = _parse_secret(self.secret)

    # ----- transport selection (MKultra's _build_connection_candidates) -----

    def _build_connection_candidates(self):
        if self.secret_mode == "ee":
            if FAKETLS_AVAILABLE and ConnectionTcpMTProxyFakeTLS:
                return [("faketls", ConnectionTcpMTProxyFakeTLS)]
            return []
        if self.secret_mode == "dd":
            return [
                ("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate),
                ("intermediate", connection.ConnectionTcpMTProxyIntermediate),
                ("abridged", connection.ConnectionTcpMTProxyAbridged),
            ]
        return [
            ("intermediate", connection.ConnectionTcpMTProxyIntermediate),
            ("abridged", connection.ConnectionTcpMTProxyAbridged),
            ("randomized", connection.ConnectionTcpMTProxyRandomizedIntermediate),
        ]

    # ----- async probe (mirrors MKultra's _probe_mtproto_async) -----

    async def _probe_async(self, timeout: float, dc_candidates):
        candidates = self._build_connection_candidates()
        if not candidates:
            reason = "FakeTLS backend unavailable"
            if FAKETLS_IMPORT_ERROR:
                reason += f": {FAKETLS_IMPORT_ERROR}"
            return False, reason

        best_connect_only_error = None
        last_error = "Unknown error"

        for dc in dc_candidates:
            dc_id = dc.get("dc_id")
            for transport_name, conn_cls in candidates:
                client = TelegramClient(
                    None,
                    self.api_id,
                    self.api_hash,
                    connection=conn_cls,
                    proxy=(self.host, self.port, self.telethon_secret),
                    timeout=timeout,
                    request_retries=0,
                    connection_retries=0,
                    retry_delay=0,
                    auto_reconnect=False,
                    receive_updates=False,
                    sequential_updates=False,
                    device_model="MTProtoProxyChecker",
                    app_version="health-check",
                    system_version="python",
                    lang_code="en",
                    system_lang_code="en",
                    base_logger=_get_quiet_telethon_logger(),
                )

                try:
                    await _connect_sender_only(client, timeout, dc_candidate=dc)
                    if not client.is_connected():
                        last_error = f"dc{dc_id}/{transport_name}: Disconnected after connect"
                        continue

                    try:
                        await _invoke_probe_request(client, timeout)
                        return True, None  # LIVE
                    except Exception as exc:
                        best_connect_only_error = (
                            f"dc{dc_id}/{transport_name}: {_format_probe_error(exc)}"
                        )
                        last_error = best_connect_only_error
                except asyncio.TimeoutError:
                    last_error = f"dc{dc_id}/{transport_name}: Timeout"
                except Exception as exc:
                    last_error = f"dc{dc_id}/{transport_name}: {_format_probe_error(exc)}"
                finally:
                    try:
                        await client.disconnect()
                        await asyncio.sleep(0)
                    except Exception:
                        pass

        # Connected to proxy but couldn't complete RPC — still counts as alive
        if best_connect_only_error is not None:
            return True, f"connect_only: {best_connect_only_error}"

        return False, last_error

    # ----- public API -----

    async def check(self, timeout: float = 5.0) -> tuple[bool, Optional[str]]:
        """
        Check if the proxy is alive.

        Returns (is_alive, error_or_warning).
        Requires Telethon; falls back to simple TCP if unavailable.
        """
        if not TELETHON_AVAILABLE:
            return self._check_tcp_fallback(timeout)

        dc_candidates = rank_telegram_dcs(timeout=min(timeout, 1.5))
        if not dc_candidates:
            dc_candidates = TELEGRAM_DC_OPTIONS[:DEFAULT_DC_PROBE_LIMIT]

        return await self._probe_async(timeout, dc_candidates)

    # Simple TCP fallback when Telethon is not installed
    def _check_tcp_fallback(self, timeout: float) -> tuple[bool, Optional[str]]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))
            return True, "tcp_only (install telethon for full probe)"
        except socket.timeout:
            return False, "Connection timeout"
        except socket.gaierror:
            return False, "DNS resolution failed"
        except ConnectionRefusedError:
            return False, "Connection refused"
        except ConnectionResetError:
            return False, "Connection reset by proxy"
        except OSError as e:
            return False, f"Network error: {e}"
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass


class HealthChecker:
    """Main health checker with periodic monitoring and notifications."""

    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        proxy_secret: str,
        bot_token: str,
        chat_id: str,
        check_interval: int = 300,
        daily_report: bool = True,
        failure_threshold: int = 1,
        api_id: int = DEFAULT_API_ID,
        api_hash: str = DEFAULT_API_HASH,
    ):
        self.checker = MTProtoChecker(proxy_host, proxy_port, proxy_secret, api_id, api_hash)
        self.notifier = TelegramNotifier(bot_token, chat_id)
        self.check_interval = check_interval
        self.daily_report_enabled = daily_report
        self.failure_threshold = max(1, failure_threshold)
        self.chat_id = chat_id

        self.proxy_display = f"{proxy_host}:{proxy_port}"
        self.is_down = False
        self.last_daily_report = datetime.now() - timedelta(days=1)
        self.consecutive_failures = 0
        self.total_checks = 0
        self.failed_checks = 0
        self.start_time = datetime.now()

    def format_uptime(self) -> str:
        """Format uptime duration"""
        uptime = datetime.now() - self.start_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")

        return " ".join(parts) if parts else "0m"

    def send_down_alert(self, error: str):
        """Send alert when proxy goes down"""
        message = (
            f"🔴 <b>Proxy Down Alert</b>\n\n"
            f"<b>Proxy:</b> <code>{self.proxy_display}</code>\n"
            f"<b>Error:</b> {error}\n"
            f"<b>Consecutive failures:</b> {self.consecutive_failures}\n"
            f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.notifier.send_message(message)

    def send_recovery_alert(self):
        """Send alert when proxy recovers"""
        message = (
            f"🟢 <b>Proxy Recovered</b>\n\n"
            f"<b>Proxy:</b> <code>{self.proxy_display}</code>\n"
            f"<b>Downtime:</b> {self.consecutive_failures * self.check_interval // 60} minutes\n"
            f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.notifier.send_message(message)

    def send_daily_report(self):
        """Send daily health report"""
        uptime_pct = 0.0
        if self.total_checks > 0:
            uptime_pct = ((self.total_checks - self.failed_checks) / self.total_checks) * 100

        status_emoji = "🟢" if not self.is_down else "🔴"
        status_text = "Online" if not self.is_down else "Offline"

        message = (
            f"📊 <b>Daily Health Report</b>\n\n"
            f"<b>Proxy:</b> <code>{self.proxy_display}</code>\n"
            f"<b>Status:</b> {status_emoji} {status_text}\n"
            f"<b>Uptime:</b> {uptime_pct:.2f}%\n"
            f"<b>Total checks:</b> {self.total_checks}\n"
            f"<b>Failed checks:</b> {self.failed_checks}\n"
            f"<b>Monitor uptime:</b> {self.format_uptime()}\n"
            f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.notifier.send_message(message)

    async def run_check(self):
        """Perform a single health check."""
        self.total_checks += 1
        is_alive, error = await self.checker.check()

        if not is_alive:
            self.failed_checks += 1
            self.consecutive_failures += 1

            # Send alert if proxy just went down (after threshold consecutive failures)
            if not self.is_down and self.consecutive_failures >= self.failure_threshold:
                self.is_down = True
                self.send_down_alert(error or "Unknown error")
                log.warning("Proxy DOWN: %s", error)
            elif not self.is_down:
                log.info("Proxy check failed (%d/%d): %s", self.consecutive_failures, self.failure_threshold, error)
            else:
                log.info("Proxy still down: %s (failures: %d)", error, self.consecutive_failures)
        else:
            # Send recovery alert if proxy was down
            if self.is_down:
                self.is_down = False
                self.send_recovery_alert()
                log.info("Proxy RECOVERED after %d failures", self.consecutive_failures)
            else:
                log.info("Proxy OK")

            self.consecutive_failures = 0

    async def run(self):
        """Main monitoring loop"""
        log.info("Starting health checker for %s", self.proxy_display)
        log.info("Check interval: %d seconds, failure threshold: %d", self.check_interval, self.failure_threshold)

        # Send startup notification
        message = (
            f"✅ <b>Health Checker Started</b>\n\n"
            f"<b>Proxy:</b> <code>{self.proxy_display}</code>\n"
            f"<b>Check interval:</b> {self.check_interval}s ({self.check_interval // 60} minutes)\n"
            f"<b>Failure threshold:</b> {self.failure_threshold}\n"
            f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.notifier.send_message(message)

        while True:
            try:
                # Perform health check
                await self.run_check()

                # Check if we need to send daily report
                now = datetime.now()
                if self.daily_report_enabled and (now - self.last_daily_report).total_seconds() >= 86400:
                    self.send_daily_report()
                    self.last_daily_report = now

                # Wait for next check
                await asyncio.sleep(self.check_interval)

            except KeyboardInterrupt:
                log.info("Shutting down...")
                break
            except Exception as e:
                log.error("Error in monitoring loop: %s", e)
                await asyncio.sleep(self.check_interval)


def get_chat_id(bot_token: str):
    """Helper to retrieve chat ID by sending a message to the bot"""
    print("=" * 60)
    print("Chat ID Retriever")
    print("=" * 60)
    print("\n1. Open Telegram and find your bot")
    print("2. Send any message to the bot")
    print("3. This script will fetch the chat ID\n")

    input("Press Enter when you've sent a message to the bot...")

    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"

    try:
        req = Request(url)
        with urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))

            if not data.get('ok'):
                print(f"Error: {data.get('description', 'Unknown error')}")
                return

            updates = data.get('result', [])
            if not updates:
                print("No messages found. Please send a message to the bot and try again.")
                return

            # Get the most recent message
            latest = updates[-1]
            chat = latest.get('message', {}).get('chat', {})
            chat_id = chat.get('id')
            chat_type = chat.get('type')
            chat_title = chat.get('title') or chat.get('first_name') or 'Unknown'

            print("\n" + "=" * 60)
            print("Found Chat ID!")
            print("=" * 60)
            print(f"Chat ID: {chat_id}")
            print(f"Chat Type: {chat_type}")
            print(f"Chat Name: {chat_title}")
            print("\nAdd this to your .env file:")
            print(f"CHAT_ID={chat_id}")
            print("=" * 60)

    except URLError as e:
        print(f"Network error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='MTProto Proxy Health Checker')
    parser.add_argument('--get-chat-id', action='store_true',
                       help='Helper to retrieve chat ID from bot')

    args = parser.parse_args()

    # Load environment variables
    bot_token = os.getenv('BOT_TOKEN')

    if args.get_chat_id:
        if not bot_token:
            log.error("BOT_TOKEN environment variable not set")
            sys.exit(1)
        get_chat_id(bot_token)
        return

    # Load environment variables
    chat_id = os.getenv('CHAT_ID')
    proxy_url = os.getenv('PROXY_URL')
    proxy_host = os.getenv('PROXY_HOST')
    proxy_port = os.getenv('PROXY_PORT')
    proxy_secret = os.getenv('PROXY_SECRET')
    check_interval = os.getenv('CHECK_INTERVAL', '300')

    # Parse proxy configuration
    if proxy_url:
        # PROXY_URL takes precedence
        parsed_proxy, error = parse_proxy_url(proxy_url)
        if error:
            log.error("Failed to parse PROXY_URL: %s", error)
            log.error("URL: %s", proxy_url)
            sys.exit(1)
        proxy_host = parsed_proxy['host']
        proxy_port = parsed_proxy['port']
        proxy_secret = parsed_proxy['secret']
    else:
        # Fall back to individual PROXY_HOST/PORT/SECRET
        missing = []
        if not proxy_host:
            missing.append('PROXY_HOST')
        if not proxy_port:
            missing.append('PROXY_PORT')
        if not proxy_secret:
            missing.append('PROXY_SECRET')

        if missing:
            log.error("Either PROXY_URL or all of PROXY_HOST, PROXY_PORT, PROXY_SECRET must be set")
            log.error("Missing variables: %s", ", ".join(missing))
            log.info("Example: PROXY_URL=tg://proxy?server=example.com&port=443&secret=ee00000...")
            sys.exit(1)

        # Validate port when using individual settings
        try:
            proxy_port = int(proxy_port)
            if proxy_port < 1 or proxy_port > 65535:
                raise ValueError()
        except ValueError:
            log.error("Invalid PROXY_PORT '%s'. Must be 1-65535", proxy_port)
            sys.exit(1)

    # Validate other required vars
    missing = []
    if not bot_token:
        missing.append('BOT_TOKEN')
    if not chat_id:
        missing.append('CHAT_ID')

    if missing:
        log.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(1)

    # Validate check interval
    try:
        interval = int(check_interval)
        if interval < 10:
            raise ValueError()
    except ValueError:
        log.error("Invalid CHECK_INTERVAL '%s'. Must be >= 10 seconds", check_interval)
        sys.exit(1)

    # Validate failure threshold
    failure_threshold_str = os.getenv('FAILURE_THRESHOLD', '1')
    try:
        failure_threshold = int(failure_threshold_str)
        if failure_threshold < 1:
            raise ValueError()
    except ValueError:
        log.error("Invalid FAILURE_THRESHOLD '%s'. Must be >= 1", failure_threshold_str)
        sys.exit(1)

    # Create and run health checker
    api_id = int(os.getenv('API_ID', str(DEFAULT_API_ID)))
    api_hash = os.getenv('API_HASH', DEFAULT_API_HASH)
    daily_report = os.getenv('DAILY_REPORT', '1').lower() not in ('0', 'false', 'no', 'off')

    checker = HealthChecker(
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_secret=proxy_secret,
        bot_token=bot_token,
        chat_id=chat_id,
        check_interval=interval,
        daily_report=daily_report,
        failure_threshold=failure_threshold,
        api_id=api_id,
        api_hash=api_hash,
    )

    try:
        asyncio.run(checker.run())
    except KeyboardInterrupt:
        log.info("Shutdown complete")


if __name__ == '__main__':
    main()
