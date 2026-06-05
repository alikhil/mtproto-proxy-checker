# Copilot instructions for mtproto-proxy-checker

## Project shape

- `checker.py` is the main entrypoint and contains the full runtime: proxy parsing, MTProto probing, Telegram notifications, and the CLI `main()`.
- `test_checker.py` is a standalone test harness with plain Python test functions; it is not pytest-based.
- `docker-compose.yml` runs a single `checker` service from `.env`.
- `Makefile` mirrors the common local and container workflows.

## Build, test, and run

- `make build` — build the Docker image.
- `make run` — start the checker with Docker Compose.
- `make stop` — stop the Compose stack.
- `make logs` — follow container logs.
- `make test` — run the full test script: `python3 test_checker.py`.
- `python3 test_checker.py` — run tests directly without Make.
- Single test function: `python3 -c "from test_checker import test_proxy_url_parsing; test_proxy_url_parsing()"`.
- `make get-chat-id` — run the chat-ID helper with `BOT_TOKEN` set.
- `make setup` — copy `.env.example` to `.env` if needed.
- `make validate-env` — quick environment check from the shell.
- No dedicated lint target is defined in this repo.

## Architecture

- The checker validates an MTProto proxy by performing a real Telethon connection through the proxy to Telegram DCs, not just a TCP port check.
- Proxy URLs are normalized in this order: `PROXY_URL` first, then `PROXY_HOST`/`PROXY_PORT`/`PROXY_SECRET`.
- Secret handling is mode-based:
  - `standard` for plain hex secrets
  - `dd` for dd-obfuscated secrets
  - `ee` for FakeTLS secrets
- `ee` mode depends on `mtproto_faketls`; if it is unavailable, the checker reports that explicitly.
- `HealthChecker` owns the periodic loop, alerting, recovery notifications, and daily reports.
- `TelegramNotifier` sends bot messages directly over HTTPS; it does not tunnel Telegram notifications through the proxy being checked.
- When Telethon is unavailable, the code falls back to a simple TCP connectivity check.

## Conventions

- Keep changes aligned with the existing single-file runtime style in `checker.py` unless a refactor is clearly needed.
- Preserve the current env-var contract:
  - required: `BOT_TOKEN`, `CHAT_ID`
  - proxy config: either `PROXY_URL` or all of `PROXY_HOST`, `PROXY_PORT`, `PROXY_SECRET`
  - optional: `PROXY_NAME`, `CHECK_INTERVAL`, `FAILURE_THRESHOLD`, `API_ID`, `API_HASH`, `DAILY_REPORT`
- `CHECK_INTERVAL` must stay at least 10 seconds; `FAILURE_THRESHOLD` must stay at least 1.
- `PROXY_PORT` is validated as an integer in the range 1-65535.
- `PROXY_NAME` should be shown in Telegram notifications when set, with `host:port` as the fallback display name.
- Tests are written as simple functions that print status and raise on failure; keep that style if adding coverage.
- Keep logging behavior quiet around Telethon and explicit for checker status transitions.
