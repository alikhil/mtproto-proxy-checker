# MTProto Proxy Health Checker

Monitors MTProto proxy availability via Telethon handshake and sends Telegram alerts.
Based on [MKultra's MK_XRAYchecker](https://github.com/MKultra6969/MK_XRAYchecker). Supports standard, dd-obfuscated, and ee-FakeTLS secrets.

## Setup

```bash
cp .env.example .env   # fill in your values
docker-compose up -d
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `BOT_TOKEN` | Yes | — | Bot token from @BotFather |
| `CHAT_ID` | Yes | — | Chat ID for notifications |
| `PROXY_URL` | No* | — | Full proxy link (`tg://proxy?server=...&port=...&secret=...`) |
| `PROXY_HOST` | No* | — | Proxy hostname (if no `PROXY_URL`) |
| `PROXY_PORT` | No* | — | Proxy port (if no `PROXY_URL`) |
| `PROXY_SECRET` | No* | — | Proxy secret (if no `PROXY_URL`) |
| `CHECK_INTERVAL` | No | `300` | Seconds between checks (min 10) |

\*Either `PROXY_URL` or all three `PROXY_HOST`/`PORT`/`SECRET`.

To get your chat ID — send a message to the bot, then:

```bash
BOT_TOKEN=your_token python3 checker.py --get-chat-id
```

## License

MIT
