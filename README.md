# SimpleProxy

Forward HTTP CONNECT-прокси для Telegram Bot API (`api.telegram.org`) на Node.js.
Разработан для обхода блокировки `api.telegram.org` из РФ, разворачивается на бесплатном
хостинге [Wispbyte](https://wispbyte.com) (1 vCPU 35%, 512 MB RAM, 1 GB диск).

**Ключевые свойства:**

- **Ноль внешних зависимостей** — только встроенные модули Node.js (`node:http`, `node:net`, `node:crypto`). На хостинг не нужно ставить `node_modules`.
- **TLS end-to-end** — прокси открывает байтовый туннель (`CONNECT`) и не видит токены ботов и тела запросов.
- **Allowlist** — CONNECT разрешён только на `*.telegram.org:443` (api/core/updates и поддомены), всё остальное → `403`.
- **Заголовки не модифицируются** — трафик идёт байт-в-байт; прокси не трогает Host/User-Agent/Authorization внутри TLS.
- **Keep-alive** — один CONNECT-туннель переиспользуется для многих запросов.
- **Idle-таймаут** (по умолчанию 120 с) — не рвёт long-polling `getUpdates` (~50 с тишины), но не копит висящие соединения.
- **Опциональная basic auth** — `PROXY_USER`/`PROXY_PASS`, ответ `407` без валидных креденшелов.
- **Лимит одновременных туннелей** (по умолчанию 32) — защита от перегрузки лимитированного хостинга.
- **Graceful shutdown** по `SIGTERM`/`SIGINT`.

## Быстрый старт

```bash
# локально
PORT=8080 node src/index.js

# тесты (Node 18+)
npm test            # или: node --test
```

Проверка:

```bash
# через прокси (работает, если из вашей сети исходящий доступ к api.telegram.org не блокируется)
curl -x http://127.0.0.1:8080 https://api.telegram.org

# с basic auth
curl -x http://user:pass@127.0.0.1:8080 https://api.telegram.org
```

## Настройка клиентов

Прокси — обычный forward HTTP-прокси. Задайте переменные окружения или передайте прокси в HTTP-клиент.

```bash
export HTTP_PROXY="http://<host>:<port>"
export HTTPS_PROXY="http://<host>:<port>"
export ALL_PROXY="http://<host>:<port>"        # если нужно для всех протоколов

# при включённой basic auth:
export HTTP_PROXY="http://user:pass@<host>:<port>"
export HTTPS_PROXY="http://user:pass@<host>:<port>"
```

**python-telegram-bot / aiogram (httpx/requests):**

```python
import httpx
proxies = "http://<host>:<port>"
# python-telegram-bot:
#   application = Application.builder().token(TOKEN).proxy_url(proxies).build()
# aiogram:
#   session = aiohttp_session(...)  # либо передать proxy в httpx-транспорт
# requests:
requests.get("https://api.telegram.org/bot<token>/getMe", proxies={"https": proxies})
```

## Конфигурация (env)

| Переменная | По умолчанию | Описание |
|---|---|---|
| `PORT` | `8080` | Порт, который слушает прокси (`0.0.0.0`) |
| `MAX_TUNNELS` | `32` | Лимит одновременных CONNECT-туннелей; превышение → `503` |
| `IDLE_TIMEOUT_MS` | `120000` | Idle-таймаут туннеля; сброс на любой байт |
| `PROXY_USER` | — | Включает basic auth (нужны оба: `PROXY_USER` + `PROXY_PASS`) |
| `PROXY_PASS` | — | Пароль basic auth |

## Развёртывание на Wispbyte

1. Создайте сервер в панели Wispbyte: **Server Type** = Free Plan, **Runtime** = Node.js.
2. Загрузите файлы проекта (`package.json`, `src/`). `node_modules` не нужен.
3. Убедитесь, что стартовая команда — `node src/index.js` (см. `"start"` в `package.json`).
4. Задайте env-переменные в панели: `PORT` (если панель его не выдаёт автоматически) и, при необходимости, `PROXY_USER`/`PROXY_PASS`.
5. Проверьте снаружи:

```bash
curl -x http://<адрес-и-порт-от-wispbyte> https://api.telegram.org
```

## Ограничения

- Только HTTPS-трафик через `CONNECT` (plain-HTTP не пересылается — `405`).
- Только домены `*.telegram.org:443`; остальное — `403`.
- Масштаб: десятки параллельных ботов комфортно; сотни упрутся в лимит CPU 35% Wispbyte.

## Структура

```
src/index.js     — точка входа: wiring config → log → allow → auth → proxy
src/config.js    — M-CONFIG: env → конфиг
src/log.js       — M-LOG: форматтер [proxy][marker], redaction
src/allow.js     — M-ALLOW: парсер authority + allowlist
src/auth.js      — M-AUTH: basic auth (timing-safe)
src/tunnel.js    — M-TUNNEL: байтовый туннель, idle-таймер, счётчики
src/proxy.js     — M-PROXY: http.Server (connect/request), cap, graceful start
tests/           — node:test (юнит + e2e)
docs/            — GRACE-документы проекта
```

Подробности архитектуры и методология — в `docs/` и `AGENTS.md`.
