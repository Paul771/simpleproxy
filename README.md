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
| `MTPROTO_SECRET` | — | MTProto-секреты, 32 hex (16 байт); несколько через запятую. Формат `user:secret` (или просто `secret` → пользователь `default`). **Не задан → MTProto выключен** |
| `MTPROTO_PORT` | `0` | Отдельный порт для MTProto; `0` = мультиплексировать с HTTP на `PORT` |
| `MTPROTO_MAX_CONNECTIONS` | `64` | Лимит одновременных MTProto-соединений |
| `MTPROTO_HOST` | `YOUR_HOST_OR_IP` | Публичный адрес сервера для подстановки в `tg://proxy`-ссылки (домен или IP) |
| `MTPROTO_TLS_DOMAIN` | `www.google.com` | Домен для fake-TLS (ee) маскировки; подставляется в ee-ссылку как SNI. См. примечание ниже про выбор домена |
| `MTPROTO_MASK_HOST` | = `MTPROTO_TLS_DOMAIN` | Реальный upstream для traffic-masking при unknown SNI / неверном секрете |
| `MTPROTO_MASK_PORT` | `443` | Порт mask-host |
| `MTPROTO_UNKNOWN_SNI_ACTION` | `mask` | Поведение при unknown SNI / неверном fake-TLS секрете: `mask` (splice к mask_host) \| `reject` (TLS alert) \| `drop` (destroy) |
| `MTPROTO_REPLAY_WINDOW` | `1024` | Размер LRU для replay-защиты (0 = выключена) |
| `MTPROTO_REPLAY_TTL_MS` | `30000` | TTL записей LRU replay-защиты, мс |
| `MTPROTO_DIGEST_FRESHNESS_MS` | `0` | Макс. отклонение timestamp в digest (0 = не проверять) |
| `MTPROTO_TLS_ALPN` | `h2,http/1.1` | ALPN-список fake ServerHello; первый = выбранный протокол |
| `MTPROTO_PREFER_IPV6` | `false` | Использовать IPv6-адреса DC Telegram (`1`/`true`/`yes`/`on`) |
| `MTPROTO_TLS_PROFILE_CAPTURE` | `false` | Захват структуры TLS server-flight у `MTPROTO_TLS_DOMAIN` и replay в fake ServerHello (anti-DPI) |
| `MTPROTO_TLS_PROFILE_REFRESH_MS` | `600000` | Интервал refresh TLS-профиля, мс (10 мин) |
| `MTPROTO_TLS_PROFILE_TIMEOUT_MS` | `5000` | Таймаут захвата TLS-профиля, мс |
| `MTPROTO_DOPPELGANGER` | `false` | Replay inter-arrival delays server-flight при отправке fake ServerHello (требует TLS-профиль) |
| `MTPROTO_DOPPELGANGER_MAX_DELAY_MS` | `500` | Верхняя граница задержки в doppelganger-режиме, мс |
| `MTPROTO_PENDING_MAX` | `256` | Лимит сокетов в фазе MTProto-handshake (slowloris-защита) |
| `MTPROTO_METRICS_PORT` | `0` | Side-port для Prometheus `/metrics`; `0` = выключен |
| `MTPROTO_METRICS_HOST` | `0.0.0.0` | Хост, на котором слушает `/metrics`-сервер |
| `MTPROTO_USER_MAX_CONNS` | — | JSON-карта `{user: N}` — лимит одновременных MTProto-соединений на пользователя |
| `MTPROTO_USER_EXPIRATIONS` | — | JSON-карта `{user: "ISO-8601" | epochMs}` — срок действия секрета пользователя |
| `MTPROTO_USER_QUOTAS` | — | JSON-карта `{user: bytes}` — суммарная байтовая квота пользователя |
| `MTPROTO_BLOCKLIST` | — | Client-IP blocklist: CIDR/голые IP через запятую (IPv4/IPv6). Заблокированный IP → silent destroy на edge |

## MTProto proxy (официальные клиенты Telegram)

Прокси умеет принимать и MTProto-трафик (obfuscated2): официальные приложения Telegram
(мобильные/десктоп) подключаются по ссылке `tg://proxy`. TLS/обфускация end-to-end,
прокси видит только handshake. Поддерживаются **simple** (16 байт), **dd** (фиксация DC)
и **ee** (fake-TLS, маскировка под HTTPS для обхода DPI) секреты.

Генерация секрета:

```bash
# 32 случайных hex-символа (16 байт)
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

При старте сервер печатает ссылки для каждого секрета:

```
[proxy][mtproto_link] simple:  tg://proxy?server=YOUR_HOST_OR_IP&port=8080&secret=<hex>
[proxy][mtproto_link] dd:      tg://proxy?server=YOUR_HOST_OR_IP&port=8080&secret=dd<hex>
[proxy][mtproto_link] ee:      tg://proxy?server=YOUR_HOST_OR_IP&port=8080&secret=ee<hex><domain-hex>
```

- **simple** — обычный obfuscated2.
- **dd** — фиксирует конкретный датацентр Telegram (полезно при роуминге).
- **ee** — fake-TLS: соединение выглядит как обычный HTTPS к домену из `MTPROTO_TLS_DOMAIN`,
  маскирует трафик от DPI. Берите домен, правдоподобный для IP сервера.

> **Выбор `MTPROTO_TLS_DOMAIN` критичен.** DPI на пути к серверу режет ClientHello с
> популярными SNI (`www.google.com`, `www.yandex.ru`, `www.cloudflare.com`, `vk.com`,
> `github.com` и т.п.) — соединение висит 0 байт, HMAC ломается (`faketls_auth_fail`).
> Проверено на Wispbyte (78.154.103.40): рабочий фронт — **`rutube.ru`** (RU-домен, DPI
> не ест, TLS :443 за ~70 мс). Запасные: `mail.ru`, `ozon.ru`, `habr.com`.
> ee-ссылка для `rutube.ru` получит суффикс `7275747562652e7275`.

Подставьте адрес и порт вашего сервера Wispbyte, откройте ссылку в Telegram
(Настройки → Прокси → «Добавить прокси» или просто перейдите по `tg://`-ссылке)
и проверьте статус «Готово к использованию».

**Пример ссылки (после подстановки хоста):**

```
tg://proxy?server=example.wispbyte.com&port=8080&secret=00112233445566778899aabbccddeeff
```

### Anti-DPI: маскирование порта 443 (по мотивам telemt)

По умолчанию (`MTPROTO_UNKNOWN_SNI_ACTION=mask`) прокси ведёт себя как настоящий веб-сервер на порту 443:
любое соединение без валидного fake-TLS секрета или с неизвестным SNI прозрачно splice'ится
к `MTPROTO_MASK_HOST` (по умолчанию = `MTPROTO_TLS_DOMAIN`). DPI и краулеры видят легитимный HTTPS
к этому домену с настоящим сертификатом, а не RST/обрыв — порт неотличим от реального веб-сервера.

- **`mask`** (default) — non-keyed клиент/краулер получает реальный HTTPS-ответ от mask_host.
  Telegram-клиент с верным секретом проходит MTProto-путь; с неверным — маскируется.
- **`reject`** — прокси выдаёт TLS-alert `unrecognized_name` и закрывает соединение
  (как `nginx ssl_reject_handshake on;`) — порт неотличим от stock web-сервера без запрошенного vhost.
- **`drop`** — немедленный `destroy` (legacy-поведение до anti-DPI).

Дополнительно включена **replay-защита** (`MTPROTO_REPLAY_WINDOW=1024`): повторно перехваченный
fake-TLS ClientHello (тот же digest) отклоняется и маскируется, не доходя до DC Telegram.
Свежесть timestamp digest можно ограничить через `MTPROTO_DIGEST_FRESHNESS_MS`.

В fake ServerHello добавлено **ALPN**-расширение (`MTPROTO_TLS_ALPN`, default `h2,http/1.1`)
для снижения синтетичности fingerprint. Для IPv6-only сетей доступен `MTPROTO_PREFER_IPV6=true`.

**TLS profile capture & replay** (`MTPROTO_TLS_PROFILE_CAPTURE=true`, off по умолчанию): прокси
захватывает *структуру* server-flight у `MTPROTO_TLS_DOMAIN` (cipher suite, ALPN, число CCS,
размеры ApplicationData-записей) и replay'ит её в fake ServerHello вместо синтетики — снижает
record-size fingerprint (JA3/JA4 server-side). Захват — сырой `net.connect` + чтение первого
flight, профиль ~1 КБ, refresh каждые `MTPROTO_TLS_PROFILE_REFRESH_MS`. При неудаче — fallback
на синтетический ServerHello (обратная совместимость).

**Doppelganger** (`MTPROTO_DOPPELGANGER=true`, требует TLS-профиль): помимо структуры replay'ятся
и inter-arrival задержки между записями первого flight — тайминги рукопожатия становятся близки
к реальному origin (стеady-state relay не затрагивается, задержка ограничена
`MTPROTO_DOPPELGANGER_MAX_DELAY_MS`).

При старте прокси логирует anti-DPI-конфиг:

```
[proxy][mask_config] start {"action":"mask","mask_host":"www.cloudflare.com:443","alpn":"h2,http/1.1","replay":1024,"ipv6":0}
```

> Выбирайте `MTPROTO_TLS_DOMAIN` / `MTPROTO_MASK_HOST` как домен, правдоподобный для IP вашего сервера
> и **не режущийся DPI** (см. примечание выше; на Wispbyte рабочий — `rutube.ru`)
> (напр., CDN, который реально отвечает TLS-рукопожатием). Masking — чистый TCP-splice, прокси не
> расшифровывает TLS и не видит содержимое.

### Развёртывание на Wispbyte

1. Создайте сервер в панели Wispbyte: **Server Type** = Free Plan, **Runtime** = Node.js.
2. Загрузите файлы проекта (`package.json`, `src/`). `node_modules` не нужен.
3. Убедитесь, что стартовая команда — `node src/index.js` (см. `"start"` в `package.json`).
4. Задайте env-переменные в панели: `PORT` (если панель его не выдаёт автоматически),
   `MTPROTO_SECRET`, при необходимости `PROXY_USER`/`PROXY_PASS`.
5. Проверьте HTTP-часть снаружи:

```bash
curl -x http://<адрес-и-порт-от-wispbyte> https://api.telegram.org
```

6. Откройте `tg://proxy`-ссылку (см. лог старта) в Telegram — статус «Готово к использованию».

### Наблюдаемость и операционка

**Prometheus-метрики** (`MTPROTO_METRICS_PORT`, off по умолчанию): side-порт `/metrics` отдаёт
text-exposition (v0.0.4) со счётчиками (`*_http_connections_total`, `*_mtproto_connections_total`,
`*_bytes_in_total`, `*_bytes_out_total`, `*_replay_attacks_total`, `*_mask_splices_total`,
`*_pending_caps_total`, `*_rejected_total`) и gauges (`*_active_tunnels`, `*_active_mtproto`,
`*_pending_mtproto`). Ноль зависимостей — крошечный HTTP-сервер на `node:net`.

```bash
# scrape
curl http://<host>:9091/metrics
# в prometheus.yml: scrape http://<host>:9091/metrics
```

**Hot-reload конфига (SIGUSR2)**: `kill -USR2 <pid>` перечитывает env и сливает новый конфиг
в live-объект in-place. Обработчики читают `cfg.*` на каждом соединении, поэтому **ротация
секретов, смена mask-host/TLS-domain/caps/doppelganger применяются без рестарта**. Подсистемы
с boot-time state (replay guard, profile manager, metrics-сервер, слушающий порт) помечаются
как `restart_needed` в логе `[proxy][reload]`. На Windows `SIGUSR2` не доставляется — используйте
рестарт через панель. При ошибке валидации env логируется `[proxy][reload_fail]` и старый
конфиг сохраняется.

### Multi-tenant: per-user секреты

`MTPROTO_SECRET` парсится как `user:secret` (без префикса → пользователь `default`), а лимиты
задаются JSON-картами:

```bash
MTPROTO_SECRET="alice:00112233445566778899aabbccddeeff,bob:ffeeddccbbaa99887766554433221100"
MTPROTO_USER_MAX_CONNS='{"alice":5,"bob":2}'          # одновременных соединений
MTPROTO_USER_EXPIRATIONS='{"bob":"2025-12-31T23:59:59Z"}'  # срок действия секрета
MTPROTO_USER_QUOTAS='{"alice":104857600}'             # 100 МБ суммарного трафика
```

При handshake прокси находит user по секрету и проверяет: не истёк ли срок, не исчерпана ли
байтовая квота, не превышен ли лимит одновременных. Отказ → `destroy` + лог
`[proxy][mtproto_user_reject]`. Без лимитов — обратная совместимость (admit всегда true).

### Этап 3: IPv6 fallback и blocklist

**IPv4↔IPv6 DC fallback** — `getDcAddressCandidates` возвращает упорядоченный список адресов DC
(предпочитаемая семья первой, затем другая). При TCP connect-failure к кандидату прокси пробует
следующего (лог `[proxy][mtproto_dc_fallback]`); все исчерпаны → `[proxy][mtproto_upstream_error]`.
DC-таблицы (IPv4/IPv6) сверены с эталонным `mtprotoproxy.py`.

**Client-IP blocklist** (`MTPROTO_BLOCKLIST`) — отсечение сканеров на edge: подключение с IP,
попавшего в список (CIDR или голый IP, IPv4/IPv6, IPv4-mapped `::ffff:` нормализуется),
получает silent destroy на мультиплексоре до обработки — ни HTTP, ни MTProto-обработчик не
вызываются, байты не отправляются. Лог `[proxy][blocklist_reject]`. Невалидная запись →
`INVALID_ENV` при старте.

```bash
MTPROTO_BLOCKLIST="10.0.0.0/8, 192.168.1.5, 2001:db8::/32"
```

> Middle-End Pool / SOCKS5-upstream осознанно **не реализованы** (этап 3 плана, «держать вне v1»).

## Ограничения

- Только HTTPS-трафик через `CONNECT` (plain-HTTP не пересылается — `405`).
- HTTP: только домены `*.telegram.org:443`; остальное — `403`.
- MTProto: только `*.telegram.org` DC-IP, порт 443; секреты simple/dd/ee (fake-TLS).
- Anti-DPI masking — TCP-splice к mask_host без TLS-терминации; Middle-End Pool / SOCKS5-upstream не реализуется (вне скоупа).
- Масштаб: десятки параллельных ботов + сотни MTProto-клиентов комфортно; тысячи упрутся в лимит CPU 35% Wispbyte.

## Структура

```
src/index.js           — точка входа: wiring config → log → allow → auth → mux → start (replay-guard, profile manager, metrics, user-store, SIGUSR2 reload)
src/config.js          — M-CONFIG: env → конфиг (вкл. MTPROTO_* + anti-DPI + per-user + applyConfigUpdate для hot-reload)
src/log.js             — M-LOG: форматтер [proxy][marker], redaction
src/allow.js           — M-ALLOW: парсер authority + allowlist
src/auth.js            — M-AUTH: basic auth (timing-safe)
src/tunnel.js          — M-TUNNEL: байтовый туннель, idle-таймер, счётчики, metrics bytes in/out
src/proxy.js           — M-PROXY: парсер CONNECT, auth→allow→cap→tunnel, metrics counters
src/mux.js             — M-MUX: определение протокола по первым байтам, маршрутизация
src/mtproto.js         — M-MTPROTO: obfuscated2 handshake (parse/build), DC mapping (IPv4+IPv6)
src/faketls.js         — M-FAKETLS: fake-TLS (ee) handshake, ServerHello+ALPN, SNI-парсинг, TLS alert
src/mtproto-server.js  — MTProto-обработчик: plain + fake-TLS → DC → relay; routeUnknown (mask/reject/drop) + replay + metrics + per-user
src/mask.js            — M-MASK: traffic-masking (TCP-splice к mask_host)
src/replay-guard.js    — M-REPLAY: LRU+TTL replay-защита по digest
src/tls-profile.js     — M-TLS-PROFILE: capture & replay структуры TLS server-flight
src/metrics.js         — M-METRICS: Prometheus text-exposition реестр + /metrics side-port
src/user-store.js      — M-USER-STORE: per-user секреты, cap/expiry/quota (multi-tenant)
src/blocklist.js       — M-BLOCKLIST: client-IP blocklist (CIDR/bare IP, IPv4/IPv6, edge-reject)
tests/                 — node:test (юнит + e2e, 127 тестов)
docs/                  — GRACE-документы проекта
```

Подробности архитектуры и методология — в `docs/` и `AGENTS.md`.
