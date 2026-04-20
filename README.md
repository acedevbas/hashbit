# hashbit

Сервис для массового опроса BitTorrent-трекеров по списку инфохешей.
Параллельно поддерживает 6 скрейперов (Rutor, NNM-Club, Kinozal, Rutracker, **public** — агрегатор публичных HTTP+UDP трекеров, **dht** — Mainline DHT + BEP 33 bloom-filter scrape), умно планирует повторные опросы, отдаёт агрегированный max по сидам/пирам через REST API.

Стек: **Go 1.22 + PostgreSQL 16 + Docker Compose**. Запускается одной командой `docker compose up -d --build`.

## Что умеет

- Принимает миллионы инфохешей через API (JSON или plain text)
- 5 независимых воркеров, каждый со своей стратегией:
  - **Rutor** — batch HTTP scrape (300 хешей за запрос, anonymous)
  - **NNM-Club** — batch HTTP scrape (300 хешей за запрос, anonymous)
  - **Kinozal** — HTTP announce (1 хеш за запрос, с твоим passkey `uk=`)
  - **Rutracker** — HTTP announce + peer counting (без seeders/leechers split)
  - **Public** — агрегатор 16 HTTP + ~50 UDP публичных трекеров (BEP 48 + BEP 15 multi-hash scrape). Лучший источник для хешей, которых нет на приватных трекерах.
  - **DHT** — Mainline DHT `get_peers` с BEP 33 bloom-filter `scrape=1`. Один итеративный обход даёт (1) живые peer-адреса из DHT и (2) bloom-filter-оценку seed/peer count от 10-20% нод, реализующих BEP 33. Без NAT/TCP/μTP — чистый UDP DHT; ~12с на хеш, ~4 часа на 620k при параллельности 64.
- Смарт-шедулер: живые торренты обновляем часто, мёртвые — редко (экспоненциальный backoff)
- Bearer-аутентификация на всех API-ручках
- Агрегат по всем трекерам: `max(seeders)` даёт лучшую известную оценку swarm'а
- Per-tracker детализация для диагностики
- On-demand scrape через `?force=1` с таймаутом 10 сек
- JSON-логи, healthcheck, graceful shutdown

## Архитектура

```
┌──────────────────────────────────────────┐
│  Postgres (pgx + auto-migrations)        │
│    infohashes (agg: seeders, peers, ...) │
│    tracker_state (per-tracker rows)      │
└──────────────┬───────────────────────────┘
               │
   ┌───────────┼──────────┬──────────┐
   ▼           ▼          ▼          ▼
  rutor    nnm-club   kinozal   rutracker
  worker    worker     worker    worker
   (scr)     (scr)     (ann)     (ann)
   │          │          │         │
   └────┬─────┴──────────┴─────────┘
        ▼
   HTTP Client (uTorrent UA, timeouts)
        ▼
  External trackers

  ─────────────────────────────

  HTTP API (Bearer auth):
     POST /hashes        — закинуть инфохеши
     POST /hashes/query  — получить стату по списку (до 5000)
     GET  /hash/{ih}     — детали по одному + per-tracker breakdown
     GET  /hash/{ih}?force=1  — немедленный scrape (3-10 сек)
     GET  /stats         — глобальная стата
     GET  /health        — healthcheck (без auth)
```

## Быстрый старт

```bash
git clone https://github.com/acedevbas/hashbit.git
cd hashbit

# 1) сгенерировать секреты
cp .env.example .env
POSTGRES_PASSWORD=$(openssl rand -hex 16)
API_TOKEN=$(openssl rand -hex 32)
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
sed -i "s/^API_TOKEN=.*/API_TOKEN=$API_TOKEN/" .env

# 2) опционально — Kinozal passkey
# echo "KINOZAL_UK=74FW9sfWUc" >> .env

# 3) запуск
docker compose up -d --build
docker compose logs -f app
```

Проверка:
```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

Основные ручки требуют токен:
```bash
export API_TOKEN=$(grep ^API_TOKEN= .env | cut -d= -f2)
curl -H "Authorization: Bearer $API_TOKEN" http://localhost:8080/stats
```

## API

### Загрузить инфохеши — `POST /hashes`

JSON со структурой (рекомендуемый формат):

```bash
curl -X POST http://localhost:8080/hashes \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hashes": [
      {"infohash": "d9f870adfb1dd582d72061b54074cfac9edcf852", "source_tracker": "rutor"},
      {"infohash": "75bfa2ba05591fe4ed9325e17a7276c522ffd707", "source_tracker": "kinozal"}
    ]
  }'
```

Плоский JSON без `source_tracker` — тоже работает:

```bash
curl -X POST http://localhost:8080/hashes \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hashes": ["d9f870adfb1dd582d72061b54074cfac9edcf852"]}'
```

Plain text (удобно для массовой заливки):

```bash
# один хеш в строке
curl -X POST http://localhost:8080/hashes \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: text/plain" \
  --data-binary @hashes.txt

# с указанием провайдера (через запятую или пробел):
#   d9f870adfb1dd582d72061b54074cfac9edcf852,rutor
#   75bfa2ba05591fe4ed9325e17a7276c522ffd707 kinozal
```

Ответ:
```json
{"received": 1000000, "newly_added": 999500, "already_known": 500}
```

**Резать на чанки** по 50-200k хешей — проще и быстрее чем 1М одним запросом.

### Получить статистику — `POST /hashes/query`

```bash
curl -X POST http://localhost:8080/hashes/query \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hashes": ["d9f870adfb1dd582d72061b54074cfac9edcf852", "abcdef..."]}'
```

Ответ:
```json
{
  "results": [
    {
      "infohash": "d9f870adfb1dd582d72061b54074cfac9edcf852",
      "known": true,
      "source_tracker": "rutor",
      "seeders": 235,
      "leechers": 21,
      "peer_count": null,
      "last_update_at": "2026-04-18T16:00:00Z",
      "added_at": "2026-04-18T15:30:00Z"
    },
    {
      "infohash": "abcdef...",
      "known": false
    }
  ]
}
```

Лимит: 5000 хешей за один запрос.

### Детали по хешу — `GET /hash/{infohash}`

```bash
curl -H "Authorization: Bearer $API_TOKEN" \
  http://localhost:8080/hash/d9f870adfb1dd582d72061b54074cfac9edcf852
```

Ответ:
```json
{
  "infohash": "d9f870adfb1dd582d72061b54074cfac9edcf852",
  "seeders": 235,
  "leechers": 21,
  "peer_count": null,
  "last_update_at": "2026-04-18T16:00:00Z",
  "per_tracker": [
    {"tracker": "rutor",     "seeders": 235, "leechers": 21, "status": "ok",
     "last_scrape_at": "2026-04-18T16:00:00Z"},
    {"tracker": "nnm-club",  "seeders": 44,  "leechers": 2,  "status": "ok", ...},
    {"tracker": "kinozal",   "seeders": 70,  "leechers": 1,  "status": "ok", ...},
    {"tracker": "rutracker", "peer_count": 0, "status": "not_found", ...}
  ]
}
```

С `?force=1` — немедленно опрашивает все 4 трекера и возвращает свежие данные (3-10 сек):

```bash
curl 'http://localhost:8080/hash/d9f870adfb1dd582d72061b54074cfac9edcf852?force=1' \
  -H "Authorization: Bearer $API_TOKEN"
```

### Глобальная стата — `GET /stats`

```json
{
  "total": 1000000,
  "scraped_at_least_1": 950000,
  "with_seeders": 350000,
  "with_peers_only": 20000,
  "due_now_by_tracker": {
    "rutor": 45,
    "nnm-club": 38,
    "kinozal": 1203,
    "rutracker": 1156
  }
}
```

## Интерпретация данных

| Поле | Что значит |
|---|---|
| `seeders` / `leechers` | max() по всем трекерам, которые разделяют сидов/пиров. Rutracker в эту сумму не входит (он не разделяет). |
| `peer_count` | max() по тем трекерам, которые **только** общий peer count (т.е. rutracker). Не учитывается если есть `seeders`. |
| `null` | Ни один трекер не вернул данные. Либо хеш мёртв, либо его никто не знает. |
| `source_tracker` | Подсказка от клиента "откуда этот хеш". Для логики скрейпа не используется, все 4 трекера опрашиваются в любом случае. |

### "Жив ли торрент?"

```python
def is_alive(result):
    return (result['seeders'] or 0) > 0 or (result['peer_count'] or 0) > 0
```

## Конфигурация

Все параметры через env в `docker-compose.yml`:

| Var | По умолчанию | Описание |
|---|---|---|
| `API_TOKEN` | — (обязательно) | Bearer-токен для auth |
| `KINOZAL_UK` | — | Твой passkey с Kinozal; без него kinozal-воркер отключён |
| `RUTOR_BATCH_SIZE` | 300 | Хешей за один batch-запрос на rutor |
| `NNM_BATCH_SIZE` | 300 | То же для NNM-Club |
| `PUBLIC_BATCH_SIZE` | 500 | Хешей за один public-scrape (раздаётся на ~66 трекеров параллельно) |
| `PUBLIC_CONCURRENCY` | 32 | Макс. параллельных endpoint-запросов в одном public-проходе |
| `DHT_BATCH_SIZE` | 100 | Хешей за один DHT-scrape тик |
| `DHT_CLIENTS` | 4 | Размер пула DHT-клиентов (N разных node ID / сокетов, каждый по своему маршруту через Kademlia) |
| `DHT_CONCURRENCY` | 64 | Всего параллельных операций во всём пуле |
| `DHT_ALPHA` | 8 | Kademlia α (параллелизм внутри одного lookup) |
| `DHT_LOOKUP_TIMEOUT` | 12s | Бюджет одного (hash, client) lookup'а |
| `KINOZAL_RPS` | 5 | req/sec на kinozal |
| `RUTRACKER_RPS` | 5 | req/sec на rutracker |
| `SCRAPE_TICK` | 15s | Как часто просыпается scrape-воркер |
| `ANNOUNCE_TICK` | 1s | Как часто просыпается announce-воркер |
| `INTERVAL_ALIVE` | 30m | Как часто перескрейпливать живые |
| `INTERVAL_DEAD1/2/LONG` | 1h / 6h / 24h | Для постепенно мёртвых |
| `TRACKER_TIMEOUT` | 15s | HTTP-таймаут на запрос к трекеру |

После правки в `.env` или `docker-compose.yml`:
```bash
docker compose up -d --build
```

## Математика

На твоих цифрах (1М хешей, 4 трекера):

- Rutor + NNM-Club (batch): `1M / 300 = ~3300 запросов на трекер`. При tick=15s и 1 запросе/тик: **~14 часов полного прохода**.
- Kinozal + Rutracker (announce): `5 req/sec × 86400 = 432k/день/воркер`. **~2.3 дня полного прохода** каждого.

Это первичный обход **с нуля**. После него включается умный шедулер: живые торренты (seeders > 0) переопрашиваются каждые 30 мин, мёртвые в backoff'е — трафик падает в 10-50 раз. Sustained нагрузка на сеть — 10-30 KB/s.

## Операционка

### Логи
```bash
docker compose logs -f --tail=200 app
```

### Заглянуть в БД
```bash
docker compose exec db psql -U tracker -d tracker

# примеры полезных запросов:
SELECT COUNT(*), COUNT(*) FILTER (WHERE seeders > 0) FROM infohashes;
SELECT tracker, status, COUNT(*) FROM tracker_state GROUP BY 1,2;
SELECT * FROM infohashes ORDER BY last_update_at DESC LIMIT 10;
```

### Пересобрать после правок
```bash
docker compose up -d --build
```

### Сбросить всё
```bash
docker compose down -v    # -v стирает volume с БД
```

## Известные особенности

1. **Rutracker не отдаёт seeders/leechers**. Только peer_count. Для rutracker-only хешей поле `seeders` будет `null`, зато `peer_count` будет актуальный.
2. **"Torrent not registered"** — нормальный ответ от Rutracker/Kinozal когда трекер не знает хеш. Статус `not_found`.
3. **Self-echo на Rutracker**. Трекер возвращает наш собственный peer_id в списке пиров. Мы вычитаем 1 из `peer_count` (см. `internal/trackers/rutracker`).
4. **IP-геобан**. Rutracker иногда отвечает 403 с Амстердамского IP на браузерный User-Agent. Мы используем `uTorrent/3.5.5` — проходит. Если бан по IP — добавь прокси через `HTTP_PROXY` env в compose только для app-сервиса.

## Лицензия

MIT
