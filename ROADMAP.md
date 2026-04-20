# hashbit roadmap — peer discovery improvements

Пройденные в этой сессии изменения (коммиты `886adf2` → `1d36940`):
- 7 скрейперов (rutor, nnm-club, kinozal, rutracker, public, dht, webtorrent)
- Passive DHT observer на UDP 6881
- DHT engine на базе `anacrolix/dht/v2` с persistent routing table + BEP 33
- Temporal columns в БД (`peak_seeders`, `peak_leechers`, `peak_peer_count`, `last_nonzero_at`)
- GitHub Actions CI/CD: push → build → SSH deploy

Оставшиеся улучшения ранжированы по (эффект / сложность):

## Tier 1 — дешёвые большие выигрыши

### 1. `/metrics` Prometheus endpoint
Базовый стандарт для любого production-сервиса. Экспортировать:
- per-tracker: `scrapes_total{tracker, status}`, `tick_duration_seconds{tracker}`
- DHT: `dht_peers_found`, `dht_bep33_responders`, `dht_routing_table_size`
- passive: `passive_cache_hashes_total`, `passive_observations_total`
- БД: `hashes_total`, `hashes_with_seeders`, `scraped_fraction`

~80 строк + `github.com/prometheus/client_golang` dep. Позволяет Grafana/alerting.

### 2. BEP 51 `sample_infohashes`
anacrolix/dht поддерживает через `Return.Bep51Return`. Для каждой DHT-ноды с которой говорим — спрашиваем «какие хэши знаешь». Получаем **discovery**: новые хэши, которые в нашей базе ещё нет.

Применение: бесплатный seed-discovery source для проекта-в-общем. Можно складывать в отдельную таблицу `discovered_hashes` и user сам решает что с ними делать.

~100 строк. Не меняет существующую логику.

### 3. Retry для "когда-то живых" хэшей
Сейчас: first `not_found` → backoff `1h → 6h → 24h`.

Проблема: хэш с `peak_peer_count > 0` но сейчас `not_found` — живой swarm, variance. Но уходит в 24h backoff после 10 zeros подряд.

Fix: **shorter backoff** для хэшей с `peak_peer_count > 0`:
```sql
CASE
  WHEN peak_peer_count > 0 AND consecutive_zero_scrapes < 5 THEN '10 min'
  WHEN peak_peer_count > 0 AND consecutive_zero_scrapes < 15 THEN '1 hour'
  ...
END
```

~30 строк SQL. Ловит edge-case variance, не блокирует мёртвые хэши.

## Tier 2 — средней сложности

### 4. IPv6 DHT (отдельный udp6 socket)
anacrolix/dht поддерживает через `ServerConfig.Conn = net.ListenPacket("udp6", ...)`. Второй Server для IPv6 трафика.

**+30% peer base** — IPv6-only клиенты и IPv6 BEP 33 responders. Наш сервер уже имеет IPv6 (`2a01:e5c0:45ed::2`).

~100 строк.

### 5. Handshake seed fingerprint через HTTP API
Сейчас seed counting через BEP 33 estimate (аппроксимация). Можно дать user'у `?fingerprint=1` опцию для конкретного хэша — мы открываем TCP handshake к top-20 peers, читаем bitfield, считаем реальные seeds.

**Confirmed seeds** вместо estimate. TCP-only вариант — pure-Go, не требует cgo.

~150 строк. Opt-in (не каждый запрос, только когда важно знать точно).

### 6. Grafana дашборд
На базе #1 (Prometheus). Docker-контейнер Grafana + provisioned dashboards для:
- trajectory hashes/seeders over time
- per-tracker hit rate
- DHT routing table coverage
- alerts: если `scraped_at_least_1` не растёт 30 мин

~100 строк YAML конфигов.

## Tier 3 — большие работы

### 7. μTP через go-libutp в prod (cgo)
Сейчас μTP только в `cmd/dht-probe` диагностике. В prod ловим только TCP handshake для seed fingerprint.

μTP даст **+30% peer reachability** для NAT'нутых seeders. Цена — cgo в Dockerfile (+build-base, +libstdc++).

Только если Tier 1+2 станут недостаточны.

### 8. Полноценный BT peer daemon (stateful PEX)
Держать 100-200 долгих TCP-соединений к активным seeders, получать ut_pex обновления каждую минуту. Каждый PEX = ~50 новых peer-адресов. **Экспоненциальный рост** peer coverage.

Крупный проект: stateful peer manager, connection pool, PEX accumulator. ~1000 строк. Оправдано только на 1M+ hashes scale.

### 9. Интеграция btdig.com / аналогов
Внешний DHT crawler как fallback для edge-case хэшей. Proxy-API: если наша DHT вернула null, спрашиваем btdig.

Зависимость от стороннего сервиса, rate-limits. Резерв.

---

## Текущий SLA (baseline)

На 619 680 хэшах (по состоянию коммита `1d36940`):
- **total growth**: ~1000 hashes/мин (зависит от user upload)
- **seeders found**: ~150-300/мин (varies, ~7% of total `with_seeders`)
- **DHT throughput** (anacrolix tuned): ~50-70 hashes/мин per client
- **Public throughput** (scrape+UDP/HTTP announce): ~1000/мин
- **Passive DHT accumulation**: ~10-30 unique hashes/hour

Ожидаемое покрытие за 24 часа:
- `scraped_at_least_1`: 100% (все скрейперы пройдутся)
- `peak_seeders > 0`: 10-30% (реальный % живых в BitTorrent-мире)
- `passive cache`: несколько тысяч уникальных hashes

## Приоритетный следующий шаг

**Tier 1 #1: Prometheus `/metrics`** — нужен для видимости как работают остальные улучшения. Без него каждое изменение будем валидировать через копание в логах + raw SQL.

Ориентировочно **1-2 часа работы**, даёт основу для всего остального.
