-- SilentFabric schema. Runs once when the ClickHouse volume is first created.
CREATE DATABASE IF NOT EXISTS silentfabric;

CREATE TABLE IF NOT EXISTS silentfabric.events
(
    time        DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    received_at DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    source      LowCardinality(String),
    host        LowCardinality(String),
    message     String CODEC(ZSTD(3)),
    fields      Map(LowCardinality(String), String) CODEC(ZSTD(3)),
    raw         String CODEC(ZSTD(3)),
    INDEX idx_message message TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (source, host, time)
TTL toDateTime(time) + INTERVAL 90 DAY DELETE;

CREATE TABLE IF NOT EXISTS silentfabric.alerts
(
    time       DateTime64(3, 'UTC'),
    rule_id    LowCardinality(String),
    rule_title LowCardinality(String),
    level      LowCardinality(String),
    tags       Array(LowCardinality(String)),
    host       LowCardinality(String),
    event_raw  String CODEC(ZSTD(3)),
    status     LowCardinality(String) DEFAULT 'new'
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(time)
ORDER BY (time, rule_id)
TTL toDateTime(time) + INTERVAL 365 DAY DELETE;
