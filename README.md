# SilentFabric

An open source SIEM that is cheap to run, simple to operate, and has no paywalled detection features.

SilentFabric normalizes every log once, runs [Sigma](https://github.com/SigmaHQ/sigma) rules on events as they stream in, and stores everything in [ClickHouse](https://clickhouse.com), a columnar database that typically compresses logs around 10x. A small deployment is one VM running two processes: the SilentFabric binary and ClickHouse. No JVM, no Kafka, no cluster.

> **Status: early scaffold.** Syslog and JSON ingest, streaming Sigma detection, ClickHouse storage, and webhook alerts work. Search UI, correlation rules, and cases are next.

## Quick start

Requires Docker with the Compose plugin.

```sh
cp .env.example .env          # set CLICKHOUSE_PASSWORD
docker compose up -d --build
```

Send a test event:

```sh
curl -X POST localhost:8080/api/v1/events \
  -d '{"host":{"name":"web01"},"syslog":{"appname":"sshd"},"message":"Failed password for root from 203.0.113.9"}'
```

or point devices' syslog at UDP port 514 on the VM. Query what arrived:

```sh
docker compose exec clickhouse clickhouse-client -d silentfabric \
  -q "SELECT time, rule_title, host FROM alerts ORDER BY time DESC LIMIT 10"
```

## Sizing (estimates)

| Devices | Raw logs/day | Disk for 90 days | VM |
| --- | --- | --- | --- |
| 50 | 2.5-10 GB | 25-90 GB | 4 vCPU, 8 GB RAM, 250 GB SSD |
| 500 | 25-100 GB | 250-900 GB | 8 vCPU, 32 GB RAM, 1-2 TB SSD |

## Rules as code

Rules are plain Sigma YAML files under `rules/`. Check and test them before deploying:

```sh
make build
bin/silentfabric rules check rules
bin/silentfabric rules test rules testdata/events.ndjson
```

Events expose their parsed fields with dotted names (`syslog.appname`, `host.name`, `process.name`) plus `message`, `host` and `source`.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/silentfabric` | The single binary: `serve`, `rules check`, `rules test` |
| `internal/ingest` | Syslog (RFC 5424/3164) over UDP, JSON/NDJSON over HTTP |
| `internal/detect` | Streaming Sigma engine |
| `internal/pipeline` | Batching between detection and storage |
| `internal/store` | ClickHouse writer |
| `deploy/clickhouse` | Table schema, 90-day event retention |

## Roadmap

1. Search UI with facets and timeline; alert triage states
2. Parsers for Windows events, firewalls, and Wazuh alerts; OTLP logs ingest
3. Sigma correlation rules (count, value count, sequences) as scheduled ClickHouse queries
4. Cases, threat-intel matching (MISP, STIX/TAXII), OIDC login and RBAC
5. Scale-out: buffer, ClickHouse cluster, S3 cold tier

## License

SilentFabric is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version as a network service, you must offer its source to the users of that service.

Commercial licenses for use outside the AGPL may be offered in the future. To keep that possible, contributors will be asked to sign a contributor license agreement before their first pull request is merged.
