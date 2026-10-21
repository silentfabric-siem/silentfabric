# SilentFabric

An open source SIEM that is cheap to run, simple to operate, and has no paywalled detection features.

SilentFabric normalizes every log once, runs [Sigma](https://github.com/SigmaHQ/sigma) rules on events as they stream in, and stores everything in [ClickHouse](https://clickhouse.com), a columnar database that typically compresses logs around 10x. A small deployment is one VM running two processes: the SilentFabric binary and ClickHouse. No JVM, no Kafka, no cluster.

> **Status: early.** Syslog (UDP and TCP) and JSON ingest, parsers for Windows, Linux, macOS, Ubiquiti UniFi and SonicWall, streaming Sigma detection, ClickHouse storage, and webhook alerts work. A web UI for search and alerts is built in. Correlation rules and cases are next.

## Quick start

Requires Docker with the Compose plugin.

```sh
cp .env.example .env          # set CLICKHOUSE_PASSWORD and SF_UI_PASSWORD
docker compose up -d --build
```

Send a test event:

```sh
curl -X POST localhost:8080/api/v1/events \
  -d '{"host":{"name":"web01"},"syslog":{"appname":"sshd"},"message":"Failed password for root from 203.0.113.9"}'
```

or point devices' syslog at port 514 (UDP or TCP) on the VM. See [docs/collectors.md](docs/collectors.md) for Windows, Linux, macOS, UniFi and SonicWall setup. Query what arrived:

```sh
docker compose exec clickhouse clickhouse-client -d silentfabric \
  -q "SELECT time, rule_title, host FROM alerts ORDER BY time DESC LIMIT 10"
```

## Web UI

Open `http://<vm>:8080` and sign in with `SF_UI_USER` / `SF_UI_PASSWORD`. The UI stays off until a password is set.

- **Search**: type words to match anywhere in the log, `field:value` to filter (`host:web01`, `event.dataset:windows.security`), `*` for wildcards (`user.name:adm*`), quotes for phrases, and a leading `-` to exclude. Click a facet or any field value to add it as a filter.
- **Alerts**: every rule match, filterable by level, with the event that triggered it.

The UI uses plain HTTP basic auth. If the VM is reachable from outside your network, put it behind a reverse proxy with TLS.

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

Events expose normalized fields with dotted names (`source.ip`, `user.name`, `event.action`, `event.outcome`) plus `message`, `host` and `source`. Windows events also keep native names (`EventID`, `Image`, `CommandLine`), so SigmaHQ Windows rules work as-is. Every sample in `testdata/events.ndjson` is checked against the bundled rules in CI.

## Layout

| Path | What it is |
| --- | --- |
| `cmd/silentfabric` | The single binary: `serve`, `rules check`, `rules test` |
| `internal/ingest` | Syslog (RFC 5424/3164) over UDP and TCP, JSON/NDJSON over HTTP |
| `internal/parse` | Format detection and field normalization per platform and vendor |
| `internal/detect` | Streaming Sigma engine |
| `internal/pipeline` | Batching between detection and storage |
| `internal/store` | ClickHouse writer and search queries |
| `internal/query` | Search box syntax to parameterized SQL |
| `internal/api` | Web UI and JSON API (`/api/v1/search`, `/api/v1/alerts`) |
| `deploy/clickhouse` | Table schema, 90-day event retention |

## Roadmap

1. Alert triage states (new, acknowledged, closed) and saved searches
2. More parsers (Wazuh alerts, Fortinet, pfSense); OTLP logs ingest
3. Sigma correlation rules (count, value count, sequences) as scheduled ClickHouse queries
4. Cases, threat-intel matching (MISP, STIX/TAXII), OIDC login and RBAC
5. Scale-out: buffer, ClickHouse cluster, S3 cold tier

## License

SilentFabric is licensed under the [GNU Affero General Public License v3.0](LICENSE). If you run a modified version as a network service, you must offer its source to the users of that service.

Commercial licenses for use outside the AGPL may be offered in the future. To keep that possible, contributors will be asked to sign a contributor license agreement before their first pull request is merged.
