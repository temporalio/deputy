# Deputy OpenTelemetry Observability Stack

Local development stack for traces, metrics, and logs using OpenTelemetry.

## Components

- **OpenTelemetry Collector** - Receives OTLP data and routes to backends
- **Grafana Tempo** - Distributed tracing backend
- **Grafana Loki** - Log aggregation backend
- **Prometheus** - Metrics backend
- **Grafana** - Visualization and dashboards

## Quick Start

```bash
# Start the stack
cd docker/otel
docker compose up -d

# Verify services are running
docker compose ps

# Run Deputy with OTel enabled
export DEPUTY_OTEL_ENABLED=true
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
export OTEL_EXPORTER_OTLP_INSECURE=true

deputy scan

# View traces in Grafana
open http://localhost:3000
```

## Demo: Logs ↔ Traces ↔ Metrics Correlation

Full observability correlation in 3 steps.

### 1. Generate Data

```bash
DEPUTY_LOG_LEVEL=info DEPUTY_OTEL_ENABLED=true \
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317 \
OTEL_EXPORTER_OTLP_INSECURE=true ./deputy scan
```

### 2. Open the Dashboard

**Direct link:** http://localhost:3000/d/deputy-overview

Or navigate: Grafana → Dashboards → Deputy Overview

### 3. Navigate Between Signals

| From | To | How |
|------|-----|-----|
| **Logs → Traces** | Click log line → expand → click `trace_id` "View Trace" link |
| **Traces → Logs** | Click Trace ID in table → click span → "Logs" button |
| **Traces → Metrics** | Click span → "Metrics" dropdown → select query |
| **Metrics → Traces** | In Explore with Prometheus, enable "Exemplars" → click dots |

### Direct Links

| View | URL |
|------|-----|
| Dashboard | http://localhost:3000/d/deputy-overview |
| Explore Traces | http://localhost:3000/explore?orgId=1&left={"datasource":"tempo","queries":[{"refId":"A","queryType":"traceqlSearch"}]} |
| Explore Logs | http://localhost:3000/explore?orgId=1&left={"datasource":"loki","queries":[{"refId":"A","expr":"{service_name=\"deputy\"}"}]} |
| Explore Metrics | http://localhost:3000/explore?orgId=1&left={"datasource":"prometheus","queries":[{"refId":"A","expr":"deputy_scan_duration_seconds_bucket"}]} |

### Correlation Flow

```
Logs (Loki) ←──trace_id──→ Traces (Tempo) ←──exemplars──→ Metrics (Prometheus)
     ↑                           ↑                              ↑
     └───────────────── Dashboard (Deputy Overview) ────────────┘
```

Every log line includes `trace_id` and `span_id` labels. Click to jump between systems.

## Access Points

| Service | URL | Description |
|---------|-----|-------------|
| Grafana | http://localhost:3000 | Dashboards (no login required) |
| Prometheus | http://localhost:9090 | Metrics queries |
| Tempo | http://localhost:3200 | Trace API |
| Loki | http://localhost:3100 | Log API |
| OTel Collector (gRPC) | localhost:4317 | OTLP receiver |
| OTel Collector (HTTP) | localhost:4318 | OTLP receiver |
| OTel Collector Metrics | http://localhost:8889/metrics | Prometheus scrape endpoint |

## Environment Variables

```bash
# Enable OTel in Deputy
DEPUTY_OTEL_ENABLED=true

# Configure exporter (defaults shown)
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_INSECURE=true

# Sampling (1.0 = 100%)
OTEL_TRACES_SAMPLER_ARG=1.0
```

## Verifying Data Collection

### Check Traces (CLI)

```bash
# Query Tempo for recent Deputy traces
curl -s "http://localhost:3200/api/search?tags=service.name%3Ddeputy&limit=5" | jq .

# Get a specific trace by ID
curl -s "http://localhost:3200/api/traces/<trace-id>" | jq .
```

### Check Metrics (CLI)

```bash
# View raw metrics from collector
curl -s http://localhost:8889/metrics | grep deputy

# Query Prometheus
curl -s "http://localhost:9090/api/v1/query?query=deputy_scan_duration_seconds_count" | jq .
```

## Using Grafana

### Pre-built Dashboard

A Deputy Overview dashboard is automatically provisioned with panels for:
- Scan duration (p50/p95) by ecosystem
- Vulnerabilities found by severity
- Proxy request rate by ecosystem
- Policy denials
- OSV cache hit rate
- OSV query latency

Access: **Dashboards > Browse > Deputy > Deputy Overview**

### Exploring Traces

1. Open http://localhost:3000
2. Go to **Explore** (compass icon)
3. Select **Tempo** datasource
4. Use the Search tab or TraceQL tab

### Example Queries

#### Prometheus (Metrics)

```promql
# Scan duration p95 by ecosystem
histogram_quantile(0.95, sum(rate(deputy_scan_duration_seconds_bucket[5m])) by (le, deputy_ecosystem))

# Vulnerabilities found in the last hour
sum(increase(deputy_scan_vulnerabilities_total[1h])) by (severity)

# Proxy requests per second
sum(rate(deputy_proxy_requests_total[5m])) by (deputy_ecosystem)

# OSV cache hit ratio
sum(rate(deputy_osv_cache_hits_total[5m])) /
(sum(rate(deputy_osv_cache_hits_total[5m])) + sum(rate(deputy_osv_cache_misses_total[5m])))

# Policy denial rate
sum(rate(deputy_proxy_policy_denials_total[5m])) by (deputy_ecosystem, policy)
```

#### TraceQL (Tempo)

```
# Find all Deputy traces
{ resource.service.name="deputy" }

# Find scan operations
{ resource.service.name="deputy" && name="deputy.scan.repository" }

# Find slow scans (>5s)
{ resource.service.name="deputy" && name="deputy.scan.repository" } | duration > 5s

# Find scans that found vulnerabilities
{ resource.service.name="deputy" && span.deputy.vuln.count > 0 }

# Find proxy requests denied by policy
{ resource.service.name="deputy" && span.deputy.proxy.policy.result="deny" }
```

### Check Logs (CLI)

```bash
# Query Loki for recent Deputy logs
curl -s "http://localhost:3100/loki/api/v1/query?query=%7Bservice_name%3D%22deputy%22%7D&limit=10" | jq .

# Query logs with a specific trace ID
curl -s 'http://localhost:3100/loki/api/v1/query?query={service_name="deputy"} |= "abc123"' | jq .
```

### Exploring Logs

1. Open http://localhost:3000
2. Go to **Explore** (compass icon)
3. Select **Loki** datasource
4. Use LogQL to query logs

#### LogQL (Loki)

```logql
# Find all Deputy logs
{service_name="deputy"}

# Find error logs
{service_name="deputy"} |= "level=ERROR"

# Find logs for a specific trace
{service_name="deputy"} | json | trace_id="<your-trace-id>"

# Find logs mentioning vulnerabilities
{service_name="deputy"} |~ "vuln|CVE"
```

### Exemplars (Metrics → Traces)

Histogram metrics include exemplars linking to traces. To view:

1. Go to Explore → Prometheus
2. Query a histogram: `deputy_scan_duration_seconds_bucket`
3. Enable "Exemplars" in visualization options
4. Click dots on the graph to jump to traces

## Troubleshooting

### Services not starting

```bash
# Check service status
docker compose ps

# View logs for a specific service
docker compose logs otel-collector
docker compose logs tempo
docker compose logs loki
docker compose logs prometheus
```

### No traces appearing

1. **Verify OTel is enabled:**
   ```bash
   echo $DEPUTY_OTEL_ENABLED  # Should print "true"
   ```

2. **Check collector is receiving data:**
   ```bash
   docker compose logs otel-collector | grep -i "traces"
   ```

3. **Query Tempo directly:**
   ```bash
   curl -s "http://localhost:3200/api/search?limit=5" | jq .
   ```

4. **Check for connection errors in Deputy output:**
   ```bash
   DEPUTY_LOG_LEVEL=debug DEPUTY_OTEL_ENABLED=true deputy scan
   ```

### No metrics appearing

1. **Check collector is exporting metrics:**
   ```bash
   curl -s http://localhost:8889/metrics | grep deputy | head -10
   ```

2. **Check Prometheus is scraping:**
   ```bash
   curl -s "http://localhost:9090/api/v1/targets" | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
   ```

3. **Query Prometheus:**
   ```bash
   curl -s "http://localhost:9090/api/v1/query?query=up" | jq '.data.result'
   ```

### No logs appearing

1. **Check collector is receiving logs:**
   ```bash
   docker compose logs otel-collector | grep -i "logs"
   ```

2. **Check Loki is healthy:**
   ```bash
   curl -s http://localhost:3100/ready
   ```

3. **Query Loki directly:**
   ```bash
   curl -s "http://localhost:3100/loki/api/v1/labels" | jq .
   ```

4. **Verify logs are being sent:**
   ```bash
   DEPUTY_LOG_LEVEL=debug DEPUTY_OTEL_ENABLED=true ./deputy scan 2>&1 | head -20
   ```

### No exemplars appearing on metrics

1. **Verify Prometheus has exemplar storage enabled:**
   ```bash
   curl -s http://localhost:9090/api/v1/status/flags | jq '.data["storage.exemplars.retention-duration"]'
   ```

2. **Check collector exports exemplars (OpenMetrics format):**
   ```bash
   curl -s -H "Accept: application/openmetrics-text" http://localhost:8889/metrics | grep -A2 "exemplar"
   ```

3. **Ensure histogram metrics have data:**
   ```bash
   curl -s "http://localhost:9090/api/v1/query?query=deputy_scan_duration_seconds_bucket" | jq '.data.result | length'
   ```

4. **Verify exemplars in Prometheus:**
   ```bash
   curl -s "http://localhost:9090/api/v1/query_exemplars?query=deputy_scan_duration_seconds_bucket&start=$(date -v-1H +%s)&end=$(date +%s)" | jq .
   ```

Note: Exemplars only appear for histogram metrics when there's an active, sampled trace context during measurement recording.

### Connection refused errors

Ensure the endpoint doesn't include a protocol prefix:
```bash
# Wrong
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Correct
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
```

### Collector keeps restarting

Check for configuration errors:
```bash
docker compose logs otel-collector | tail -20
```

Common issues:
- Invalid YAML syntax in config files
- Deprecated exporters (e.g., `loki` exporter was removed; use `otlphttp` instead)

## Stack Management

### Stop (preserve data)

```bash
cd docker/otel
docker compose down
```

Containers stop but volumes (traces, metrics, logs) are preserved. Restart with `docker compose up -d`.

### Full Reset (nuke everything)

```bash
cd docker/otel

# Stop containers and remove volumes
docker compose down -v

# Verify volumes removed
docker volume ls | grep otel
```

This removes all observability data. Use when:
- Starting a fresh demo
- Debugging data corruption
- Clearing stale test data

### Restart Individual Services

```bash
# Restart just Grafana (e.g., after config changes)
docker compose restart grafana

# Recreate a service (pulls fresh config)
docker compose up -d --force-recreate grafana

# View logs for a specific service
docker compose logs -f tempo
```

### Check Service Health

```bash
# Service status
docker compose ps

# Quick health check
curl -s http://localhost:3100/ready  # Loki
curl -s http://localhost:3200/ready  # Tempo
curl -s http://localhost:9090/-/ready # Prometheus
curl -s http://localhost:3000/api/health # Grafana
```

## Production Considerations

This stack is for local development. For production:

- Use managed services (Grafana Cloud, AWS X-Ray, Datadog, etc.)
- Configure proper authentication
- Set up persistent storage with backups
- Adjust sampling rates for high-volume workloads
- Consider ClickHouse for SQL-queryable observability data at scale
