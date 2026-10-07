# 🔍 Certificate Transparency Log Monitor

A powerful Python tool for monitoring Certificate Transparency (CT) logs to extract domain names, IP addresses, and email addresses from SSL/TLS certificates in real-time.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 🆕 What's new in 1.4.0

- **Gap-free fetching**: advances by the entries a log actually returns, fetches ranges in parallel,
  and resumes from a state file after a restart (`--new-fetcher-logs`, `--fetch-workers`, `--state-file`).
- **Precertificates are parsed** (from `extra_data`) by the gap-free fetcher. Many CAs log some
  certificates only as a precertificate.
- **One Elasticsearch document per issued certificate**: the document id is built from the domain and
  issuer + serial, so a precertificate and its final certificate collapse, and a certificate seen in
  several logs is stored once per daily index.
- **Bounded memory**: the queues are bounded, and the Elasticsearch retry list is capped.
- **Several processes can share the logs** (`--logs`, `--exclude-logs`). One process uses one CPU core.
- **Stopping loses nothing**: `SIGTERM` drains the queues before exiting.
- **DNS resolution**:
  - a name is resolved once, when its document is first created;
  - wildcards resolve their base name only;
  - lookups run continuously;
  - a periodic status line reports the DNS queue.

## 🌟 Features

- **🚀 Multi-threaded Processing**: Concurrent monitoring of multiple CT logs
- **🎯 Pattern Matching**: Regex filtering for targeted domain discovery
- **🤫 Quiet Mode**: Clean JSON output perfect for automation
- **🔍 Verbose Mode**: Detailed certificate processing information
- **📊 Real-time Statistics**: Progress tracking and success rates
- **⚡ Adaptive Rate Limiting**: Per-server adaptive rate control with circuit breaker pattern
- **🔄 Follow Mode**: Continuous monitoring for new certificates
- **🧭 Gap-free Fetching**: Parallel ranges per log, resume from a state file, graceful stop
- **🌐 Global Coverage**: Monitors all known CT logs or specific targets
- **🔍 DNS Resolution**: Resolve discovered domains to IP addresses with caching
- **🌍 Public DNS Round-Robin**: Distribute queries across 6 major DNS providers
- **💾 Elasticsearch Storage**: Direct output to Elasticsearch with daily indices, de-duplicated document ids and automatic retry

## 🔧 Installation

### Prerequisites

```bash
pip install -r requirements.txt
```

The requirements are `requests`, `cryptography`, `publicsuffix2`, `colorama`, `python-dotenv`, `xxhash`,
`dnspython` (for `--dns-resolve`) and `tldextract`.

### Clone Repository

```bash
git clone https://github.com/jonaslejon/ct-monitor.git
cd ct-monitor
chmod +x ct-monitor.py
```

## 🚀 Quick Start

### Basic Usage

```bash
# Monitor recent certificates from all CT logs
python3 ct-monitor.py -n 1000

# Search for specific domains
python3 ct-monitor.py -m ".*\.example\.com$" -n 2000

# Continuous monitoring
python3 ct-monitor.py -f -n 500

# With DNS resolution to Elasticsearch
python3 ct-monitor.py --es-output --dns-resolve --dns-public -n 1000
```

## 🧭 Gap-free fetching and resume after restart

Some CT logs return fewer entries per `get-entries` request than asked for (Google's logs return
roughly 7-30 whatever the request size). The gap-free fetcher always advances by the entries actually
returned, can fetch several ranges of one log in parallel, never moves its position past a range that
failed, and can persist each log's position so a restart resumes where it stopped.

It is enabled per log, so it can be rolled out gradually:

```bash
# Gap-free fetching for every Argon shard, 4 parallel ranges each, resume from a state file
python3 ct-monitor.py -f --new-fetcher-logs argon --fetch-workers argon=4 \
    --state-file state/positions.json

# All logs
python3 ct-monitor.py -f --new-fetcher-logs all --state-file state/positions.json
```

| Option | Meaning |
|---|---|
| `--new-fetcher-logs` | Comma-separated substrings of log URLs, or `all` |
| `--fetch-workers` | Parallel ranges per log, e.g. `argon=16,xenon=4`; each key is a substring of the log URL (default 1) |
| `--state-file` | Where to persist each log's position |
| `--max-backlog` | On start, skip ahead if the saved position is further behind than this (default 2,000,000) |
| `--logs` | Only monitor logs whose URL contains any of these comma-separated substrings |
| `--exclude-logs` | Skip logs whose URL contains any of these comma-separated substrings |

> ⚠️ **Key `--fetch-workers` by log family (`argon=16`), not by shard (`argon2026h2=4`).** A key is matched as a
> substring of the log URL, and a log that no key matches is fetched on ONE range. Logs are sharded by certificate
> expiry and a new shard opens every half-year, so a shard key leaves the newest shard, which receives most new
> certificates, on a single range. That is how `argon2027h1` fell tens of millions of entries behind in October 2026:
> one range fetched ~26 entries/s while the log grew ~250/s.
>
> ⚠️ **`--max-backlog` skips for good.** Before restarting, compare each log's saved position with its live
> `get-sth` tree size; a log further behind than `--max-backlog` loses the difference on start. Raise the limit
> first if those entries matter.

### Splitting the logs across processes

Parsing certificates is CPU-bound, and one Python process uses one core, roughly 1,000 log entries per
second. When the logs together grow faster than that, run several processes that share the logs. Give
each its own state file, and let one of them use `--exclude-logs`, so that any log added to Chrome's list
later is picked up by that one:

```bash
python3 ct-monitor.py -f --new-fetcher-logs all --logs argon --state-file state/positions-argon.json
python3 ct-monitor.py -f --new-fetcher-logs all --logs xenon --state-file state/positions-xenon.json
python3 ct-monitor.py -f --new-fetcher-logs all --exclude-logs argon,xenon --state-file state/positions.json
```

A selection that matches no log exits with code 2 instead of running idle.

### Stopping without losing entries

The saved position counts entries that have been fetched and queued. On `SIGTERM` the monitor stops
fetching, lets the workers and the writer finish everything already queued, saves the positions, and
exits. A restart therefore resumes without a gap. If entries or results are still queued after
`CT_DRAIN_TIMEOUT` seconds, it logs what is left and exits with code 3. Pending DNS lookups are best
effort: the stop gives them `CT_DRAIN_DNS_TIMEOUT` seconds and reports how many were not done. Under
systemd, set `TimeoutStopSec` above `CT_DRAIN_TIMEOUT`. `Ctrl-C` still stops immediately.

| Environment variable | Default | Meaning |
|---|---|---|
| `CT_QUEUE_MAX` | 100000 | Size of the input and output queues. Fetching pauses while they are full, so memory stays bounded. Smaller queues drain faster on stop |
| `CT_DRAIN_TIMEOUT` | 150 | Seconds a `SIGTERM` stop waits for queued entries and results |
| `CT_DRAIN_DNS_TIMEOUT` | 10 | Seconds a `SIGTERM` stop then waits for pending DNS lookups |
| `CT_DRAIN_FETCH_WAIT` | 5 | Seconds a `SIGTERM` stop waits for requests still in flight. Positions are frozen when the stop begins, so anything fetched later is fetched again on the next start |

### DNS resolution (`--dns-resolve`)

- With Elasticsearch output, a name is resolved when its certificate document is first **created**
  that day: not again for the same certificate in another log, nor for a final certificate that
  replaces its precertificate.
- A wildcard name `*.example.com` resolves `example.com` only. No subdomains are guessed.
- Lookups run continuously, with `2 x --dns-workers` in flight per resolver thread (4 threads).
- Answers are cached by host name (`--dns-cache-size` entries, 15 minutes).
- Every 60 seconds a `🔎 DNS:` line reports the queue, drops, lookups per second and the cache hit
  rate, even with `--quiet`. With `--state-file`, the same numbers are written to
  `stats-<state file name>` next to it.
| `CT_ES_RETRY_MAX_DOCS` | 200000 | Documents held for an Elasticsearch retry before the writer pauses |

## 🐳 Docker Usage

You can also run ct-monitor using the official Docker image from Docker Hub, built for `linux/amd64`
and `linux/arm64`.

| Tag | Image |
|-----|-------|
| `latest`, `1.4.0`, `1.4` | The current release |
| `latest-attested`, `1.4.0-attested` | The same image. Every image now carries SBOM and provenance attestations ([SECURE_ATTESTATIONS.md](SECURE_ATTESTATIONS.md)) |
| `1.3.0`, `1.2.0` | Earlier releases, kept for pinning |

To build the image from this repository instead: `docker build -t ct-monitor .`

### Pull the image

```bash
docker pull jonaslejon/ct-monitor:latest
```

### Run the container

```bash
# Monitor recent certificates from all CT logs
docker run --rm -it jonaslejon/ct-monitor:latest -n 1000

# Search for specific domains
docker run --rm -it jonaslejon/ct-monitor:latest -m ".*\.example\.com$" -n 2000

# Continuous monitoring
docker run --rm -it jonaslejon/ct-monitor:latest -f -n 500

# With DNS resolution (requires .env file mounted)
docker run --rm -it -v $(pwd)/.env:/app/.env jonaslejon/ct-monitor:latest --es-output --dns-resolve --dns-public -n 1000

# Long-running, gap-free, resuming after a restart: keep the state file in the /data volume
docker run -d --name ct-monitor --stop-timeout 180 -v ct-state:/data -v $(pwd)/.env:/app/.env \
  jonaslejon/ct-monitor:latest --es-output -f --new-fetcher-logs all --state-file /data/state.json
```

`docker stop` sends `SIGTERM` but kills the container after 10 seconds unless told otherwise. Give the
graceful stop more time than `CT_DRAIN_TIMEOUT` (150 s by default) with `--stop-timeout 180` on
`docker run`, or `stop_grace_period: 3m` in Compose.

### Advanced Examples

```bash
# Quiet mode for automation
python3 ct-monitor.py -q -m "github" -n 5000 > domains.json

# Verbose debugging
python3 ct-monitor.py -v -l https://ct.googleapis.com/logs/eu1/xenon2026h2/ -n 100

# Find email-containing certificates
python3 ct-monitor.py -q -n 10000 | jq 'select(.email != null)'

# Monitor specific patterns with custom rate limiting
python3 ct-monitor.py -m ".*\.microsoft\.com$" -p 30 -f

# Elasticsearch output with timeout
python3 ct-monitor.py --es-output --timeout 30 -f

# Batch processing to Elasticsearch
python3 ct-monitor.py --es-output -n 5000
```

## 📋 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --log-url` | Monitor specific CT log URL | All logs |
| `-n, --tail-count` | Entries from end to start from | 100 |
| `-p, --poll-time` | Seconds between polls | 10 |
| `-f, --follow` | Follow mode (continuous) | False |
| `-m, --pattern` | Regex pattern for filtering | None |
| `-v, --verbose` | Detailed processing info | False |
| `-q, --quiet` | Suppress status messages | False |
| `--timeout` | Run for specified minutes then exit | None |
| `--es-output` | Output to Elasticsearch instead of stdout | False |
| `--dns-resolve` | Enable DNS resolution for discovered domains | False |
| `--dns-public` | Use public DNS resolvers with round-robin | False |
| `--dns-workers` | DNS concurrency: each of the 4 resolver threads keeps 2 × this many lookups in flight | 20 |
| `--dns-cache-size` | Host names kept in the DNS answer cache (15 minutes) | 10000 |
| `--new-fetcher-logs` | Use the gap-free fetcher for logs whose URL contains any of these comma-separated substrings, or `all` | None |
| `--fetch-workers` | Parallel ranges per log for the gap-free fetcher, e.g. `argon=16` (a URL substring: key by log family, not shard) | 1 |
| `--state-file` | Persist each log's position here and resume from it after a restart | None |
| `--max-backlog` | On start, skip ahead if a saved position is further behind than this | 2000000 |
| `--logs` | Only monitor logs whose URL contains any of these comma-separated substrings | All logs |
| `--exclude-logs` | Skip logs whose URL contains any of these comma-separated substrings | None |

## 📊 Output Format

The tool outputs JSON lines with certificate information:

```json
{
  "name": "example.com",
  "ts": 1750518406484,
  "cn": "example.com",
  "sha1": "abc123...",
  "dns": ["www.example.com"],
  "email": ["admin@example.com"],
  "ip": ["192.168.1.1"],
  "ik": "3f1c…:4b2e…",
  "pc": false
}
```

One line is written per name in the certificate.

### Output Fields

- **name**: Domain name extracted from certificate
- **ts**: Certificate timestamp (milliseconds)
- **cn**: Common Name from certificate subject
- **sha1**: SHA1 hash of certificate
- **dns**: The certificate's other DNS names, without `name` itself (optional)
- **email**: Email addresses from certificate (optional)
- **ip**: IP addresses from certificate (optional)
- **ik**: Issuer + serial number. A precertificate and its final certificate share it
- **pc**: `true` for a precertificate

## 🎯 Use Cases

### Security Monitoring
```bash
# Monitor your organization's domains
python3 ct-monitor.py -f -m ".*\.yourcompany\.com$"

# Detect typosquatting
python3 ct-monitor.py -m ".*(microsoft|google|amazon).*" -f
```

### Reconnaissance & Research
```bash
# Discover subdomains
python3 ct-monitor.py -q -m ".*\.target\.com$" -n 10000 | jq -r '.name' | sort -u

# Find certificates by country TLD
python3 ct-monitor.py -m ".*\.se$" -n 5000

# Extract email addresses
python3 ct-monitor.py -q -n 20000 | jq -r '.email[]?' | sort -u
```

### Automation & Integration
```bash
# Export to CSV
python3 ct-monitor.py -q -n 5000 | jq -r '[.name,.cn,.sha1] | @csv'

# Real-time alerting
python3 ct-monitor.py -q -f -m "suspicious.*pattern" | while read cert; do
  echo "Alert: $cert" | mail -s "Certificate Alert" admin@company.com
done

# Database integration
python3 ct-monitor.py -q -f | while read line; do
  curl -X POST -H "Content-Type: application/json" -d "$line" http://api.internal/certs
done

# Elasticsearch integration
python3 ct-monitor.py --es-output -f  # Continuous to ES
python3 ct-monitor.py --es-output -n 10000  # Batch to ES
```

## 🔥 Rate Limiting & Performance

### Current CT Log Issues (2025)

Many CT logs rate-limit readers, some per log rather than per address:

- **Sectigo logs**: 20 req/sec per IP, 400 req/sec global limit
- **High error rates**: Some logs have availability below the recommended 99%
- **Recommended**: Use higher `-p` values (30-60 seconds) for Sectigo logs with the classic fetch loop
- **Gap-free fetcher**: a 429, 503 or 504 makes only that range back off (2 s, doubling to 60 s, with
  jitter); the log is never given up

### Optimization Tips

```bash
# Avoid problematic logs
python3 ct-monitor.py -l https://ct.googleapis.com/logs/eu1/xenon2026h2/ -n 5000

# Use higher poll intervals for rate-limited logs
python3 ct-monitor.py -p 60 -f

# Process smaller batches more frequently
python3 ct-monitor.py -n 500 -p 30 -f
```

## 📈 Statistics & Monitoring

The tool provides comprehensive statistics:

```
📊 Final Statistics:
  🎯 Total entries processed: 15000
  ✅ Valid certificates: 14985 (99.9%)
  ❌ Parse errors: 15 (0.1%)
  🎯 Pattern matches: 25 (0.2% of valid certs)
  ⚠️ Rate limited logs: 8 (consider using -p with higher value)
```

## 🚨 Error Handling

The tool gracefully handles:

- **Rate limiting**: Exponential backoff with automatic retry
- **Network failures**: Automatic retry with configurable timeouts
- **Certificate parsing errors**: Graceful skipping of malformed certificates
- **Keyboard interrupts**: Clean shutdown with statistics display

## 🐛 Troubleshooting

### Common Issues

**High parse error rates**:
- The classic fetch loop skips precertificates, and many CAs log some certificates only as a
  precertificate. Use the gap-free fetcher (`--new-fetcher-logs all`), which parses them.

**Rate limiting errors**:
```bash
# Use longer poll intervals
python3 ct-monitor.py -p 30

# Monitor specific logs instead of all
python3 ct-monitor.py -l https://ct.googleapis.com/logs/eu1/xenon2026h2/
```

**No pattern matches**:
```bash
# Test your regex pattern
python3 ct-monitor.py -v -m "your-pattern" -n 100

# Try broader patterns
python3 ct-monitor.py -m "microsoft" -n 2000
```

### Debug Mode

```bash
# Maximum verbosity
python3 ct-monitor.py -v -n 50

# Check specific certificate details
python3 ct-monitor.py -v -l https://ct.googleapis.com/logs/eu1/xenon2026h2/ -n 10
```

## ⚡ Adaptive Rate Limiting

### Overview

The CT monitor implements intelligent per-server rate limiting that automatically adapts to each CT log server's behavior. The batch and poll-interval steps below apply to the classic fetch loop. The gap-free fetcher backs off per request instead (see Rate Limiting & Performance), and the circuit breaker applies to both:

### Features

- **Per-Server Adaptation**: Each CT log server is tracked independently
- **Progressive Backoff**: Batch sizes and poll intervals adjust based on server responses
- **Circuit Breaker**: Temporarily excludes problematic servers after repeated failures
- **Automatic Recovery**: Gradually restores normal operation when servers become responsive

### How It Works

1. **After 3 rate limits**: Batch size reduced by 50%
2. **After 5 rate limits**: Poll interval doubled (up to 8x)
3. **After 10 rate limits**: Server excluded for 30 minutes (circuit breaker)
4. **On success**: Gradually increases batch size and reduces delays

### Status Indicators

- ✅ Healthy server (no issues)
- ⚠️ Warning (occasional rate limits)
- ⛔ Problematic (frequent rate limits)
- ❌ Severe issues (many failures)
- 🚫 Excluded (circuit breaker activated)

### Example Output

```
📊 Rate Limit Status:
  ⛔ sabre2025h2.ct.sectigo.com: batch=25, delay=4.0x, failures=6
  🚫 mammoth2026h2.ct.sectigo.com: EXCLUDED until 14:30:00
  ⚠️ tiger2025h2.ct.sectigo.com: batch=50, delay=2.0x, failures=3
```

This ensures optimal performance across all servers while respecting their individual rate limits.

## 🔍 DNS Resolution

### Overview

The DNS resolution feature automatically resolves discovered domains to IP addresses, storing the results in Elasticsearch for bidirectional lookups (domain→IP and IP→domain). This is invaluable for security analysis, infrastructure mapping, and threat intelligence.

### Features

- **Continuous async resolution**: Each resolver thread keeps a fixed number of lookups in flight
- **Host cache**: An LRU cache keyed by host name avoids repeated queries
- **Once per certificate**: With `--es-output`, a name is resolved when its certificate document is
  first created that day, not again for every log or for a final certificate replacing its precertificate
- **Wildcards**: `*.example.com` resolves `example.com` only. No subdomains are guessed.
- **Public DNS Round-Robin**: Distributes queries across 6 major DNS providers to avoid rate limits
- **Status**: A `🔎 DNS:` line every 60 seconds (queue, drops, lookups per second, cache hit rate)
- **Elasticsearch Storage**: Time-based indices with certificate linkage for security analysis

### Local DNS Resolver (Unbound/BIND)

#### systemd-resolved Detection

The tool automatically detects if you're using systemd-resolved (common on Ubuntu/Debian):

```bash
# If /etc/resolv.conf shows nameserver 127.0.0.53
python3 ct-monitor.py --dns-resolve --es-output
# Output: "✅ Using systemd-resolved stub resolver at 127.0.0.53"
```

With systemd-resolved, DNS queries follow this path:
`ct-monitor → systemd-resolved (127.0.0.53) → upstream resolver (unbound/etc)`

#### Bypassing systemd-resolved

To use unbound or another local resolver directly:

```bash
# Force DNS resolution through local unbound resolver
export DNS_LOCAL_RESOLVER=127.0.0.1
python3 ct-monitor.py --dns-resolve --es-output

# The tool will show: "🔧 Forcing DNS resolver to: 127.0.0.1"
```

This ensures all DNS queries go directly to your specified resolver, bypassing systemd-resolved.

#### Verifying DNS Query Flow

```bash
# Check systemd-resolved statistics
systemd-resolve --statistics

# Check unbound statistics (if using unbound)
sudo unbound-control stats | grep -E "total.num.queries"

# Monitor DNS queries in real-time
sudo tcpdump -ni any port 53
```

### Public DNS Resolvers

When using `--dns-public`, queries are distributed round-robin across:
- **Cloudflare**: 1.1.1.1, 1.0.0.1
- **Google**: 8.8.8.8, 8.8.4.4
- **Quad9**: 9.9.9.9, 149.112.112.112

### Basic Usage

```bash
# Enable DNS resolution with system resolver
python3 ct-monitor.py --es-output --dns-resolve -n 1000

# Use public DNS resolvers with round-robin
python3 ct-monitor.py --es-output --dns-resolve --dns-public -n 1000

# Customize DNS workers and cache
python3 ct-monitor.py --es-output --dns-resolve --dns-public --dns-workers 50 --dns-cache-size 20000

# Continuous monitoring with DNS resolution
python3 ct-monitor.py --es-output --dns-resolve --dns-public -f
```

### DNS Data in Elasticsearch

DNS results are stored in daily `ct-dns-YYYY-MM-DD` indices with:
- **Bidirectional lookups**: Query by domain or IP
- **Certificate linkage**: `c` is the SHA-1 of the certificate in which the name was first seen that day
- **Lookup outcome**: `e` is `nxdomain`, `noanswer` (no A record), `timeout`, `servfail` or `unknown` when the lookup failed
- **Compact storage**: ~50-80 bytes per record with compression
- **Deduplication**: Hash-based prevention of duplicate entries

### Query Examples

```bash
# Find all IPs for a domain (using Elasticsearch)
curl -X GET "localhost:9200/ct-dns-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": { "term": { "d": "example.com" } }
}'

# Find all domains on an IP
curl -X GET "localhost:9200/ct-dns-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": { "term": { "i": "192.168.1.1" } }
}'

# Find all domains/IPs for a certificate
curl -X GET "localhost:9200/ct-dns-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": { "term": { "c": "cert_sha1_here" } }
}'
```

### Performance & Rate Limiting

- **Round-robin distribution** prevents rate limiting from any single DNS provider
- **Continuous resolution**: a slow or timed-out lookup does not hold back the others
- **Async resolution** enables high throughput (hundreds of lookups per second against a local resolver)
- **Cache prevents** redundant queries for recently resolved domains

### Use Cases

**Infrastructure Mapping**:
```bash
# Map all infrastructure for an organization
python3 ct-monitor.py --es-output --dns-resolve --dns-public -m ".*\.company\.com$" -f
```

**CDN Detection**:
```bash
# Identify domains using specific CDNs
python3 ct-monitor.py --es-output --dns-resolve --dns-public -n 10000
# Then query Elasticsearch for IPs in Cloudflare ranges (104.x.x.x)
```

**Security Analysis**:
```bash
# Track certificate/IP relationships
python3 ct-monitor.py --es-output --dns-resolve --dns-public -f
# Query for certificates that suddenly change IPs
```

## 📊 Elasticsearch Integration

### Configuration

The tool supports Elasticsearch output via environment variables. Create a `.env` file based on the provided template:

```bash
# Copy the example file
cp .env.example .env

# Edit with your Elasticsearch credentials
nano .env
```

**Example .env file:**
```env
ES_HOST=http://localhost:9200
ES_USER=elastic
ES_PASSWORD=your_secure_password_here
```

### Usage

```bash
# Send output to Elasticsearch
python3 ct-monitor.py --es-output -n 1000

# Continuous monitoring to Elasticsearch
python3 ct-monitor.py --es-output -f

# With custom timeout
python3 ct-monitor.py --es-output --timeout 60 -n 5000
```

### Error Handling & Reliability

- ✅ **Startup validation**: Fails immediately if Elasticsearch is unreachable or credentials are invalid
- ✅ **Runtime retries**: Failed batches are automatically retried every 30 seconds
- ✅ **Final retry attempt**: All failed batches are retried during graceful shutdown
- ✅ **Connection errors**: Clear error messages distinguish between authentication failures and connection issues

### Security Notes

- ✅ **Never commit `.env`** to version control (it's in `.gitignore`)
- ✅ **Use environment variables** instead of hardcoded credentials
- ✅ **Create dedicated service account** with minimal privileges
- ✅ **Change default passwords** from installation defaults

### 💾 Elasticsearch Storage Requirements & Efficiency

Measured in production in late September 2026, following every RFC 6962 log in Chrome's list with
the gap-free fetcher:

- **~160 bytes per document**, including the full SAN list
- **~37 million documents per day** (one per domain and issued certificate), **~6 GB per day**
- Daily volume varies with CA issuance, and roughly doubles while a large backlog is being caught up

Plan disk for the retention you want: 90 days at that rate is roughly 0.55 TB, before replicas.

## ⚠️ Limitations

This tool is a **non-verifying monitor**. It correctly parses certificate data from logs but does not perform the cryptographic verification steps of a full CT auditor. Specifically, it does not:

- **Verify Signed Certificate Timestamps (SCTs)**: The script does not verify the signature on the SCT to ensure it was issued by a trusted log. It trusts the log server to provide authentic data.
- **Verify Merkle Tree Consistency**: It does not verify inclusion proofs or consistency between different Signed Tree Heads (STHs).

For most monitoring and data extraction purposes, this is a safe and efficient approach. If you require full cryptographic verification, you should use a dedicated CT auditing tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
git clone https://github.com/jonaslejon/ct-monitor.git
cd ct-monitor
pip install -r requirements.txt
```

### Running Tests

```bash
# Unit tests
python3 -m pytest test_ct-monitor.py test_fetcher.py test_precert.py test_es_retry_cap.py \
    test_split_drain.py test_dns_pipeline.py

# Test basic functionality
python3 ct-monitor.py -n 10

# Test pattern matching
python3 ct-monitor.py -m "test" -n 50

# Test rate limiting handling
python3 ct-monitor.py -l https://tiger2026h2.ct.sectigo.com/ -n 100
```

## 📋 TODO & Future Enhancements

### Current Limitations
- **No automatic cleanup**: Older certificate entries are not automatically removed from Elasticsearch
- **Manual index management**: Users need to manually manage index retention and cleanup

### Planned Features

**Core Enhancements**:
- **Automatic retention policies**: Configurable TTL for certificate data
- **Index lifecycle management**: Automated index rotation and deletion
- **Compression optimization**: Further storage efficiency improvements
- **Cluster support**: Distributed Elasticsearch cluster support

**Security & Verification**:
- **SCT verification**: Signed Certificate Timestamp validation
- **Merkle tree proofs**: Log consistency verification
- **Certificate chain validation**: Full chain of trust validation
- **Revocation checking**: OCSP and CRL integration

**Advanced Functionality**:
- **Web interface**: Dashboard for data exploration
- **Alerting system**: Notifications for specific patterns
- **API endpoints**: REST API for querying results
- **Multiple export formats**: CSV, SQLite, Parquet support
- **Advanced filtering**: By issuer, key type, validity period
- **Threat intelligence**: Integration with TI feeds
- **Domain categorization**: Automated domain classification

**Operational Improvements**:
- **Configuration files**: YAML/JSON config support
- **Performance metrics**: Prometheus/Grafana integration
- **Historical backfilling**: Import historical CT data
- **Subdomain analysis**: Pattern-based subdomain enumeration

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Certificate Transparency project by Google
- [cryptography](https://cryptography.io/) library for certificate parsing
- [colorama](https://github.com/tartley/colorama) for cross-platform colored output
- CT log operators for providing public transparency data

## 📚 Related Tools

- [crt.sh](https://crt.sh/) - Certificate search web interface
- [Certstream](https://certstream.calidog.io/) - Real-time certificate transparency monitoring
- [ct-exposer](https://github.com/chris408/ct-exposer) - Discover subdomains via CT logs

---

⭐ **Star this repository if you find it useful!**
