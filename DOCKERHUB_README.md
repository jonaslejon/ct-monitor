# 🔍 Certificate Transparency Log Monitor

A powerful Python tool for monitoring Certificate Transparency (CT) logs to extract domain names, IP addresses, and email addresses from SSL/TLS certificates in real-time.

## 🐳 Docker Image

### Quick Start

```bash
# Pull the latest image
docker pull jonaslejon/ct-monitor:latest

# Monitor recent certificates from all CT logs
docker run --rm jonaslejon/ct-monitor:latest -n 1000

# Search for specific domains
docker run --rm jonaslejon/ct-monitor:latest -m ".*\.example\.com$" -n 2000

# Continuous monitoring
docker run --rm jonaslejon/ct-monitor:latest -f -n 500
```

### Image Tags

- `latest`, `1.4.0`, `1.4` - Current release (v1.4.0)
- `latest-attested`, `1.4.0-attested` - The same image; every image carries SBOM and provenance attestations
- `1.3.0`, `1.2.0` - Earlier releases

### What's New in v1.4.0

- **Gap-free fetching**: follows the entries a log actually returns, fetches ranges in parallel, and resumes from a state file after a restart (`--new-fetcher-logs`, `--fetch-workers`, `--state-file`)
- **Precertificates are parsed**: many CAs log some certificates only as a precertificate
- **One Elasticsearch document per issued certificate**: a precertificate and its final certificate collapse, and a certificate seen in several logs is stored once per daily index
- **Bounded memory**: bounded queues and a capped Elasticsearch retry list
- **Several processes can share the logs** (`--logs`, `--exclude-logs`)
- **Stopping loses nothing**: `SIGTERM` drains the queues before exiting
- **DNS resolution rework**: each name is resolved once, wildcards resolve their base name, lookups run continuously
- **Image fixes**: `/data` is writable by the container user, and the health check that probed `localhost:9200` inside the container (always unhealthy) is gone

### Features

- 🚀 **Multi-threaded Processing**: Concurrent monitoring of multiple CT logs
- 🎯 **Pattern Matching**: Regex filtering for targeted domain discovery
- 🤫 **Quiet Mode**: Clean JSON output perfect for automation
- 🔍 **Verbose Mode**: Detailed certificate processing information
- 📊 **Real-time Statistics**: Progress tracking and success rates
- ⚡ **Adaptive Rate Limiting**: Per-server rate control with a circuit breaker
- 🔄 **Follow Mode**: Continuous monitoring for new certificates
- 🧭 **Gap-free Fetching**: Parallel ranges per log, resume from a state file, graceful stop
- 🌐 **Global Coverage**: Monitors all known CT logs or specific targets
- 🌍 **DNS Resolution**: Resolve discovered domains, optionally via public resolvers in round-robin
- 📦 **Elasticsearch Integration**: Daily indices, de-duplicated document ids, automatic retry

### Advanced Docker Usage

```bash
# Quiet mode for automation
docker run --rm jonaslejon/ct-monitor:latest -q -m "github" -n 5000 > domains.json

# Verbose debugging
docker run --rm jonaslejon/ct-monitor:latest -v -l https://ct.googleapis.com/logs/eu1/xenon2026h2/ -n 100

# Elasticsearch output (requires env variables)
docker run --rm -e ES_HOST=http://elasticsearch:9200 \
  -e ES_USER=elastic -e ES_PASSWORD=your_password \
  jonaslejon/ct-monitor:latest --es-output -n 5000

# Long-running, gap-free, resuming after a restart: keep the state file in the /data volume
docker run -d --name ct-monitor --stop-timeout 180 -v ct-state:/data \
  -e ES_HOST=http://elasticsearch:9200 -e ES_USER=elastic -e ES_PASSWORD=your_password \
  jonaslejon/ct-monitor:latest --es-output -f --new-fetcher-logs all --state-file /data/state.json
```

`docker stop` kills a container 10 seconds after `SIGTERM` unless told otherwise. Give the graceful stop
more time than `CT_DRAIN_TIMEOUT` (150 s by default): `--stop-timeout 180` on `docker run`, or
`stop_grace_period: 3m` in Compose.

### Environment Variables for Elasticsearch

```bash
ES_HOST=http://localhost:9200          # Elasticsearch host
ES_USER=elastic                        # Elasticsearch username
ES_PASSWORD=your_password              # Elasticsearch password
```

They can also come from a `.env` file mounted at `/app/.env`. The README lists the tuning variables
(`CT_DRAIN_TIMEOUT`, queue sizes, retry caps).

### Docker Compose Example

See [`docker-compose.example.yml`](https://github.com/jonaslejon/ct-monitor/blob/main/docker-compose.example.yml) for a complete setup with Elasticsearch and Kibana.

### Image Details

- **Base Image**: Python 3.13 Alpine
- **Architecture**: Multi-arch (amd64, arm64)
- **Security**: Non-privileged user, minimal dependencies, SBOM and provenance attestations
- **Volume**: `/data`, writable by the container user (use it for `--state-file`)

### Source Code

- GitHub: https://github.com/jonaslejon/ct-monitor
- Dockerfile: https://github.com/jonaslejon/ct-monitor/blob/main/Dockerfile

### License

MIT License - See [LICENSE](https://github.com/jonaslejon/ct-monitor/blob/main/LICENSE)

### Support

- Issues: https://github.com/jonaslejon/ct-monitor/issues
- Documentation: https://github.com/jonaslejon/ct-monitor#readme
