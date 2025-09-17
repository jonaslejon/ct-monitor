# 🔍 Certificate Transparency Log Monitor

A powerful Python tool for monitoring Certificate Transparency (CT) logs to extract domain names, IP addresses, and email addresses from SSL/TLS certificates in real-time.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 🌟 Features

- **🚀 Multi-threaded Processing**: Concurrent monitoring of multiple CT logs
- **🎯 Pattern Matching**: Regex filtering for targeted domain discovery  
- **🤫 Quiet Mode**: Clean JSON output perfect for automation
- **🔍 Verbose Mode**: Detailed certificate processing information
- **📊 Real-time Statistics**: Progress tracking and success rates
- **⚡ Adaptive Rate Limiting**: Per-server adaptive rate control with circuit breaker pattern
- **🔄 Follow Mode**: Continuous monitoring for new certificates
- **🌐 Global Coverage**: Monitors all known CT logs or specific targets
- **🔍 DNS Resolution**: Resolve discovered domains to IP addresses with caching
- **🌍 Public DNS Round-Robin**: Distribute queries across 6 major DNS providers

## 🔧 Installation

### Prerequisites

```bash
# Core requirements
pip install requests cryptography publicsuffix2 colorama python-dotenv

# Optional: For DNS resolution feature (recommended)
pip install dnspython
```

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

## 🐳 Docker Usage

You can also run ct-monitor using the official Docker image from Docker Hub.

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
```

### Advanced Examples

```bash
# Quiet mode for automation
python3 ct-monitor.py -q -m "github" -n 5000 > domains.json

# Verbose debugging
python3 ct-monitor.py -v -l https://ct.googleapis.com/logs/xenon2025/ -n 100

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
| `--dns-workers` | Number of concurrent DNS resolution workers | 20 |
| `--dns-cache-size` | DNS cache size for deduplication | 10000 |

## 📊 Output Format

The tool outputs JSON lines with certificate information:

```json
{
  "name": "example.com",
  "ts": 1750518406484,
  "cn": "example.com", 
  "sha1": "abc123...",
  "dns": ["example.com", "www.example.com"],
  "email": ["admin@example.com"],
  "ip": ["192.168.1.1"]
}
```

### Output Fields

- **name**: Domain name extracted from certificate
- **ts**: Certificate timestamp (milliseconds)
- **cn**: Common Name from certificate subject
- **sha1**: SHA1 hash of certificate
- **dns**: All DNS names from certificate (optional)
- **email**: Email addresses from certificate (optional)  
- **ip**: IP addresses from certificate (optional)

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

Many CT logs, especially Sectigo's, are experiencing severe rate limiting:

- **Sectigo logs**: 20 req/sec per IP, 400 req/sec global limit
- **High error rates**: Some logs have availability below the recommended 99%
- **Recommended**: Use higher `-p` values (30-60 seconds) for Sectigo logs

### Optimization Tips

```bash
# Avoid problematic logs
python3 ct-monitor.py -l https://ct.googleapis.com/logs/xenon2025/ -n 5000

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
  ✅ Valid certificates: 9500 (63.3%)
    ❌ Parse errors: 5500 (36.7%)
  🎯 Pattern matches: 25 (0.3% of valid certs)
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
- Normal for CT logs (a small percentage of failure is typical)
- Precertificates are harder to parse than regular certificates

**Rate limiting errors**:
```bash
# Use longer poll intervals
python3 ct-monitor.py -p 30

# Monitor specific logs instead of all
python3 ct-monitor.py -l https://ct.googleapis.com/logs/xenon2025/
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
python3 ct-monitor.py -v -l https://ct.googleapis.com/logs/xenon2025/ -n 10
```

## ⚡ Adaptive Rate Limiting

### Overview

The CT monitor implements intelligent per-server rate limiting that automatically adapts to each CT log server's behavior:

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

- **Async Resolution**: High-performance DNS lookups with configurable concurrency
- **Smart Caching**: LRU cache prevents redundant queries
- **SAN Resolution**: Automatically resolves Subject Alternative Names from certificates
- **Wildcard Expansion**: Expands `*.example.com` to common subdomains (www, mail, api, etc.)
- **Public DNS Round-Robin**: Distributes queries across 6 major DNS providers to avoid rate limits
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
- **Certificate linkage**: Track which certificates use which IPs
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
- **Batch processing** groups domains for efficient resolution
- **Async resolution** enables high throughput (100+ lookups/second)
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

Based on production Elasticsearch data analysis with full SAN storage:

**Compression Efficiency**:
- **156 bytes per domain** (including full SAN lists)
- **6.88 million domains per GB**
- **0.15 GB per million domains**

**Daily Storage** (average):
- **~7.15 million domains/day**
- **~1.04 GB/day**

**Projected Storage Needs**:
- **Weekly**: 50M domains, 7.3 GB
- **Monthly**: 215M domains, 31.2 GB
- **Yearly**: 2.61B domains, 379 GB

**Key Insights**:
- ✅ **Excellent Elasticsearch compression**: 156 bytes/domain with complete certificate data
- ✅ **High variability**: Daily volumes can fluctuate significantly (200%+ observed)
- ✅ **Cost-effective**: ~$38/month for 1TB Elasticsearch storage covers yearly data
- ✅ **Scalable**: Elasticsearch schema supports billions of domains efficiently

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
# Test basic functionality
python3 ct-monitor.py -n 10

# Test pattern matching
python3 ct-monitor.py -m "test" -n 50

# Test rate limiting handling
python3 ct-monitor.py -l https://mammoth2025h1.ct.sectigo.com/ -n 100
```

## 📋 TODO & Future Enhancements

### Current Limitations
- **No automatic cleanup**: Older certificate entries are not automatically removed from Elasticsearch
- **Manual index management**: Users need to manually manage index retention and cleanup
- **No deduplication**: Certificates may be stored multiple times if they appear in different CT logs

### Planned Features

**Core Enhancements**:
- **Automatic retention policies**: Configurable TTL for certificate data
- **Index lifecycle management**: Automated index rotation and deletion
- **Deduplication**: Prevent storing duplicate certificates across logs
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
- **Docker containerization**: Easy deployment
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
