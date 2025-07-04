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
- **⚡ Rate Limit Handling**: Smart exponential backoff for CT log rate limits
- **🔄 Follow Mode**: Continuous monitoring for new certificates
- **🌐 Global Coverage**: Monitors all known CT logs or specific targets

## 🔧 Installation

### Prerequisites

```bash
pip install requests cryptography publicsuffix2 colorama
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
