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

- `latest` - Latest stable release (currently v1.2.0)
- `1.2.0` - Specific version release
- `1.1.1` - Previous version

### What's New in v1.2.0

- **Python 3.13** - Updated to latest Python version
- **Smaller Image** - 99.7MB (reduced from 119MB)
- **Elasticsearch 8.15.0** - Latest Elasticsearch support
- **Environment Optimization** - Proper Python environment variables
- **Multi-stage Build** - Optimized build process

### Features

- 🚀 **Multi-threaded Processing**: Concurrent monitoring of multiple CT logs
- 🎯 **Pattern Matching**: Regex filtering for targeted domain discovery
- 🤫 **Quiet Mode**: Clean JSON output perfect for automation
- 🔍 **Verbose Mode**: Detailed certificate processing information
- 📊 **Real-time Statistics**: Progress tracking and success rates
- ⚡ **Rate Limit Handling**: Smart exponential backoff for CT log rate limits
- 🔄 **Follow Mode**: Continuous monitoring for new certificates
- 🌐 **Global Coverage**: Monitors all known CT logs or specific targets
- 📦 **Elasticsearch Integration**: Direct output to Elasticsearch

### Advanced Docker Usage

```bash
# Quiet mode for automation
docker run --rm jonaslejon/ct-monitor:latest -q -m "github" -n 5000 > domains.json

# Verbose debugging
docker run --rm jonaslejon/ct-monitor:latest -v -l https://ct.googleapis.com/logs/xenon2025/ -n 100

# Elasticsearch output (requires env variables)
docker run --rm -e ES_HOST=http://elasticsearch:9200 \
  -e ES_USER=elastic -e ES_PASSWORD=your_password \
  jonaslejon/ct-monitor:latest --es-output -n 5000

# Continuous monitoring to Elasticsearch
docker run --rm -e ES_HOST=http://elasticsearch:9200 \
  jonaslejon/ct-monitor:latest --es-output -f
```

### Environment Variables for Elasticsearch

```bash
ES_HOST=http://localhost:9200          # Elasticsearch host
ES_USER=elastic                        # Elasticsearch username
ES_PASSWORD=your_password              # Elasticsearch password
```

### Docker Compose Example

See `docker-compose.example.yml` for a complete setup with Elasticsearch and Kibana.

### Image Details

- **Base Image**: Python 3.13 Alpine
- **Size**: 99.7MB
- **Architecture**: Multi-arch support (amd64, arm64)
- **Security**: Non-privileged user, minimal dependencies
- **Health Check**: Built-in health monitoring

### Source Code

- GitHub: https://github.com/jonaslejon/ct-monitor
- Dockerfile: https://github.com/jonaslejon/ct-monitor/blob/main/Dockerfile

### License

MIT License - See [LICENSE](https://github.com/jonaslejon/ct-monitor/blob/main/LICENSE)

### Support

- Issues: https://github.com/jonaslejon/ct-monitor/issues
- Documentation: https://github.com/jonaslejon/ct-monitor#readme