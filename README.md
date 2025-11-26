# cidrx

High-performance botnet detection tool that analyzes HTTP logs and automatically identifies attack patterns by clustering IP addresses into CIDR ranges.

**[📚 Full Documentation →](https://christianf88.github.io/cidrx/)**

## About

cidrx helps you identify and block botnets attacking your web services by:

1. **Analyzing HTTP logs** (Nginx, Apache, custom formats)
2. **Clustering malicious IPs** into CIDR ranges automatically
3. **Generating block lists** for firewalls, nginx, iptables

**Two modes:**
- **Static**: Analyze historical logs (post-incident, audits)
- **Live**: Real-time monitoring with automatic banning

**Performance:** 2.4M+ requests/sec on commodity hardware

## Quick Start

### Installation

```bash
git clone https://github.com/ChristianF88/cidrx.git
cd cidrx/cidrx/src
go build -o cidrx .
```

### Basic Example

Analyze a log file and detect potential botnets:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --startTime "2025-01-15T00:00:00Z" \
  --endTime "2025-01-15T23:59:59Z" \
  --useragentRegex ".*bot.*|.*scanner.*" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

**Output:**
```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Rate:      1,373,322 requests/sec
Duration:        1078 ms

🔍 CLUSTERING RESULTS
────────────────────────────────────────────────────────────────────────────────
Set 1: min_size=1000, depth=24-32, threshold=0.10
  45.40.50.192/26      3,083 requests  (  0.29%)
  123.55.205.91/32     1,308 requests  (  0.12%)
  ─────────────────    4,391 requests  (  0.41%) [TOTAL]
```

### What This Does

1. **Parsing**: Reads log file at 1M+ requests/sec
2. **Filtering**: Optionally filter by URL patterns, User-Agent, time windows
3. **Clustering**: Detects IP clusters with configurable parameters:
   - `1000` = minimum requests required in cluster
   - `24,32` = CIDR range size (min /24, max /32)
   - `0.1` = 10% clustering threshold

## Learn More

**📖 Documentation:** https://christianf88.github.io/cidrx/

- [Installation Guide](https://christianf88.github.io/cidrx/docs/getting-started/installation/) - Detailed setup
- [Static Mode](https://christianf88.github.io/cidrx/docs/usage/static-mode/) - Historical analysis
- [Live Mode](https://christianf88.github.io/cidrx/docs/usage/live-mode/) - Real-time protection
- [Configuration](https://christianf88.github.io/cidrx/docs/configuration/config-files/) - TOML files and filtering
- [Docker Setup](https://christianf88.github.io/cidrx/docs/usage/docker/) - Test environment

## Features

- ⚡ **Ultra-Fast**: 1M+ requests/sec parsing
- 🔍 **Smart Detection**: Multiple clustering strategies
- 🛡️ **Real-Time**: Live mode with automatic banning
- 🎯 **Flexible**: Regex filtering, whitelist/blacklist
- 📊 **Multiple Outputs**: JSON, plain text, interactive TUI

## License

MIT License - See [LICENSE](LICENSE) file for details
