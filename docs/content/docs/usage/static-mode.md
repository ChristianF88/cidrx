---
title: "Static Mode"
description: "Using cidrx for historical log analysis and threat detection"
summary: "Complete guide to static mode for analyzing log files and detecting attack patterns"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 210
toc: true
seo:
  title: "cidrx Static Mode Guide"
  description: "Learn how to use cidrx static mode for botnet detection in log files with examples and best practices"
  canonical: ""
  noindex: false
---

Static mode analyzes historical log files to identify attack patterns. It's ideal for post-incident analysis, security audits, and testing detection strategies.

## Basic Usage

### Simple Threat Detection

Analyze a log file with basic clustering:

```bash
./cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

This command:
- Reads `/var/log/nginx/access.log`
- Detects clusters with 1000+ requests
- Searches in /24 to /32 CIDR ranges
- Uses 10% threshold for detection
- Outputs in plain text format

### Multi-Strategy Detection

Run multiple detection strategies simultaneously:

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

Each `--clusterArgSets` parameter runs an independent analysis:
- **First set**: Small clusters (500+) in narrow ranges - catches focused attacks
- **Second set**: Medium clusters (2000+) in mid ranges - catches distributed attacks
- **Third set**: Large clusters (10000+) in wide ranges - catches major botnets

## Advanced Filtering

### User-Agent Filtering

Target specific types of clients:

```bash
./cidrx static --logfile access.log \
  --useragentRegex ".*bot.*|.*scanner.*" \
  --clusterArgSets 100,30,32,0.05 \
  --plain
```

This detects scanning tools and bots by filtering on User-Agent strings.

### Endpoint Filtering

Focus on specific API endpoints or paths:

```bash
./cidrx static --logfile access.log \
  --endpointRegex "/api/.*" \
  --clusterArgSets 100,30,32,0.05 \
  --plain
```

Useful for detecting API abuse or endpoint-specific attacks.

### Combined Filtering

Use multiple filters together:

```bash
./cidrx static --logfile access.log \
  --useragentRegex ".*bot.*|.*scanner.*|.*nikto.*|.*sqlmap.*" \
  --endpointRegex "/api/.*|/admin/.*" \
  --clusterArgSets 100,30,32,0.05 \
  --plain
```

## Time-Bounded Analysis

### Specific Time Window

Analyze a specific time period:

```bash
./cidrx static --logfile access.log \
  --startTime "2025-01-15T00:00:00Z" \
  --endTime "2025-01-15T23:59:59Z" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

Time format is RFC3339 (ISO 8601): `YYYY-MM-DDTHH:MM:SSZ`

### Recent Activity Only

Analyze just the last hour of logs:

```bash
./cidrx static --logfile access.log \
  --startTime "2025-10-09T09:00:00Z" \
  --endTime "2025-10-09T10:00:00Z" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## CIDR Range Focusing

### Analyze Specific Networks

Focus on known problematic networks:

```bash
./cidrx static --logfile access.log \
  --rangesCidr "203.0.113.0/24" \
  --rangesCidr "198.51.100.0/24" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

Multiple `--rangesCidr` options can be specified. This is useful when:
- You've identified suspicious networks from other tools
- You want to verify if specific ASNs are attacking
- You're monitoring known threat actors

## Whitelist and Blacklist Management

### Using Whitelist and Blacklist

Protect legitimate traffic and focus on threats:

```bash
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --blacklist /etc/cidrx/blacklist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Whitelist Format

Create `/etc/cidrx/whitelist.txt`:

```
# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Office IPs
203.0.113.0/24

# CDN and monitoring services
192.0.2.100/32
198.51.100.50/32
```

### Blacklist Format

Create `/etc/cidrx/blacklist.txt`:

```
# Known malicious ranges
45.40.50.0/24
198.51.205.0/24

# Confirmed attack sources
20.171.207.2/32
```

### User-Agent Whitelists/Blacklists

Filter by User-Agent strings:

```bash
./cidrx static --logfile access.log \
  --userAgentWhitelist /etc/cidrx/ua_whitelist.txt \
  --userAgentBlacklist /etc/cidrx/ua_blacklist.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

User-Agent whitelist example (`/etc/cidrx/ua_whitelist.txt`):

```
# Legitimate bots
Googlebot
Bingbot
DuckDuckBot

# Monitoring services
UptimeRobot
Pingdom
```

User-Agent blacklist example (`/etc/cidrx/ua_blacklist.txt`):

```
# Known malicious scanners
sqlmap
nikto
havij
acunetix

# Common attack patterns
python-requests
curl
wget
```

## Jail and Ban File Management

### Understanding Jail Files

The jail file maintains persistent state of detected threats:

```bash
./cidrx static --logfile access.log \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

Jail file (`/tmp/jail.json`) tracks:
- Detected CIDR ranges
- Request counts
- First and last seen timestamps
- Detection strategy that flagged it

### Understanding Ban Files

The ban file (`/tmp/ban.txt`) is a simple list of CIDR ranges:

```
45.40.50.192/26
198.51.205.91/32
20.171.207.2/32
```

This format can be directly used by:
- iptables rules
- nginx deny directives
- Apache mod_rewrite
- Cloud firewall rules

### Importing to Firewall

**iptables example:**

```bash
while read cidr; do
  iptables -I INPUT -s "$cidr" -j DROP
done < /tmp/ban.txt
```

**nginx example:**

```nginx
# Include in nginx.conf
include /tmp/ban.txt;
```

Ban file format for nginx:

```
deny 45.40.50.192/26;
deny 198.51.205.91/32;
deny 20.171.207.2/32;
```

## Configuration File Usage

### Basic Configuration

For complex scenarios, use a TOML configuration file:

```bash
./cidrx static --config cidrx.toml --plain
```

Example `cidrx.toml`:

```toml
[global]
jailFile = "/tmp/cidrx_jail.json"
banFile = "/tmp/cidrx_ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "/tmp/heatmap.html"

[static.comprehensive_scan]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]

[static.security_scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

This configuration:
- Runs two independent analyses (comprehensive_scan and security_scanners)
- Each has its own detection parameters
- Both contribute to the jail file via `useForJail = [true]`

### Multiple Scenarios

Add as many `[static.X]` sections as needed:

```toml
[static.botnet_detection]
clusterArgSets = [[10000,16,24,0.3]]
useForJail = [true]

[static.api_abuse]
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]

[static.admin_probing]
endpointRegex = "/admin/.*|/wp-admin/.*"
clusterArgSets = [[50,30,32,0.01]]
useForJail = [true]
```

## Custom Log Formats

### Nginx Combined Format

Default format works for most Nginx setups:

```bash
./cidrx static --logfile access.log \
  --logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

### Apache Combined Format

Same as Nginx:

```bash
./cidrx static --logfile access.log \
  --logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

### Custom Format with X-Forwarded-For

If using a proxy that logs real IP in a different position:

```bash
./cidrx static --logfile access.log \
  --logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

See [Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) for detailed format documentation.

## Large Log Files

For very large files (>10GB):

1. **Use time windows** to analyze specific periods
2. **Reduce cluster strategies** for faster processing
3. Split log files and analyze separately, or use [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) with sliding windows

See [Performance]({{< relref "/docs/advanced/performance/" >}}) for optimization details.

## Output Options

### JSON Output

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1
```

Produces structured JSON for programmatic processing.

### Compact JSON

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact
```

Single-line JSON for SIEM integration.

### Plain Text

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain
```

Human-readable formatted output with tables and charts.

### Interactive TUI

```bash
./cidrx static --config cidrx.toml --tui
```

Terminal user interface with visualizations.

See [Output Formats]({{< relref "/docs/usage/output/" >}}) for detailed documentation.

## Real-World Example

Here's a complete real-world example from the README:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 \
  --clusterArgSets 10000,12,16,0.1 \
  --rangesCidr 14.160.0.0/12 \
  --rangesCidr 198.51.0.0/16 \
  --plain \
  --logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

This analyzes 1M+ requests in ~1 second and produces:

```
📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Log File:        /var/log/nginx/access.log
Total Requests:  1,046,826
Parse Time:      762 ms
Parse Rate:      1,373,322 requests/sec

🔍 CLUSTERING RESULTS (3 sets)
...............................................................................
  Set 1: min_size=1000, depth=24-32, threshold=0.10
  Detected Threat Ranges:
    20.171.207.2/32            1,574 requests  (  0.15%)
    45.40.50.192/26            3,083 requests  (  0.29%)
    198.51.205.91/32           1,308 requests  (  0.12%)
    ───────────────────        5,965 requests  (  0.57%) [TOTAL]

  Set 2: min_size=10000, depth=16-24, threshold=0.20
  Detected Threat Ranges:
    14.169.0.0/16             17,642 requests  (  1.69%)
    14.186.0.0/15             28,830 requests  (  2.75%)
    14.191.0.0/16             52,868 requests  (  5.05%)
    113.172.0.0/15            28,812 requests  (  2.75%)
    123.20.0.0/16             14,927 requests  (  1.43%)
    ───────────────────      143,079 requests  ( 13.67%) [TOTAL]

  Set 3: min_size=10000, depth=12-16, threshold=0.10
  Detected Threat Ranges:
    14.169.0.0/16             17,642 requests  (  1.69%)
    14.186.0.0/15             28,830 requests  (  2.75%)
    14.191.0.0/16             52,868 requests  (  5.05%)
    14.240.0.0/13             14,335 requests  (  1.37%)
    113.172.0.0/15            28,812 requests  (  2.75%)
    113.176.0.0/13            24,927 requests  (  2.38%)
    123.20.0.0/15             29,335 requests  (  2.80%)
    ───────────────────      196,749 requests  ( 18.79%) [TOTAL]
```

## Best Practices

1. **Start conservative** - Use high thresholds initially, then tune down
2. **Use multiple strategies** - Different cluster sizes catch different attack types
3. **Maintain whitelists** - Protect legitimate traffic from false positives
4. **Review regularly** - Audit detected ranges before blocking
5. **Test in staging** - Verify detection behavior before production deployment
6. **Archive results** - Keep historical analysis for compliance and trend analysis

## Next Steps

- Learn about [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) for real-time protection
- Configure [Custom Log Formats]({{< relref "/docs/configuration/log-formats/" >}})
- Fine-tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Explore [Output Formats]({{< relref "/docs/usage/output/" >}}) in detail
