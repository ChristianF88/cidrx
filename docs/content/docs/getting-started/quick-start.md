---
title: "Quick Start"
description: "Get started with cidrx in minutes"
summary: "Quick examples to get you analyzing logs and detecting attacks immediately"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 120
toc: true
seo:
  title: "cidrx Quick Start Guide"
  description: "Learn how to use cidrx for botnet detection in minutes with practical examples"
  canonical: ""
  noindex: false
---

## Your First Analysis

Let's start with a simple example that analyzes a log file and detects potential attack patterns.

### Basic Threat Detection

```bash
./cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

This command:
- Analyzes `/var/log/nginx/access.log`
- Detects clusters of at least 1000 requests from IPs in /24 to /32 ranges
- Uses a 10% threshold for cluster detection
- Outputs results in plain text format

### Understanding the Output

You'll see output like this:

```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Log File:        /var/log/nginx/access.log
Analysis Type:   static
Generated:       2025-10-09 10:00:00 UTC
Duration:        540 ms

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Time:      437 ms
Parse Rate:      2,394,927 requests/sec

🔍 CLUSTERING RESULTS (1 set)
...............................................................................
  Set 1: min_size=1000, depth=24-32, threshold=0.10
  Execution Time: 95 μs
  Detected Threat Ranges:
    45.40.50.192/26            3,083 requests  (  0.29%)
    198.51.205.91/32           1,308 requests  (  0.12%)
    ───────────────────        4,391 requests  (  0.42%) [TOTAL]
```

The detected CIDR ranges represent potential attack sources that you can block.

## Common Use Cases

### Emergency Response

When under active attack, use multiple cluster sizes to catch different patterns:

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

This runs three detection strategies:
1. Small clusters (500+ requests) in narrow ranges (/28-/32) - catches focused attacks
2. Medium clusters (2000+ requests) in mid ranges (/20-/28) - catches distributed attacks
3. Large clusters (10000+ requests) in wide ranges (/16-/24) - catches major botnets

### Blocking Security Scanners

Detect and block scanning tools and bots:

```bash
./cidrx static --logfile access.log \
  --useragentRegex ".*bot.*|.*scanner.*|.*nikto.*|.*sqlmap.*" \
  --clusterArgSets 100,30,32,0.05 \
  --plain
```

The low threshold (100 requests) catches scanners early, and the narrow range (/30-/32) focuses on individual IPs or tiny clusters.

### Time-Specific Analysis

Analyze a specific time window (useful for investigating known incidents):

```bash
./cidrx static --logfile access.log \
  --startTime "2025-01-15T00:00:00Z" \
  --endTime "2025-01-15T23:59:59Z" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Focusing on Specific Networks

If you're seeing attacks from known networks, focus analysis:

```bash
./cidrx static --logfile access.log \
  --rangesCidr "203.0.113.0/24" \
  --rangesCidr "198.51.100.0/24" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Working with Whitelists and Blacklists

Protect legitimate traffic while focusing on threats:

```bash
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --blacklist /etc/cidrx/blacklist.txt \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

Whitelist format (one CIDR per line):

```
# /etc/cidrx/whitelist.txt
10.0.0.0/8          # Internal network
203.0.113.0/24      # Office IPs
192.0.2.100/32      # Monitoring service
```

## Using Configuration Files

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

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

[static.comprehensive_scan]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]

[static.security_scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

## Real-Time Protection

Switch to live mode for continuous monitoring:

```bash
./cidrx live --port 8080 \
  --jailFile /etc/cidrx/jail.json \
  --banFile /etc/cidrx/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

This starts cidrx in live mode:
- Listens on port 8080 for Lumberjack protocol logs
- Maintains a 2-hour sliding window
- Keeps up to 100,000 recent requests in memory
- Automatically updates jail and ban files

## Output Formats

### JSON Output (Default)

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

Human-readable formatted output (shown in examples above).

### Interactive TUI

```bash
./cidrx static --config cidrx.toml --tui
```

Terminal user interface with visualizations and interactive exploration.

## Testing Your Setup

Use the Docker test environment to verify cidrx is working:

```bash
# Start test environment with simulated attacks
docker compose up --build

# Watch detections in real-time
docker compose logs -f cidrx

# Verify ban file generation
docker compose exec cidrx cat /data/blocklist.txt

# Clean up
docker compose down
```

The test environment simulates 44 attack clients across multiple networks. Within 1-2 minutes, cidrx should detect and block several CIDR ranges.

## Understanding Cluster Parameters

Format: `--clusterArgSets minSize,minDepth,maxDepth,threshold`

- **minSize**: Minimum requests to flag (e.g., 1000)
- **minDepth**: Smallest CIDR prefix (e.g., 24 for /24)
- **maxDepth**: Largest CIDR prefix (e.g., 32 for /32)
- **threshold**: Percentage threshold (e.g., 0.1 for 10%)

See [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) for detailed tuning guide.

## Next Steps

Now that you've run your first analysis:

- Learn about [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) for detailed historical analysis
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) for real-time protection
- Configure [Custom Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) for your setup
- Fine-tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Review [Performance Tips]({{< relref "/docs/advanced/performance/" >}}) for optimization

## Getting Help

If you encounter issues:

1. Check the logs for error messages
2. Verify log format matches your files
3. Ensure file permissions are correct
4. Review the [Configuration Guide]({{< relref "/docs/configuration/config-files/" >}})
5. Open an issue on GitHub with details
