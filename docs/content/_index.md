---
title: "cidrx"
description: "High-performance IP clustering tool"
lead: "Ultra-fast IP address clustering for HTTP log analysis"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-10T07:45:00+00:00
draft: false
seo:
  title: "cidrx - High-Performance IP Clustering"
  description: "High-performance tool that clusters IP addresses into CIDR ranges at 1M+ requests/second. Ideal for botnet detection and log analysis."
  canonical: ""
  noindex: false
---

## What is cidrx?

cidrx clusters IP addresses from HTTP logs into CIDR ranges at exceptional speed. By automatically grouping related IPs, it works well for botnet detection, attack pattern analysis, and network traffic investigation.

### Key Features

- **Ultra-Fast**: 1M+ requests/second parsing and clustering
- **Two Modes**: Static (historical logs) and Live (real-time protection)
- **Smart Detection**: Multiple clustering strategies run simultaneously
- **Flexible**: Regex filtering, whitelist/blacklist, time windows
- **Multiple Outputs**: JSON, plain text, interactive TUI
- **Blocklist Generation**: Inspired by *fail2ban* generates a blocklist of ranges for your firewall.

### Quick Example

```bash
cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 \
  --plain
```

**Example Output:**

```
cidrx Analysis Results
──────────────────────────────────────────────────────────

📊 ANALYSIS OVERVIEW
Log File:        /var/log/nginx/access.log
Total Requests:  1,046,826
Parse Rate:      1,261,744 requests/sec
Duration:        1156 ms

🔍 CLUSTERING RESULTS

Set 1: min_size=1000, depth=24-32, threshold=0.10
  20.171.207.2/32      1,574 requests  (  0.15%)
  45.40.50.192/26      3,083 requests  (  0.29%)
  112.58.205.91/32     1,308 requests  (  0.12%)

Set 2: min_size=10000, depth=16-24, threshold=0.20
  14.169.0.0/16       17,642 requests  (  1.69%)
  14.186.0.0/15       28,830 requests  (  2.75%)
  14.191.0.0/16       52,868 requests  (  5.05%)
  113.172.0.0/15      28,812 requests  (  2.75%)
  123.20.0.0/16       14,927 requests  (  1.43%)
```

[Get Started →]({{< relref "/docs/getting-started/introduction/" >}})
