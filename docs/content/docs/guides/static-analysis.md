---
title: "Static Analysis Guide"
description: "Step-by-step guide to analyzing historical logs with cidrx"
summary: "Complete walkthrough of static mode for log analysis and cluster detection"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 810
toc: true
seo:
  title: "cidrx Static Analysis Guide"
  description: "Learn how to use cidrx static mode for historical log analysis and IP cluster detection"
  canonical: ""
  noindex: false
---

Static mode analyzes historical log files to identify high-volume IP clusters. Use it for log analysis, security audits, and testing detection parameters.

## Basic Analysis

Analyze a log file with a single cluster arg set:

```bash
./cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

This detects IP clusters with 1000+ requests in /24 to /32 ranges using a 10% threshold. For parameter details, see [Clustering]({{< relref "/docs/reference/clustering/" >}}).

## Multi-Tier Detection

Run multiple [cluster arg sets]({{< relref "/docs/reference/clustering/" >}}) to catch different cluster sizes:

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

Each set runs independently: small clusters (500+), medium clusters (2000+), large clusters (10000+).

## Filtering

### By User-Agent

Filter by user-agent patterns:

```bash
./cidrx static --logfile access.log \
  --useragentRegex "Chrome|Firefox" \
  --clusterArgSets 100,30,32,0.05 --plain
```

### By Endpoint

Focus on API abuse:

```bash
./cidrx static --logfile access.log \
  --endpointRegex "/api/.*" \
  --clusterArgSets 500,28,32,0.1 --plain
```

### By Time Window

Analyze a specific period:

```bash
./cidrx static --logfile access.log \
  --startTime "2025-01-15 14:00" \
  --endTime "2025-01-15 16:00" \
  --clusterArgSets 1000,24,32,0.1 --plain
```

See [Filtering]({{< relref "/docs/reference/filtering/" >}}) for all filter types, file formats, and combination patterns.

### With Whitelists

Protect legitimate traffic:

```bash
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 --plain
```

See [Filtering]({{< relref "/docs/reference/filtering/" >}}) for whitelist/blacklist file formats.

## Investigating Specific Networks

Focus on known problematic ranges:

```bash
./cidrx static --logfile access.log \
  --rangesCidr "203.0.113.0/24" \
  --rangesCidr "198.51.100.0/24" \
  --clusterArgSets 1000,24,32,0.1 --plain
```

## Generating Block Lists

Write detected ranges to files for firewall integration:

```bash
./cidrx static --logfile access.log \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --clusterArgSets 1000,24,32,0.1 --plain
```

The ban file contains one CIDR per line, ready for iptables or nginx. See [Output Formats]({{< relref "/docs/reference/output-formats/" >}}) for firewall integration examples.

## Using Configuration Files

For complex multi-trie analysis, use a TOML [config file]({{< relref "/docs/reference/config-file/" >}}):

```bash
./cidrx static --config cidrx.toml --plain
```

Config files support multiple named tries, each with independent filters and cluster parameters.

## Custom Log Formats

If your logs don't use the default format, specify a custom [log format]({{< relref "/docs/reference/log-formats/" >}}):

```bash
./cidrx static --logfile access.log \
  --logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"" \
  --clusterArgSets 1000,24,32,0.1 --plain
```

## Output Formats

Static mode supports all [output formats]({{< relref "/docs/reference/output-formats/" >}}):

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1           # JSON (default)
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact # Compact JSON
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain   # Plain text
./cidrx static --config cidrx.toml --tui                                       # Interactive TUI
```

## Large Files

For files >10GB:

1. Use `--startTime`/`--endTime` to analyze specific periods
2. Reduce cluster arg sets for faster processing
3. Consider [Live Mode]({{< relref "/docs/guides/live-protection/" >}}) with sliding windows instead

See [Performance]({{< relref "/docs/architecture/performance/" >}}) for optimization details.

## Best Practices

1. **Start conservative** -- high thresholds first, then tune down
2. **Use multiple cluster arg sets** -- different sizes catch different cluster sizes
3. **Maintain whitelists** -- protect legitimate traffic
4. **Review before blocking** -- audit detected ranges before applying to firewalls
5. **Test in staging** -- verify detection behavior before production
