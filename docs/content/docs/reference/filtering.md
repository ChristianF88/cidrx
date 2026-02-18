---
title: "Filtering"
description: "Whitelist, blacklist, regex, and time-based filtering"
summary: "Complete reference for all cidrx filtering mechanisms and file formats"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 250
slug: "filtering"
toc: true
seo:
  title: "cidrx Filtering Reference"
  description: "Learn how to configure cidrx filtering with whitelists, blacklists, and regex patterns"
  canonical: ""
  noindex: false
---

cidrx filters traffic in multiple stages before clustering. Filtering reduces noise and prevents false positives.

## Filter Processing Order

Filters are applied in this order:

1. **IP Whitelist** -- excluded first
2. **IP Blacklist** -- if specified, only these IPs are analyzed
3. **Time window** -- if startTime/endTime configured
4. **User-Agent whitelist** -- exclude matching requests
5. **User-Agent blacklist** -- if specified, only matching requests analyzed
6. **User-Agent regex** -- pattern filter
7. **Endpoint regex** -- URL path filter
8. **CIDR ranges** -- focus on specific networks

Filters early in the chain reduce work for later stages, improving performance.

## IP Whitelist

Whitelisted IPs are excluded from all analysis. Checked first.

### File Format

One CIDR per line. Comments with `#`. Blank lines ignored.

```
# /etc/cidrx/whitelist.txt

# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Office networks
203.0.113.0/24
198.51.100.0/24

# CDN providers
173.245.48.0/20
103.21.244.0/22

# Monitoring services
192.0.2.50/32    # Pingdom
192.0.2.51/32    # UptimeRobot
```

### Usage

TOML:
```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
```

CLI:
```bash
--whitelist /etc/cidrx/whitelist.txt
```

## IP Blacklist

When a blacklist is specified, **only** blacklisted IPs are analyzed. All others are excluded.

### File Format

Same format as whitelist:

```
# /etc/cidrx/blacklist.txt

# Known ranges
45.40.50.0/24
198.51.205.0/24

# Confirmed IPs
20.171.207.2/32
203.0.113.99/32
```

### Combined Usage

Whitelist and blacklist can be used together. Whitelist is applied first, then blacklist filters the remainder.

## User-Agent Whitelist

Exclude requests matching these User-Agent strings. Uses **exact substring matching** (not regex).

### File Format

One pattern per line:

```
# /etc/cidrx/ua_whitelist.txt

# Search engine bots
Googlebot
Bingbot
DuckDuckBot
Slurp
Baiduspider

# Social media
facebookexternalhit
Twitterbot
LinkedInBot

# Monitoring and uptime
UptimeRobot
Pingdom
StatusCake
Site24x7

# SEO tools
AhrefsBot
SemrushBot
```

A request is excluded if its User-Agent **contains** any listed string.

## User-Agent Blacklist

When specified, only requests with User-Agents matching these patterns are analyzed. Uses **exact substring matching**.

### File Format

```
# /etc/cidrx/ua_blacklist.txt

# SQL injection tools
sqlmap
havij

# Web scanners
nikto
acunetix
netsparker
w3af
wpscan

# General tools
curl
wget
python-requests
Go-http-client
Java

# Scrapers
HTTrack
WebCopier
WebZIP
```

## User-Agent Regex

Pattern-based filtering using Go regex (RE2 syntax).

### Usage

TOML (per-trie):
```toml
[static.user_agent_filter]
useragentRegex = ".*bot.*"
```

CLI:
```bash
--useragentRegex ".*bot.*|.*scanner.*"
```

### Common Patterns

```
".*bot.*"                                  # Any bot
"curl|wget|python-requests"               # Generic tools
"(?i).*scanner.*"                          # Case insensitive
"python-(requests|urllib)"                 # Grouped alternation
```

### Regex Syntax (RE2)

`.` any character, `*` zero or more, `+` one or more, `?` zero or one, `|` OR, `()` grouping, `[]` character class, `\\` escape, `(?i)` case insensitive.

## Endpoint Regex

Filter by URL path pattern. Same RE2 syntax.

### Usage

TOML:
```toml
[static.api_abuse]
endpointRegex = "/api/.*"
```

CLI:
```bash
--endpointRegex "/api/.*"
```

### Common Patterns

```
"/api/.*"                              # All API endpoints
"/admin/.*|/wp-admin/.*"               # Admin panels
"/login|/signin|/auth"                 # Login pages
"/api/v1/(login|auth|register)"        # Specific API routes
".*\\.php|.*\\.asp"                    # Script extensions
"/api/.*|/admin/.*|/login"             # Combined
```

## Time Window

Filter requests by timestamp range.

### CLI Format

Flexible format: `YYYY-MM-DD`, `YYYY-MM-DD HH`, or `YYYY-MM-DD HH:MM`.

```bash
--startTime "2025-01-15 14:00" --endTime "2025-01-15 16:00"
--startTime "2025-01-15"       --endTime "2025-01-15 23:59"
```

### TOML Format

RFC3339:

```toml
startTime = "2025-01-15T14:00:00Z"
endTime = "2025-01-15T16:00:00Z"
```

## CIDR Range Focusing

Analyze only traffic from specific networks.

TOML:
```toml
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
```

CLI:
```bash
--rangesCidr "203.0.113.0/24" --rangesCidr "198.51.100.0/24"
```

Useful for investigating known problematic ASNs or following up on detected ranges.

## Combining Filters

### Exclude Legitimate, Detect Everything

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"

[static.general]
clusterArgSets = [[1000, 24, 32, 0.1]]
useForJail = [true]
```

### Filter by User-Agent Pattern

```toml
[static.ua_filter]
useragentRegex = ".*bot.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]

[static.endpoint_filter]
endpointRegex = "/login|/wp-login\\.php"
clusterArgSets = [[50, 30, 32, 0.05]]
useForJail = [true]
```

### Tiered Analysis

```toml
[static.tier1_large]
clusterArgSets = [[10000, 16, 24, 0.3]]
useForJail = [true]

[static.tier2_medium]
clusterArgSets = [[1000, 24, 28, 0.1]]
useForJail = [true]

[static.tier3_focused]
useragentRegex = ".*bot.*"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]
```

## Performance Tips

- **Whitelist is the biggest optimization** (10-30% faster overall). Exclude CDN, monitoring, and internal IPs.
- Keep regex simple. `".*bot.*|.*scanner.*"` is faster than complex lookaheads.
- Use User-Agent blacklist files instead of regex when matching exact strings.
- cidrx caches compiled regex patterns. The same pattern used across tries is compiled once.

## Troubleshooting

**No results**: Filters may be too restrictive. Run without filters first, then add one at a time.

**Too many results**: Add a whitelist, increase cluster thresholds, or use more specific regex.

**Regex not matching**: Test with `echo "User-Agent string" | grep -E "pattern"`. Check for case sensitivity (`(?i)` for case-insensitive).
