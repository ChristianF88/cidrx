---
title: "Filtering"
description: "Configuring whitelist, blacklist, and pattern-based filtering in cidrx"
summary: "Complete guide to IP filtering, User-Agent filtering, and regex-based traffic filtering"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 330
toc: true
seo:
  title: "cidrx Filtering Configuration"
  description: "Learn how to configure cidrx filtering with whitelists, blacklists, and regex patterns for precise threat detection"
  canonical: ""
  noindex: false
---

cidrx provides comprehensive filtering capabilities to focus analysis on specific traffic patterns while excluding legitimate users.

## Overview

Filtering in cidrx works in multiple stages:

1. **IP Whitelist**: Exclude known legitimate IPs (always processed first)
2. **IP Blacklist**: Focus only on known problematic IPs
3. **User-Agent Whitelist**: Exclude legitimate bots/crawlers
4. **User-Agent Blacklist**: Focus on specific attack tools
5. **User-Agent Regex**: Pattern-based User-Agent filtering
6. **Endpoint Regex**: Filter by URL path patterns
7. **Time Window**: Filter by timestamp range

## IP Filtering

### IP Whitelist

Whitelists protect legitimate traffic from being flagged:

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1
```

#### Whitelist File Format

One CIDR per line, comments with `#`:

```
# /etc/cidrx/whitelist.txt

# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Office networks
203.0.113.0/24
198.51.100.0/24

# Specific servers
192.0.2.100/32

# CDN providers
# CloudFlare
173.245.48.0/20
103.21.244.0/22

# Monitoring services
192.0.2.50/32  # Pingdom
192.0.2.51/32  # UptimeRobot
```

#### Whitelist Behavior

- Requests from whitelisted IPs are **excluded** from analysis
- Whitelist is checked **first**, before any other filtering
- Use for known legitimate traffic (CDNs, monitoring, internal)
- Helps prevent false positives

### IP Blacklist

Blacklists focus analysis on specific problematic IPs:

```toml
[global]
blacklist = "/etc/cidrx/blacklist.txt"
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --blacklist /etc/cidrx/blacklist.txt \
  --clusterArgSets 1000,24,32,0.1
```

#### Blacklist File Format

Same format as whitelist:

```
# /etc/cidrx/blacklist.txt

# Known attack sources
45.40.50.0/24
198.51.205.0/24

# Confirmed malicious IPs
20.171.207.2/32
203.0.113.99/32

# Specific ASNs (example ranges)
198.51.100.0/24
```

#### Blacklist Behavior

- When blacklist is specified, **only** these IPs are analyzed
- All other IPs are excluded
- Use for targeted investigation of known threats
- Mutually exclusive with normal analysis (either blacklist OR normal)

### Whitelist vs Blacklist

| Feature | Whitelist | Blacklist |
|---------|-----------|-----------|
| Purpose | Exclude legitimate traffic | Focus on suspicious traffic |
| Effect | Removes from analysis | Only analyzes these IPs |
| Use case | Prevent false positives | Investigate known threats |
| Priority | Processed first | Processed second |
| Can combine? | Yes | Yes (whitelist applied first) |

#### Combined Usage

You can use both together:

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
```

Processing order:
1. Whitelist applied first (removes IPs)
2. Blacklist applied second (focuses on remaining IPs)
3. Other filters applied to result

## User-Agent Filtering

### User-Agent Whitelist

Exclude legitimate bots and crawlers:

```toml
[global]
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --userAgentWhitelist /etc/cidrx/ua_whitelist.txt \
  --clusterArgSets 1000,24,32,0.1
```

#### User-Agent Whitelist Format

One pattern per line, **exact string matching**:

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

# Other legitimate bots
AhrefsBot
SemrushBot
```

**Important**: Exact substring match, not regex. User-Agent containing the string will match.

### User-Agent Blacklist

Focus on specific attack tools:

```toml
[global]
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --userAgentBlacklist /etc/cidrx/ua_blacklist.txt \
  --clusterArgSets 1000,24,32,0.1
```

#### User-Agent Blacklist Format

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

### User-Agent Regex Filtering

Pattern-based User-Agent filtering using regex:

```toml
[static.scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --useragentRegex ".*bot.*|.*scanner.*" \
  --clusterArgSets 100,30,32,0.05
```

#### Regex Patterns

Common patterns:

```bash
# Any bot
".*bot.*"

# Scanners
".*scanner.*|.*scan.*"

# SQL injection tools
".*sqlmap.*|.*havij.*"

# Generic tools
"curl|wget|python-requests"

# Case insensitive (use (?i))
"(?i).*scanner.*"

# Specific versions
"curl/7\\.[0-9]+\\.[0-9]+"

# Combined patterns
".*scanner.*|.*bot.*|curl|wget|python-requests"
```

#### Regex Syntax

cidrx uses Go regex (RE2 syntax):

- `.` - Any character
- `*` - Zero or more
- `+` - One or more
- `?` - Zero or one
- `|` - OR
- `()` - Grouping
- `[]` - Character class
- `\\` - Escape special characters

**Examples**:

```bash
# Match "bot" anywhere
".*bot.*"

# Match curl or wget
"curl|wget"

# Match specific scanner versions
"nikto/[0-9]+\\.[0-9]+"

# Match python requests or urllib
"python-(requests|urllib)"

# Case insensitive matching
"(?i)SQLMAP"
```

## Endpoint Filtering

### Endpoint Regex

Filter by URL path patterns:

```toml
[static.api_abuse]
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --endpointRegex "/api/.*" \
  --clusterArgSets 500,28,32,0.1
```

#### Common Endpoint Patterns

```bash
# API endpoints
"/api/.*"

# Admin panels
"/admin/.*|/wp-admin/.*"

# Login pages
"/login|/signin|/auth"

# Specific paths
"/api/v1/users|/api/v1/auth"

# File extensions
".*\\.php|.*\\.asp"

# Exclude static resources
"^(?!.*\\.(css|js|png|jpg|gif)$).*"

# Multiple patterns
"/api/.*|/admin/.*|/login"
```

### Combining Filters

Use multiple filters together:

```toml
[static.targeted_attack]
useragentRegex = ".*scanner.*|.*nikto.*"
endpointRegex = "/admin/.*|/wp-admin/.*"
clusterArgSets = [[50,30,32,0.05]]
useForJail = [true]
```

This analyzes only:
- Requests with scanner User-Agents
- To admin endpoints
- With low threshold (50 requests)

## Time-Based Filtering

### Time Window Filtering

Filter by specific time range:

```toml
[static.incident_analysis]
startTime = "2025-01-15T14:00:00Z"
endTime = "2025-01-15T16:00:00Z"
clusterArgSets = [[1000,24,32,0.1]]
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --startTime "2025-01-15T14:00:00Z" \
  --endTime "2025-01-15T16:00:00Z" \
  --clusterArgSets 1000,24,32,0.1
```

#### Time Format

Use RFC3339 (ISO 8601) format:

```
YYYY-MM-DDTHH:MM:SSZ
```

Examples:
```
2025-01-15T00:00:00Z          # UTC midnight
2025-01-15T14:30:00-05:00     # 2:30 PM EST
2025-01-15T23:59:59+00:00     # End of day UTC
```

### Use Cases

**Incident investigation**:
```toml
[static.incident]
startTime = "2025-10-09T14:15:00Z"
endTime = "2025-10-09T14:45:00Z"
clusterArgSets = [[100,28,32,0.05]]
```

**Daily analysis**:
```bash
# Analyze yesterday
./cidrx static --logfile access.log \
  --startTime "2025-10-08T00:00:00Z" \
  --endTime "2025-10-08T23:59:59Z" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain > daily-report-20251008.txt
```

**Peak hours**:
```toml
[static.peak_hours]
startTime = "2025-10-09T12:00:00Z"
endTime = "2025-10-09T18:00:00Z"
clusterArgSets = [[5000,20,28,0.2]]
```

## CIDR Range Focusing

### Focus on Specific Networks

Analyze only specific CIDR ranges:

```toml
[static.suspicious_networks]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [[1000,24,32,0.1]]
```

Or command line:

```bash
./cidrx static --logfile access.log \
  --rangesCidr "203.0.113.0/24" \
  --rangesCidr "198.51.100.0/24" \
  --clusterArgSets 1000,24,32,0.1
```

### Use Cases

**Known problematic ASNs**:
```toml
[static.asn_check]
cidrRanges = ["45.40.0.0/16", "198.51.0.0/16"]
clusterArgSets = [[500,24,32,0.1]]
```

**Geolocation-based**:
```bash
# Analyze only Chinese IP ranges (example)
./cidrx static --logfile access.log \
  --rangesCidr "1.0.0.0/8" \
  --rangesCidr "14.0.0.0/8" \
  --clusterArgSets 1000,24,32,0.1
```

**Follow-up analysis**:
```bash
# First, discover attacking ranges
./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain

# Then, deep-dive on specific range
./cidrx static --logfile access.log \
  --rangesCidr "45.40.50.0/24" \
  --clusterArgSets 100,28,32,0.05 \
  --plain
```

## Filter Combination Strategies

### Strategy 1: Exclude Legitimate, Detect Everything

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"

[static.general]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]
```

This:
1. Excludes internal IPs and CDNs
2. Excludes legitimate bots
3. Detects all remaining traffic

### Strategy 2: Focus on Specific Attack Types

```toml
[static.scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[static.brute_force]
endpointRegex = "/login|/wp-login\\.php"
clusterArgSets = [[50,30,32,0.05]]
useForJail = [true]

[static.api_abuse]
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

Each scenario targets specific attack patterns.

### Strategy 3: Tiered Analysis

```toml
[static.tier1_large_attacks]
clusterArgSets = [[10000,16,24,0.3]]
useForJail = [true]

[static.tier2_medium_attacks]
clusterArgSets = [[1000,24,28,0.1]]
useForJail = [true]

[static.tier3_focused_attacks]
useragentRegex = ".*scanner.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

Catches attacks at different scales.

## Performance Optimization

### Filter Order

cidrx processes filters in this order:

1. IP Whitelist (excluded first)
2. IP Blacklist (if specified, only these analyzed)
3. Time window (if specified)
4. User-Agent whitelist
5. User-Agent blacklist
6. User-Agent regex
7. Endpoint regex
8. CIDR ranges

**Optimization**: Filters early in the chain reduce processing for later stages.

### Regex Performance

Complex regex can slow parsing:

```toml
# Slower - complex regex
useragentRegex = "(?i)(scanner|nikto|sqlmap|acunetix|w3af|metasploit|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

# Faster - simple patterns
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
```

**Tips**:
- Keep regex simple
- Use exact strings in whitelist/blacklist files instead of regex when possible
- Test performance with benchmarks

### Caching

cidrx caches compiled regex patterns for better performance. The same regex used in multiple scenarios is only compiled once.

## Practical Examples

### Example 1: Production Defense

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""

[static.main_defense]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]
```

### Example 2: Incident Response

```toml
[static.incident]
startTime = "2025-10-09T14:00:00Z"
endTime = "2025-10-09T16:00:00Z"
cidrRanges = ["45.40.50.0/24"]
clusterArgSets = [[50,28,32,0.05]]
useForJail = [false]
```

### Example 3: API Protection

```toml
[static.api_login_abuse]
endpointRegex = "/api/v1/(login|auth|register)"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[static.api_rate_limit]
endpointRegex = "/api/.*"
clusterArgSets = [[1000,28,32,0.1]]
useForJail = [true]
```

### Example 4: Scanner Detection

```toml
[static.known_scanners]
userAgentBlacklist = "/etc/cidrx/scanner_blacklist.txt"
clusterArgSets = [[50,30,32,0.01]]
useForJail = [true]

[static.unknown_scanners]
useragentRegex = "(?i).*(scan|probe|test|check).*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

## Best Practices

1. **Maintain whitelists**: Regularly update with legitimate traffic
2. **Start conservative**: Use high thresholds, adjust based on results
3. **Layer filters**: Combine multiple filter types for precision
4. **Document patterns**: Comment why specific regex patterns were chosen
5. **Test regex**: Verify patterns match expected traffic
6. **Review regularly**: Audit filter effectiveness monthly
7. **Version control**: Track filter changes in git
8. **Monitor performance**: Watch for regex-related slowdowns

## Troubleshooting

### No Results

**Problem**: Filters too restrictive, no traffic matches

**Solution**: Relax filters incrementally:
```bash
# Remove all filters first
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain

# Add filters one at a time
./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 --plain
```

### Too Many Results

**Problem**: Not enough filtering, too much noise

**Solution**: Add targeted filters:
```toml
# Add whitelist for legitimate traffic
whitelist = "/etc/cidrx/whitelist.txt"

# Increase cluster thresholds
clusterArgSets = [[5000,24,32,0.2]]
```

### Regex Not Matching

**Problem**: Regex doesn't match expected User-Agents

**Solution**: Test regex patterns:
```bash
# Extract unique User-Agents from log
cat access.log | awk -F'"' '{print $6}' | sort -u

# Test regex pattern
echo "Mozilla/5.0 scanner" | grep -E ".*scanner.*"
```

## Next Steps

- Fine-tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Review [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) examples
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) filtering
- Optimize [Performance]({{< relref "/docs/advanced/performance/" >}})
