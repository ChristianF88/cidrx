---
title: "Configuration Files"
description: "TOML configuration file structure and options for cidrx"
summary: "Complete reference for cidrx TOML configuration files with examples and best practices"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 310
slug: "config-files"
toc: true
seo:
  title: "cidrx Configuration Files"
  description: "Learn how to configure cidrx using TOML files for static and live modes with multiple detection strategies"
  canonical: ""
  noindex: false
---

cidrx uses TOML (Tom's Obvious, Minimal Language) for configuration files, providing a clean and easy-to-read format for complex multi-scenario setups.

## Configuration File Structure

### Basic Structure

```toml
[global]
# Global settings

[static]
# Static mode base configuration

[static.scenario_name]
# Static mode scenario

[live]
# Live mode base configuration

[live.window_name]
# Live mode window
```

## Global Section

### Required Fields

The `[global]` section contains settings shared across all modes:

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
```

### Optional Fields

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"
```

#### Field Descriptions

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `jailFile` | string | Path to persistent jail state file | `/var/lib/cidrx/jail.json` |
| `banFile` | string | Path to ban list output file | `/var/lib/cidrx/ban.txt` |
| `whitelist` | string | Path to IP whitelist file (optional) | `/etc/cidrx/whitelist.txt` |
| `blacklist` | string | Path to IP blacklist file (optional) | `/etc/cidrx/blacklist.txt` |
| `userAgentWhitelist` | string | Path to User-Agent whitelist (optional) | `/etc/cidrx/ua_whitelist.txt` |
| `userAgentBlacklist` | string | Path to User-Agent blacklist (optional) | `/etc/cidrx/ua_blacklist.txt` |

### File Paths

All paths should be absolute (not relative):

```toml
# Good
jailFile = "/var/lib/cidrx/jail.json"

# Bad (relative path)
jailFile = "./jail.json"
```

## Static Mode Configuration

### Base Configuration

The `[static]` section defines static mode parameters:

```toml
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
plotPath = "/tmp/heatmap.html"
```

#### Static Base Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `logFile` | string | Yes | Path to log file to analyze |
| `logFormat` | string | Yes | Log format parsing string |
| `plotPath` | string | No | Path for heatmap output |

### Static Scenarios

Define multiple analysis scenarios as `[static.scenario_name]` sections:

```toml
[static.comprehensive_scan]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]

[static.security_scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

#### Scenario Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `cidrRanges` | array of strings | Focus on specific CIDR ranges | `["10.0.0.0/8"]` |
| `clusterArgSets` | array of arrays | Cluster detection parameters | `[[1000,24,32,0.1]]` |
| `useForJail` | array of booleans | Which clusters to add to jail | `[true, false]` |
| `useragentRegex` | string | User-Agent filter regex | `".*bot.*"` |
| `endpointRegex` | string | Endpoint filter regex | `"/api/.*"` |
| `startTime` | string | Start of time window (RFC3339) | `"2025-01-15T00:00:00Z"` |
| `endTime` | string | End of time window (RFC3339) | `"2025-01-15T23:59:59Z"` |

### Complete Static Example

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

# Main botnet detection
[static.comprehensive_scan]
cidrRanges = ["203.0.113.0/24", "198.51.100.0/24"]
clusterArgSets = [
  [1000,24,32,0.1],    # Small clusters
  [5000,20,28,0.2]     # Medium clusters
]
useForJail = [true, true]

# Scanner detection
[static.security_scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

# API-specific abuse
[static.api_abuse]
endpointRegex = "/api/.*"
startTime = "2025-10-09T00:00:00Z"
endTime = "2025-10-09T23:59:59Z"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

## Live Mode Configuration

### Base Configuration

The `[live]` section defines the listening port:

```toml
[live]
port = "8080"
```

#### Live Base Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `port` | string | Yes | Port to listen for Lumberjack protocol |

### Live Windows

Define multiple independent sliding windows as `[live.window_name]` sections:

```toml
[live.realtime_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]

[live.scanner_detection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*bot.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

#### Window Fields

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `slidingWindowMaxTime` | string | Yes | Maximum time to keep in window | `"2h"`, `"30m"` |
| `slidingWindowMaxSize` | number | Yes | Maximum requests to keep | `100000` |
| `sleepBetweenIterations` | number | Yes | Seconds between detections | `10` |
| `clusterArgSets` | array of arrays | Yes | Cluster detection parameters | `[[1000,24,32,0.1]]` |
| `useForJail` | array of booleans | Yes | Which clusters to jail | `[true]` |
| `useragentRegex` | string | No | User-Agent filter | `".*bot.*"` |
| `endpointRegex` | string | No | Endpoint filter | `"/api/.*"` |
| `cidrRanges` | array of strings | No | Focus on specific CIDRs | `["10.0.0.0/8"]` |

### Complete Live Example

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"

[live]
port = "8080"

# Main botnet protection - 2 hour window
[live.realtime_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [
  [1000,24,32,0.1],
  [5000,20,28,0.2]
]
useForJail = [true, true]

# Fast scanner detection - 1 hour window
[live.scanner_detection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*bot.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

# API abuse - 30 minute window
[live.api_abuse]
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 25000
sleepBetweenIterations = 5
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

## Cluster Arguments

### Format

Cluster arguments are specified as arrays of four integers/floats:

```toml
clusterArgSets = [[minSize, minDepth, maxDepth, threshold]]
```

### Parameters

1. **minSize** (integer): Minimum requests for detection
2. **minDepth** (integer): Smallest CIDR prefix (e.g., 24 for /24)
3. **maxDepth** (integer): Largest CIDR prefix (e.g., 32 for /32)
4. **threshold** (float): Percentage of total requests (0.0-1.0)

### Examples

```toml
# Aggressive detection - small clusters
clusterArgSets = [[100,30,32,0.05]]
# Detects: 100+ requests in /30-/32 ranges that are 5%+ of total

# Balanced detection
clusterArgSets = [[1000,24,32,0.1]]
# Detects: 1000+ requests in /24-/32 ranges that are 10%+ of total

# Conservative detection - large clusters
clusterArgSets = [[10000,16,24,0.3]]
# Detects: 10000+ requests in /16-/24 ranges that are 30%+ of total

# Multiple strategies
clusterArgSets = [
  [100,30,32,0.05],     # Catch small focused attacks
  [1000,24,32,0.1],     # Catch medium attacks
  [10000,16,24,0.3]     # Catch large botnets
]
useForJail = [true, true, true]
```

See [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) for detailed tuning guide.

## Time Window Formats

### Duration Strings

Time windows use duration strings:

```toml
slidingWindowMaxTime = "2h"    # 2 hours
slidingWindowMaxTime = "30m"   # 30 minutes
slidingWindowMaxTime = "1h30m" # 1.5 hours
slidingWindowMaxTime = "90m"   # 90 minutes (same as 1h30m)
```

Supported units:
- `s` - seconds
- `m` - minutes
- `h` - hours

### Timestamp Strings

Absolute timestamps use RFC3339 (ISO 8601):

```toml
startTime = "2025-01-15T00:00:00Z"
endTime = "2025-01-15T23:59:59Z"
```

Format: `YYYY-MM-DDTHH:MM:SSZ`

With timezone:
```toml
startTime = "2025-01-15T00:00:00-05:00"  # EST
endTime = "2025-01-15T23:59:59+00:00"    # UTC
```

## List Files Format

### IP Whitelist/Blacklist

One CIDR per line, comments supported:

```
# /etc/cidrx/whitelist.txt
# Internal networks
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# Office IPs
203.0.113.0/24

# Monitoring services
192.0.2.100/32
```

### User-Agent Lists

One pattern per line, exact match:

```
# /etc/cidrx/ua_whitelist.txt
# Legitimate bots
Googlebot
Bingbot
DuckDuckBot

# Monitoring
UptimeRobot
Pingdom
```

```
# /etc/cidrx/ua_blacklist.txt
# Known malicious
sqlmap
nikto
havij
acunetix

# Common tools
curl
wget
python-requests
```

## Configuration Validation

### Syntax Validation

TOML syntax must be valid:

```toml
# Good
jailFile = "/var/lib/cidrx/jail.json"

# Bad - missing quotes
jailFile = /var/lib/cidrx/jail.json

# Bad - wrong delimiter
jailFile: "/var/lib/cidrx/jail.json"
```

### Required Fields

Each section must have required fields:

```toml
# Missing logFile - INVALID
[static]
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

# Complete - VALID
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

### Array Lengths

`useForJail` must match `clusterArgSets` length:

```toml
# Mismatch - INVALID
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true]

# Match - VALID
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]
```

## Example Configurations

### Example 1: Simple Static Analysis

```toml
[global]
jailFile = "/tmp/jail.json"
banFile = "/tmp/ban.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

[static.default]
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
```

### Example 2: Multi-Scenario Static

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

[static.general]
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]

[static.scanners]
useragentRegex = ".*scanner.*|.*nikto.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[static.api]
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

### Example 3: Production Live Mode

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"

[live]
port = "8080"

[live.main]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [
  [1000,24,32,0.1],
  [5000,20,28,0.2],
  [10000,16,24,0.3]
]
useForJail = [true, true, true]

[live.scanners]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[live.api]
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 25000
sleepBetweenIterations = 5
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]

[live.admin]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 5
endpointRegex = "/admin/.*|/wp-admin/.*"
clusterArgSets = [[50,30,32,0.05]]
useForJail = [true]
```

## Configuration Management

### Version Control

Store configurations in git:

```bash
# Initialize repo
cd /etc/cidrx
git init
git add *.toml *.txt
git commit -m "Initial cidrx configuration"

# Track changes
git add config.toml
git commit -m "Increased detection threshold"
```

### Backup

Regular backups:

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/var/backups/cidrx"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"
tar czf "$BACKUP_DIR/config-$DATE.tar.gz" \
  /etc/cidrx/*.toml \
  /etc/cidrx/*.txt \
  /var/lib/cidrx/jail.json

# Keep last 30 days
find "$BACKUP_DIR" -name "config-*.tar.gz" -mtime +30 -delete
```

### Environment Variables

Use environment variables for sensitive paths:

```bash
# Set environment
export CIDRX_JAIL_FILE="/var/lib/cidrx/jail.json"
export CIDRX_BAN_FILE="/var/lib/cidrx/ban.txt"

# In config (if supported in future versions)
jailFile = "${CIDRX_JAIL_FILE}"
banFile = "${CIDRX_BAN_FILE}"
```

Note: Current version doesn't support environment variable substitution. This is planned for future releases.

## Best Practices

1. **Comments**: Document why you chose specific values
2. **Organize**: Group related scenarios together
3. **Test**: Validate configuration before deployment
4. **Version**: Keep configurations in version control
5. **Backup**: Regularly backup configurations and jail files
6. **Security**: Protect files with appropriate permissions (600 or 640)
7. **Absolute paths**: Always use absolute paths, not relative
8. **Consistency**: Use consistent naming for scenarios/windows

## Troubleshooting

### Common Errors

**TOML syntax error:**
```
Error: TOML parse error at line 15, column 10: expected '=', found ':'
```
Fix: Use `=` not `:` for assignments

**Missing required field:**
```
Error: Missing required field 'logFile' in [static] section
```
Fix: Add the missing field

**Invalid cluster arguments:**
```
Error: clusterArgSets must have exactly 4 values
```
Fix: Ensure format is `[[minSize,minDepth,maxDepth,threshold]]`

**File not found:**
```
Error: Cannot open whitelist file: /etc/cidrx/whitelist.txt
```
Fix: Create the file or update the path

## Next Steps

- Configure [Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) for parsing
- Set up [Filtering]({{< relref "/docs/configuration/filtering/" >}}) with lists and regex
- Tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Review [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) usage examples
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) deployment
