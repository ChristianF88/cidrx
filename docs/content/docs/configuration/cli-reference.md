---
title: "CLI Reference"
description: "Complete command-line reference for cidrx"
summary: "Detailed documentation of all cidrx commands, flags, and options"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 350
slug: "cli-reference"
toc: true
seo:
  title: "cidrx CLI Reference"
  description: "Complete command-line interface reference for cidrx including all commands, flags, and usage examples"
  canonical: ""
  noindex: false
---

Complete command-line interface reference for cidrx. This page documents all available commands, flags, and their usage.

## Command Structure

```bash
cidrx [global options] command [command options]
```

cidrx has two main operational modes:
- **`static`** - Analyze historical log files
- **`live`** - Real-time log analysis with continuous monitoring

## Global Options

### `--help, -h`

Show help information.

```bash
cidrx --help
cidrx -h
```

## Commands

### `static` - Static Log Analysis

Analyze historical log files to detect attack patterns.

**Usage:**

```bash
cidrx static [command options]
```

**Example:**

```bash
cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

#### Static Mode Options

##### Core Options

###### `--config`

Path to TOML configuration file. When specified, all other command-line flags are ignored.

- **Type:** String (file path)
- **Mutually Exclusive:** Yes (with all other flags)
- **Example:**

```bash
cidrx static --config /etc/cidrx/config.toml
```

###### `--logfile`

Path to the log file to analyze.

- **Type:** String (file path)
- **Required:** Yes (unless using `--config`)
- **Example:**

```bash
cidrx static --logfile /var/log/nginx/access.log
```

###### `--logFormat`

Log format string using patterns similar to Apache/Nginx log formats.

- **Type:** String
- **Default:** `"%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""`
- **Example:**

```bash
cidrx static --logfile access.log \
  --logFormat '%h %^ %^ [%t] "%r" %s %b'
```

**Common Format Patterns:**

| Pattern | Description |
|---------|-------------|
| `%h` | Remote IP address |
| `%t` | Timestamp |
| `%r` | Request (method, path, protocol) |
| `%s` | Status code |
| `%b` | Response size |
| `%u` | Referer |
| `%^` | Skip field |

See [Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) for detailed documentation.

###### `--startTime`

Filter logs starting from this time.

- **Type:** String
- **Formats:** `YYYY-MM-DD`, `YYYY-MM-DD HH`, or `YYYY-MM-DD HH:MM`
- **Example:**

```bash
cidrx static --logfile access.log \
  --startTime "2025-10-09 08:00"
```

###### `--endTime`

Filter logs ending at this time.

- **Type:** String
- **Formats:** `YYYY-MM-DD`, `YYYY-MM-DD HH`, or `YYYY-MM-DD HH:MM`
- **Example:**

```bash
cidrx static --logfile access.log \
  --startTime "2025-10-09 08:00" \
  --endTime "2025-10-09 20:00"
```

##### Clustering Options

###### `--clusterArgSets`

Cluster detection parameters. Can be specified multiple times for different detection strategies.

- **Type:** String (comma-separated values)
- **Format:** `minClusterSize,minDepth,maxDepth,meanSubnetDifference`
- **Multiple:** Yes (use flag multiple times)
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2
```

**Parameters:**

| Parameter | Description | Typical Range |
|-----------|-------------|---------------|
| `minClusterSize` | Minimum requests to form cluster | 100-10000 |
| `minDepth` | Minimum CIDR subnet bits | 8-24 |
| `maxDepth` | Maximum CIDR subnet bits | 24-32 |
| `meanSubnetDifference` | Clustering threshold | 0.05-0.3 |

See [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) for tuning guide.

##### Filtering Options

###### `--useragentRegex`

Filter requests by User-Agent pattern.

- **Type:** String (regex)
- **Example:**

```bash
# Match bot traffic
cidrx static --logfile access.log \
  --useragentRegex '.*[Bb]ot.*'

# Match specific browsers
cidrx static --logfile access.log \
  --useragentRegex 'Chrome|Firefox'
```

###### `--endpointRegex`

Filter requests by URL endpoint pattern.

- **Type:** String (regex)
- **Example:**

```bash
# Match API endpoints
cidrx static --logfile access.log \
  --endpointRegex '/api/.*'

# Match admin pages
cidrx static --logfile access.log \
  --endpointRegex '/admin/.*'
```

###### `--whitelist`

Path to IP/CIDR whitelist file. IPs in this file are never flagged or banned.

- **Type:** String (file path)
- **Format:** One IP or CIDR per line
- **Example:**

```bash
cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt
```

**File format:**

```text
# Whitelist file
10.0.0.0/8
192.168.1.100
203.0.113.5
```

###### `--blacklist`

Path to IP/CIDR blacklist file. IPs in this file are always flagged.

- **Type:** String (file path)
- **Format:** One IP or CIDR per line
- **Example:**

```bash
cidrx static --logfile access.log \
  --blacklist /etc/cidrx/blacklist.txt
```

###### `--userAgentWhitelist`

Path to User-Agent whitelist file. Requests matching these patterns are never flagged.

- **Type:** String (file path)
- **Format:** One regex pattern per line
- **Example:**

```bash
cidrx static --logfile access.log \
  --userAgentWhitelist /etc/cidrx/ua_whitelist.txt
```

**File format:**

```text
# User-Agent whitelist
Googlebot.*
UptimeRobot.*
^curl/.*
```

###### `--userAgentBlacklist`

Path to User-Agent blacklist file. Requests matching these patterns are always flagged.

- **Type:** String (file path)
- **Format:** One regex pattern per line
- **Example:**

```bash
cidrx static --logfile access.log \
  --userAgentBlacklist /etc/cidrx/ua_blacklist.txt
```

See [Filtering]({{< relref "/docs/configuration/filtering/" >}}) for comprehensive filtering documentation.

##### Analysis Options

###### `--rangesCidr`

Analyze specific CIDR ranges to see request counts. Can be specified multiple times.

- **Type:** String (CIDR notation)
- **Multiple:** Yes
- **Example:**

```bash
cidrx static --logfile access.log \
  --rangesCidr 14.160.0.0/12 \
  --rangesCidr 198.51.0.0/16
```

###### `--plotPath`

Generate HTML heatmap visualization and save to specified path.

- **Type:** String (file path)
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plotPath /tmp/heatmap.html
```

Opens an interactive heatmap showing IP distribution across detected clusters.

##### Output Options

###### `--plain`

Output human-readable plain text format.

- **Type:** Boolean
- **Default:** `false`
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

###### `--compact`

Output compact JSON (single line, no formatting).

- **Type:** Boolean
- **Default:** `false`
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --compact
```

###### `--tui`

Launch interactive Terminal User Interface.

- **Type:** Boolean
- **Default:** `false`
- **Requires:** `--config` (TUI only works with config files)
- **Example:**

```bash
cidrx static --config cidrx.toml --tui
```

See [Output Formats]({{< relref "/docs/usage/output/" >}}) for detailed output documentation.

##### Ban Management Options

###### `--jailFile`

Path to jail file for ban persistence across runs.

- **Type:** String (file path)
- **Format:** JSON
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --jailFile /var/lib/cidrx/jail.json
```

###### `--banFile`

Path to output file for detected IPs/ranges (one per line).

- **Type:** String (file path)
- **Example:**

```bash
cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --banFile /tmp/banned_ips.txt
```

Can be used with firewall scripts to automatically block detected ranges.

---

### `live` - Live Mode Analysis

Continuous real-time log analysis with sliding window detection.

**Usage:**

```bash
cidrx live [command options]
```

**Example:**

```bash
cidrx live --config /etc/cidrx/live.toml
```

#### Live Mode Options

##### Core Options

###### `--config`

Path to TOML configuration file. When specified, all other command-line flags are ignored.

- **Type:** String (file path)
- **Mutually Exclusive:** Yes (with all other flags)
- **Required:** Recommended for live mode
- **Example:**

```bash
cidrx live --config /etc/cidrx/live.toml
```

###### `--port`

Port to listen on for incoming log data (Lumberjack protocol).

- **Type:** Integer
- **Default:** `5044`
- **Example:**

```bash
cidrx live --port 5044 \
  --clusterArgSet 1000,24,32,0.1
```

##### Window Configuration

###### `--slidingWindowMaxTime`

Maximum time duration for the sliding window.

- **Type:** Duration
- **Default:** `2h0m0s`
- **Format:** Go duration (e.g., `30m`, `1h`, `2h30m`)
- **Example:**

```bash
cidrx live --config live.toml \
  --slidingWindowMaxTime 1h
```

###### `--slidingWindowMaxSize`

Maximum number of requests in the sliding window.

- **Type:** Integer
- **Default:** `100000`
- **Example:**

```bash
cidrx live --config live.toml \
  --slidingWindowMaxSize 200000
```

When either time or size limit is reached, oldest entries are removed.

###### `--sleepBetweenIterations`

Sleep duration between clustering iterations (in seconds).

- **Type:** Integer (seconds)
- **Default:** `10`
- **Example:**

```bash
cidrx live --config live.toml \
  --sleepBetweenIterations 30
```

Higher values reduce CPU usage but increase detection latency.

##### Clustering Options

###### `--clusterArgSet`

Cluster detection parameters for live mode. Can be specified multiple times.

- **Type:** String (comma-separated values)
- **Format:** `minClusterSize,minDepth,maxDepth,meanSubnetDifference`
- **Multiple:** Yes
- **Example:**

```bash
cidrx live --port 5044 \
  --clusterArgSet 1000,24,32,0.1 \
  --clusterArgSet 500,28,32,0.05
```

Note: Uses `--clusterArgSet` (singular) in live mode vs `--clusterArgSets` (plural) in static mode.

##### Filtering Options

Live mode supports the same filtering options as static mode:

- `--useragentRegex` - User-Agent regex filter
- `--endpointRegex` - Endpoint regex filter
- `--whitelist` - IP/CIDR whitelist file
- `--blacklist` - IP/CIDR blacklist file
- `--userAgentWhitelist` - User-Agent whitelist file
- `--userAgentBlacklist` - User-Agent blacklist file

See static mode section above or [Filtering]({{< relref "/docs/configuration/filtering/" >}}) for details.

##### Analysis & Output Options

Live mode supports the same analysis and output options as static mode:

- `--rangesCidr` - Analyze specific CIDR ranges
- `--plotPath` - Generate heatmap visualization
- `--plain` - Plain text output
- `--compact` - Compact JSON output

##### Ban Management Options

Live mode supports the same ban management options as static mode:

- `--jailFile` - Ban persistence file
- `--banFile` - Output file for detected IPs

---

## Complete Examples

### Basic Static Analysis

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Multi-Strategy Detection

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 \
  --clusterArgSets 10000,12,16,0.1 \
  --plain
```

### Time-Bounded Analysis

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --startTime "2025-10-09 08:00" \
  --endTime "2025-10-09 20:00" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### With Custom Log Format

```bash
cidrx static \
  --logfile /var/log/apache2/access.log \
  --logFormat '%h %^ %^ [%t] "%r" %s %b "%{Referer}i" "%{User-Agent}i"' \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### Filtered Analysis

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --useragentRegex '.*[Bb]ot.*' \
  --endpointRegex '/api/.*' \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

### With CIDR Range Analysis

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --rangesCidr 14.160.0.0/12 \
  --rangesCidr 198.51.0.0/16 \
  --plain
```

### Generate Heatmap

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plotPath /tmp/attack_heatmap.html \
  --plain
```

### JSON Output for Automation

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --compact > /var/log/cidrx/detections.json
```

### With Ban File Output

```bash
cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --banFile /tmp/ban_list.txt \
  --plain

# Apply bans to firewall
while read cidr; do
  iptables -A INPUT -s "$cidr" -j DROP
done < /tmp/ban_list.txt
```

### Live Mode with Config

```bash
cidrx live --config /etc/cidrx/live.toml
```

### Live Mode Command-Line Only

```bash
cidrx live \
  --port 5044 \
  --slidingWindowMaxTime 1h \
  --slidingWindowMaxSize 100000 \
  --sleepBetweenIterations 15 \
  --clusterArgSet 1000,24,32,0.1 \
  --whitelist /etc/cidrx/whitelist.txt \
  --plain
```

## Environment Variables

cidrx does not currently support environment variables for configuration. Use command-line flags or configuration files.

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error (invalid arguments, file not found, etc.) |
| `2` | Configuration error |

## Configuration File vs Command-Line

**Command-line flags** are ideal for:
- Quick ad-hoc analysis
- Scripting and automation
- Testing different parameters

**Configuration files** are better for:
- Complex multi-trie setups
- Production deployments
- Consistent repeatable configurations
- Live mode (required for TUI)

See [Configuration Files]({{< relref "/docs/configuration/config-files/" >}}) for TOML configuration format.

## Tips & Best Practices

1. **Start Simple**: Begin with a single `--clusterArgSets` and tune from there
2. **Use Config Files in Production**: Command-line flags are great for testing but config files are more maintainable
3. **Monitor Performance**: Use `--plain` output to see parse rates and execution times
4. **Whitelist Carefully**: Add known good IPs/ranges to prevent false positives
5. **Multiple Strategies**: Use multiple `--clusterArgSets` to catch attacks at different scales
6. **Time Filtering**: Use `--startTime`/`--endTime` for focused analysis during known attack periods
7. **Automate with JSON**: Use default JSON output (or `--compact`) for parsing with `jq` or scripts
8. **Test Regex Patterns**: Validate `--useragentRegex` and `--endpointRegex` patterns before production use

## Next Steps

- Learn about [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) usage patterns
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) deployment
- Configure with [Configuration Files]({{< relref "/docs/configuration/config-files/" >}})
- Fine-tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Review [Output Formats]({{< relref "/docs/usage/output/" >}}) in detail
