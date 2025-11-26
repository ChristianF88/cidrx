---
title: "Live Mode"
description: "Real-time botnet protection with cidrx live mode"
summary: "Complete guide to using cidrx for continuous monitoring and automatic threat blocking"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 220
toc: true
seo:
  title: "cidrx Live Mode Guide"
  description: "Learn how to deploy cidrx in live mode for real-time botnet protection with automatic banning"
  canonical: ""
  noindex: false
---

Live mode provides real-time protection by continuously monitoring incoming logs and automatically detecting and blocking attack patterns.

## Overview

Live mode operates fundamentally differently from static mode:

- **Continuous Operation**: Runs as a long-lived service
- **Sliding Windows**: Maintains recent request history in memory
- **Automatic Updates**: Continuously updates jail and ban files
- **Real-Time Detection**: Detects attacks as they happen
- **Log Streaming**: Receives logs via Lumberjack protocol

## Basic Usage

### Simple Live Mode

Start basic real-time monitoring:

```bash
./cidrx live --port 8080 \
  --jailFile /etc/cidrx/jail.json \
  --banFile /etc/cidrx/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000
```

This configuration:
- Listens on port 8080 for Lumberjack protocol
- Maintains a 2-hour sliding window
- Keeps up to 100,000 recent requests in memory
- Updates `/etc/cidrx/jail.json` and `/etc/cidrx/ban.txt` automatically

### Configuration-Based Live Mode

For production deployments, use a configuration file:

```bash
./cidrx live --config /etc/cidrx/config.toml
```

This is the recommended approach for several reasons:
- Easier to manage complex configurations
- Version controllable
- Supports multiple independent windows
- Safer than long command lines

## Configuration File Structure

### Single Window Configuration

Basic `config.toml` for live mode:

```toml
[global]
jailFile = "/etc/cidrx/jail.json"
banFile = "/etc/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"

[live]
port = "8080"

[live.realtime_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
```

### Multiple Window Configuration

Run multiple independent analyses simultaneously:

```toml
[global]
jailFile = "/etc/cidrx/jail.json"
banFile = "/etc/cidrx/ban.txt"

[live]
port = "8080"

[live.realtime_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]

[live.scanner_detection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*bot.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[live.api_abuse]
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 25000
sleepBetweenIterations = 5
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

Each `[live.X]` section creates an independent sliding window:
- **realtime_protection**: General botnet detection over 2 hours
- **scanner_detection**: Fast scanner detection over 1 hour
- **api_abuse**: API-specific abuse detection over 30 minutes

All windows run concurrently and contribute to the same jail file.

## Sliding Window Parameters

### Time Window (slidingWindowMaxTime)

Controls how far back to keep history:

```toml
slidingWindowMaxTime = "2h"   # 2 hours
slidingWindowMaxTime = "30m"  # 30 minutes
slidingWindowMaxTime = "4h"   # 4 hours
```

Supported units: `s` (seconds), `m` (minutes), `h` (hours)

**Trade-offs:**
- **Longer windows**: Catch slower attacks, use more memory
- **Shorter windows**: Catch fast attacks only, use less memory

### Size Limit (slidingWindowMaxSize)

Maximum number of requests to keep:

```toml
slidingWindowMaxSize = 100000  # 100k requests
slidingWindowMaxSize = 50000   # 50k requests
slidingWindowMaxSize = 200000  # 200k requests
```

**Memory impact:**
- ~50-100 bytes per request
- 100,000 requests ≈ 5-10 MB
- 1,000,000 requests ≈ 50-100 MB

### Iteration Sleep (sleepBetweenIterations)

How often to run detection (in seconds):

```toml
sleepBetweenIterations = 10   # Every 10 seconds
sleepBetweenIterations = 5    # Every 5 seconds
sleepBetweenIterations = 30   # Every 30 seconds
```

**Trade-offs:**
- **Shorter intervals**: Faster detection, higher CPU usage
- **Longer intervals**: Lower CPU usage, slightly delayed detection

## Lumberjack Protocol Integration

cidrx receives logs via the Lumberjack protocol, commonly used by Filebeat and Logstash.

### Filebeat Configuration

Configure Filebeat to ship logs to cidrx:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log

output.logstash:
  hosts: ["cidrx-host:8080"]
  compression_level: 3
```

Restart Filebeat:

```bash
sudo systemctl restart filebeat
```

### Logstash Configuration

Alternative using Logstash:

```ruby
# logstash.conf
input {
  file {
    path => "/var/log/nginx/access.log"
    start_position => "beginning"
  }
}

output {
  lumberjack {
    hosts => ["cidrx-host:8080"]
    codec => "json"
  }
}
```

## Jail and Ban File Management

### Automatic Updates

Live mode automatically updates jail and ban files:

1. **Every iteration** (based on `sleepBetweenIterations`)
2. **When new threats detected**
3. **On graceful shutdown**

### File Locations

Specify locations in configuration:

```toml
[global]
jailFile = "/etc/cidrx/jail.json"
banFile = "/etc/cidrx/ban.txt"
```

**Recommendations:**
- Use `/etc/cidrx/` for configuration
- Use `/var/lib/cidrx/` for state files
- Ensure write permissions
- Back up jail files regularly

### Jail File Format

The jail file (`jail.json`) contains detailed threat information:

```json
{
  "45.40.50.192/26": {
    "cidr": "45.40.50.192/26",
    "count": 3083,
    "first_seen": "2025-10-09T08:15:23Z",
    "last_seen": "2025-10-09T10:22:15Z",
    "detection_strategy": "realtime_protection"
  }
}
```

### Ban File Format

The ban file (`ban.txt`) is a simple list:

```
45.40.50.192/26
198.51.205.91/32
20.171.207.2/32
```

## Integration with Firewalls

### iptables Integration

Monitor ban file and update iptables:

```bash
#!/bin/bash
# watch-banfile.sh

BANFILE="/etc/cidrx/ban.txt"
LAST_HASH=""

while true; do
  CURRENT_HASH=$(md5sum "$BANFILE" | cut -d' ' -f1)

  if [ "$CURRENT_HASH" != "$LAST_HASH" ]; then
    echo "Ban file changed, updating iptables..."

    # Clear old rules
    iptables -F CIDRX-BLOCK 2>/dev/null || iptables -N CIDRX-BLOCK

    # Add new rules
    while read cidr; do
      iptables -A CIDRX-BLOCK -s "$cidr" -j DROP
    done < "$BANFILE"

    LAST_HASH="$CURRENT_HASH"
  fi

  sleep 10
done
```

### nginx Integration

Use ban file directly in nginx:

```nginx
# nginx.conf
http {
  # Include ban file
  include /etc/cidrx/ban.txt;
}
```

Format ban file for nginx (modify cidrx output or post-process):

```bash
# Convert to nginx format
sed 's/^/deny /' /etc/cidrx/ban.txt > /etc/nginx/cidrx-bans.conf
nginx -s reload
```

### fail2ban Integration

Use cidrx as a fail2ban action:

```ini
# /etc/fail2ban/action.d/cidrx.conf
[Definition]
actionban = grep -q <ip> /etc/cidrx/banlist.txt || echo <ip> >> /etc/cidrx/banlist.txt
actionunban = sed -i '/<ip>/d' /etc/cidrx/banlist.txt
```

## Filtering in Live Mode

### Whitelist/Blacklist

Protect known good IPs and focus on threats:

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"
```

### Pattern Matching

Use regex to filter traffic:

```toml
[live.scanner_detection]
slidingWindowMaxTime = "1h"
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

[live.api_abuse]
slidingWindowMaxTime = "30m"
endpointRegex = "/api/login|/api/register"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]
```

## Monitoring Live Mode

### Log Output

cidrx logs detection events to stdout/stderr:

```bash
# View live logs
./cidrx live --config /etc/cidrx/config.toml

# Or with systemd
journalctl -u cidrx -f
```

### JSON Logging

For structured logging, redirect to a file:

```bash
./cidrx live --config /etc/cidrx/config.toml 2>&1 | tee -a /var/log/cidrx/detections.log
```

### Metrics and Monitoring

Monitor these files for changes:

- `/etc/cidrx/jail.json` - New detections
- `/etc/cidrx/ban.txt` - Active bans
- Process memory usage
- Log ingestion rate

Example monitoring script:

```bash
#!/bin/bash
# monitor-cidrx.sh

while true; do
  JAIL_SIZE=$(wc -l < /etc/cidrx/ban.txt)
  MEMORY=$(ps aux | grep cidrx | awk '{print $6}')

  echo "$(date) - Banned CIDRs: $JAIL_SIZE, Memory: ${MEMORY}KB"

  sleep 60
done
```

## Production Deployment

### systemd Service

Create `/etc/systemd/system/cidrx.service`:

```ini
[Unit]
Description=cidrx Botnet Protection
After=network.target filebeat.service
Wants=filebeat.service

[Service]
Type=simple
User=cidrx
Group=cidrx
ExecStart=/usr/local/bin/cidrx live --config /etc/cidrx/config.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/cidrx /etc/cidrx

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cidrx
sudo systemctl start cidrx
sudo systemctl status cidrx
```

### User and Permissions

Create dedicated user:

```bash
sudo useradd -r -s /bin/false cidrx
sudo mkdir -p /var/lib/cidrx /etc/cidrx
sudo chown cidrx:cidrx /var/lib/cidrx /etc/cidrx
sudo chmod 755 /var/lib/cidrx /etc/cidrx
```

### Log Rotation

Configure log rotation if logging to files:

```bash
# /etc/logrotate.d/cidrx
/var/log/cidrx/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 cidrx cidrx
    sharedscripts
    postrotate
        systemctl reload cidrx
    endscript
}
```

## Performance Tuning

Adjust window sizes and iteration frequency based on your traffic patterns. See [Performance]({{< relref "/docs/advanced/performance/" >}}) for detailed optimization strategies.

## Troubleshooting

### No Logs Received

Check Filebeat/Logstash connectivity:

```bash
# Test port is open
telnet cidrx-host 8080

# Check Filebeat logs
journalctl -u filebeat -f

# Verify cidrx is listening
netstat -tlnp | grep 8080
```

### High Memory Usage

Reduce window parameters:

```toml
slidingWindowMaxSize = 50000  # Reduce from 100000
slidingWindowMaxTime = "1h"   # Reduce from 2h
```

### Jail File Growing Too Large

Review and purge old entries:

```bash
# Backup
cp /etc/cidrx/jail.json /etc/cidrx/jail.json.backup

# Clear (cidrx will rebuild)
echo "{}" > /etc/cidrx/jail.json

# Restart cidrx
systemctl restart cidrx
```

### False Positives

Tune detection parameters:

```toml
# Increase thresholds
clusterArgSets = [[5000,24,32,0.3]]  # Higher min_size, higher threshold

# Add whitelist
whitelist = "/etc/cidrx/whitelist.txt"
```

## Best Practices

1. **Start conservative**: Use high thresholds initially
2. **Monitor closely**: Watch for false positives in first 24 hours
3. **Maintain whitelists**: Keep legitimate traffic protected
4. **Multiple windows**: Use different windows for different attack types
5. **Regular backups**: Backup jail files and configurations
6. **Review regularly**: Audit banned CIDRs weekly
7. **Test in staging**: Deploy to staging environment first
8. **Document changes**: Keep notes on configuration changes

## Example Production Configuration

Complete production-ready configuration:

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

# Main botnet protection
[live.botnet_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [
  [1000,24,32,0.1],    # Small focused attacks
  [5000,20,28,0.2],    # Medium distributed attacks
  [10000,16,24,0.3]    # Large botnets
]
useForJail = [true, true, true]

# Scanner detection
[live.scanners]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*|.*masscan.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]

# API abuse protection
[live.api_protection]
slidingWindowMaxTime = "30m"
slidingWindowMaxSize = 25000
sleepBetweenIterations = 5
endpointRegex = "/api/.*"
clusterArgSets = [[500,28,32,0.1]]
useForJail = [true]

# Admin panel protection
[live.admin_protection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 5
endpointRegex = "/admin/.*|/wp-admin/.*|/login"
clusterArgSets = [[50,30,32,0.05]]
useForJail = [true]
```

## Next Steps

- Configure [Filebeat]({{< relref "/docs/configuration/log-formats/" >}}) for log shipping
- Set up [Filtering]({{< relref "/docs/configuration/filtering/" >}}) with whitelists
- Fine-tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
- Review [Performance Tips]({{< relref "/docs/advanced/performance/" >}}) for optimization
- Explore [Docker Deployment]({{< relref "/docs/usage/docker/" >}}) for testing
