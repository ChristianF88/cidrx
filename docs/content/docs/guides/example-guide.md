---
title: "Example Guide: Detecting a bad Botnet"
description: "Step-by-step guide to detecting and blocking a botnet with cidrx"
summary: "Learn how to use cidrx to detect and respond to a real botnet scenario"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 210
toc: true
seo:
  title: "Example Guide: Detecting a Botnet with cidrx"
  description: "Step-by-step walkthrough of detecting and blocking a botnet using cidrx static and live modes"
  canonical: ""
  noindex: false
---

This guide walks you through detecting and responding to a real-world botnet using cidrx.

## Scenario

You're running a web application and notice unusual traffic patterns. Your server is experiencing:
- High request volume
- Slow response times
- Many requests from unknown IPs

Let's use cidrx to identify the attack and block malicious traffic.

## Step 1: Initial Analysis

First, analyze your access logs to identify suspicious patterns:

```bash
cd cidrx/cidrx/src
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

**What this does:**
- Analyzes your Nginx access log
- Detects IP clusters with 1000+ requests
- Checks CIDR ranges from /24 to /32
- Uses 0.1 (10%) clustering threshold

## Step 2: Examine the Results

cidrx output shows detected threat ranges:

```
🔍 CLUSTERING RESULTS
Set 1: min_size=1000, depth=24-32, threshold=0.10
Detected Threat Ranges:
  45.142.120.0/24        15,243 requests  ( 12.34%)
  103.45.67.128/25        8,891 requests  (  7.20%)
  198.51.100.42/32        3,456 requests  (  2.80%)
  ───────────────────    27,590 requests  ( 22.34%) [TOTAL]
```

**Analysis:**
- `45.142.120.0/24` - Large botnet (256 IPs)
- `103.45.67.128/25` - Medium cluster (128 IPs)  
- `198.51.100.42/32` - Single aggressive IP

## Step 3: Refine Detection

Use multiple strategies to catch different attack patterns:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

**Strategy breakdown:**
1. **Aggressive scanners** - 500+ requests, small ranges (/28-/32)
2. **Medium botnets** - 2000+ requests, medium ranges (/20-/28)
3. **Large campaigns** - 10000+ requests, large ranges (/16-/24)

## Step 4: Filter False Positives

Exclude legitimate traffic using whitelists:

```bash
# Create whitelist for known good IPs
cat > /tmp/whitelist.txt << 'WHITELIST'
8.8.8.0/24
# Google crawlers
# Monitoring services
# Your office IPs
WHITELIST

./cidrx static \
  --logfile /var/log/nginx/access.log \
  --whitelist /tmp/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Step 5: Generate Block List

Create a ban file for your firewall:

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --jailFile /tmp/jail.json \
  --banFile /tmp/ban.txt \
  --plain
```

Check the ban file:

```bash
cat /tmp/ban.txt
```

Output:
```
45.142.120.0/24
103.45.67.128/25
198.51.100.42/32
```

## Step 6: Block Malicious Traffic

### Option A: iptables

```bash
while read cidr; do
  iptables -I INPUT -s $cidr -j DROP
done < /tmp/ban.txt
```

### Option B: Nginx

Add to your nginx config:

```nginx
# /etc/nginx/conf.d/blocklist.conf
deny 45.142.120.0/24;
deny 103.45.67.128/25;
deny 198.51.100.42/32;
```

Reload Nginx:

```bash
nginx -s reload
```

### Option C: fail2ban

Create a fail2ban filter using cidrx output.

## Step 7: Enable Real-Time Protection

Switch to live mode for ongoing protection:

```bash
# Create configuration file
cat > /etc/cidrx/config.toml << 'CONFIG'
[global]
jailFile = "/var/cidrx/jail.json"
banFile = "/var/cidrx/ban.txt"

[live]
port = "5044"

[live.realtime_protection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 30
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
CONFIG

# Run cidrx in live mode
./cidrx live --config /etc/cidrx/config.toml
```

## Step 8: Monitor and Adjust

Watch cidrx detect attacks in real-time:

```bash
# In another terminal
tail -f /var/cidrx/ban.txt

# Check jail state
cat /var/cidrx/jail.json | jq '.ranges | length'
```

**Adjust thresholds** based on your traffic:
- Low traffic site: Lower `min_size` to 100-500
- High traffic site: Increase to 5000-10000
- Targeted attacks: Use smaller CIDR ranges (/28-/32)
- Distributed attacks: Use larger ranges (/16-/24)

## Step 9: Automate Blocking

Create a cron job to apply bans automatically:

```bash
# /etc/cron.d/cidrx-ban
*/5 * * * * root /usr/local/bin/apply-cidrx-bans.sh
```

Create the script:

```bash
cat > /usr/local/bin/apply-cidrx-bans.sh << 'SCRIPT'
#!/bin/bash
BAN_FILE="/var/cidrx/ban.txt"

if [ -f "$BAN_FILE" ]; then
  while read cidr; do
    # Check if rule exists
    if ! iptables -C INPUT -s $cidr -j DROP 2>/dev/null; then
      iptables -I INPUT -s $cidr -j DROP
      echo "Blocked: $cidr"
    fi
  done < "$BAN_FILE"
fi
SCRIPT

chmod +x /usr/local/bin/apply-cidrx-bans.sh
```

## Step 10: Verify Attack Mitigation

After blocking, check if the attack stopped:

```bash
# Compare before and after
grep "$(date +%d/%b/%Y)" /var/log/nginx/access.log | wc -l

# Check for blocked IPs in logs
tail -f /var/log/syslog | grep "DPT=80"
```

## Advanced: Attack Pattern Analysis

Analyze attack characteristics:

```bash
# Check User-Agent patterns
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --useragentRegex ".*bot.*|.*scanner.*|.*python.*" \
  --clusterArgSets 100,30,32,0.05 \
  --plain

# Check targeted endpoints
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --endpointRegex "/api/.*|/admin/.*" \
  --clusterArgSets 500,28,32,0.1 \
  --plain

# Time-based analysis (last hour)
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --startTime "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Summary

You've successfully:
1. ✅ Detected botnet attack patterns
2. ✅ Identified malicious CIDR ranges
3. ✅ Generated block lists
4. ✅ Blocked malicious traffic
5. ✅ Enabled real-time protection
6. ✅ Automated ongoing defense

## Next Steps

- [Learn about clustering parameters]({{< relref "/docs/configuration/clustering/" >}})
- [Configure advanced filtering]({{< relref "/docs/configuration/filtering/" >}})
- [Optimize for your workload]({{< relref "/docs/advanced/performance/" >}})
- [Set up Docker testing]({{< relref "/docs/usage/docker/" >}})

## Troubleshooting

**No threats detected?**
- Lower the `min_size` threshold
- Check your log format matches
- Verify the log file path

**Too many false positives?**
- Add legitimate IPs to whitelist
- Increase the clustering threshold
- Use more restrictive CIDR depth ranges

**Performance issues?**
- Use smaller time windows in live mode
- Optimize clustering parameters
- See [Performance Tuning]({{< relref "/docs/advanced/performance/" >}})
