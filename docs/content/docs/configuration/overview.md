---
title: "Configuration Overview"
description: "Overview of cidrx configuration best practices and examples"
summary: "Configuration methods, validation, best practices, and environment-specific examples"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 305
toc: true
seo:
  title: "cidrx Configuration Overview"
  description: "Best practices and examples for configuring cidrx across different environments"
  canonical: ""
  noindex: false
---

cidrx offers extensive configuration options to tailor detection behavior to your specific needs.

## Configuration Methods

### Command-Line Arguments

Quick one-off analysis:

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --whitelist /etc/cidrx/whitelist.txt \
  --plain
```

Best for: Testing, ad-hoc analysis, simple scenarios

### TOML Configuration Files

Complex multi-scenario analysis:

```bash
./cidrx static --config /etc/cidrx/config.toml --plain
```

Best for: Production deployments, multiple strategies, reproducible analysis

## Configuration Sections

### Global Settings

[Configuration Files]({{< relref "/docs/configuration/config-files/" >}}) cover:
- Jail and ban file locations
- Whitelist/blacklist files
- User-Agent filtering lists
- Global parameters

### Log Format Configuration

[Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) explain:
- Format specifiers for Apache/Nginx
- Custom log format parsing
- X-Forwarded-For handling
- Timestamp extraction

### Filtering Configuration

[Filtering]({{< relref "/docs/configuration/filtering/" >}}) details:
- IP whitelist/blacklist management
- User-Agent pattern matching
- Endpoint regex filtering
- Time-based filtering

### Cluster Detection

[Clustering]({{< relref "/docs/configuration/clustering/" >}}) covers:
- Cluster parameter tuning
- Multiple detection strategies
- Threshold optimization
- Performance considerations

## Quick Reference

### Basic Configuration File

```toml
[global]
jailFile = "/tmp/cidrx_jail.json"
banFile = "/tmp/cidrx_ban.txt"

[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""

[static.default]
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
```

### Production Configuration

```toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"

[live]
port = "8080"

[live.botnet_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2]]
useForJail = [true, true]
```

## Configuration Examples

### Example Files

cidrx includes example configurations:

- `cidrx.toml` - Production configuration
- `cidrx.toml.example` - Comprehensive documentation
- `docker-test-config.toml` - Docker testing

### Download Examples

```bash
# View example configuration
cat cidrx/cidrx.toml.example

# Copy and customize
cp cidrx/cidrx.toml.example /etc/cidrx/config.toml
nano /etc/cidrx/config.toml
```

## Configuration Validation

### Test Configuration

Validate syntax before deployment:

```bash
# Static mode (will fail on invalid config)
./cidrx static --config /etc/cidrx/config.toml --plain

# Live mode (validate before starting service)
./cidrx live --config /etc/cidrx/config.toml
```

### Common Issues

**Missing fields:**
```
Error: Missing required field 'logFile' in [static] section
```

**Invalid syntax:**
```
Error: TOML parse error at line 15: expected '=', found ':'
```

**Invalid values:**
```
Error: clusterArgSets must have exactly 4 values: [minSize,minDepth,maxDepth,threshold]
```

## Configuration Best Practices

1. **Version control**: Store configurations in git
2. **Comments**: Document why specific values were chosen
3. **Validate**: Test configurations before production
4. **Backup**: Keep backups of working configurations
5. **Separate environments**: Use different configs for dev/staging/prod
6. **Security**: Protect whitelist/blacklist files with proper permissions

## Environment-Specific Configurations

### Development

```toml
# dev-config.toml
[global]
jailFile = "/tmp/dev-jail.json"
banFile = "/tmp/dev-ban.txt"

[static]
logFile = "./test-data/access.log"

[static.test]
clusterArgSets = [[100,28,32,0.1]]  # Lower threshold for testing
useForJail = [true]
```

### Staging

```toml
# staging-config.toml
[global]
jailFile = "/var/lib/cidrx/staging-jail.json"
banFile = "/var/lib/cidrx/staging-ban.txt"
whitelist = "/etc/cidrx/whitelist-staging.txt"

[live]
port = "8080"

[live.staging_protection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
```

### Production

```toml
# production-config.toml
[global]
jailFile = "/var/lib/cidrx/jail.json"
banFile = "/var/lib/cidrx/ban.txt"
whitelist = "/etc/cidrx/whitelist.txt"
blacklist = "/etc/cidrx/blacklist.txt"
userAgentWhitelist = "/etc/cidrx/ua_whitelist.txt"
userAgentBlacklist = "/etc/cidrx/ua_blacklist.txt"

[live]
port = "8080"

[live.main_protection]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1], [5000,20,28,0.2], [10000,16,24,0.3]]
useForJail = [true, true, true]

[live.scanner_detection]
slidingWindowMaxTime = "1h"
slidingWindowMaxSize = 50000
sleepBetweenIterations = 5
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[100,30,32,0.05]]
useForJail = [true]
```

## Dynamic Configuration

### Reload Configuration

Currently, cidrx requires restart for configuration changes:

```bash
# systemd
sudo systemctl restart cidrx

# Docker
docker compose restart cidrx
```

### Configuration Monitoring

Monitor configuration file for changes:

```bash
#!/bin/bash
# watch-config.sh

CONFIG_FILE="/etc/cidrx/config.toml"
LAST_HASH=""

while true; do
  CURRENT_HASH=$(md5sum "$CONFIG_FILE" | cut -d' ' -f1)

  if [ "$CURRENT_HASH" != "$LAST_HASH" ] && [ -n "$LAST_HASH" ]; then
    echo "Configuration changed, restarting cidrx..."
    systemctl restart cidrx
  fi

  LAST_HASH="$CURRENT_HASH"
  sleep 60
done
```

## Next Steps

- Configure [TOML Files]({{< relref "/docs/configuration/config-files/" >}}) for your deployment
- Set up [Log Format Parsing]({{< relref "/docs/configuration/log-formats/" >}})
- Implement [Filtering]({{< relref "/docs/configuration/filtering/" >}}) strategies
- Tune [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}}) parameters
