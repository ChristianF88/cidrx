---
title: "Usage Overview"
description: "Overview of cidrx usage patterns and workflows"
summary: "Quick reference and workflow examples for cidrx static and live modes"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 205
toc: true
seo:
  title: "cidrx Usage Overview"
  description: "Quick reference guide for cidrx commands and common workflows"
  canonical: ""
  noindex: false
---

cidrx offers flexible usage patterns to fit your security needs, from one-time log analysis to continuous real-time protection.

## Operating Modes

### Static Mode

[Static Mode]({{< relref "/docs/usage/static-mode/" >}}) analyzes historical log files to identify attack patterns. Perfect for:

- Post-incident analysis
- Regular security audits
- Batch processing of archived logs
- Testing detection strategies

**Performance**: 2.4M+ requests/sec parsing speed

### Live Mode

[Live Mode]({{< relref "/docs/usage/live-mode/" >}}) provides real-time protection by continuously monitoring incoming logs. Ideal for:

- Active botnet protection
- Real-time threat detection
- Automatic IP banning
- Continuous security monitoring

**Deployment**: Runs as a service, maintains sliding windows of recent activity

## Output Options

cidrx supports multiple [output formats]({{< relref "/docs/usage/output/" >}}) to fit different workflows:

- **JSON**: Structured data for programmatic processing
- **Compact JSON**: Single-line output for SIEM integration
- **Plain Text**: Human-readable formatted reports
- **TUI**: Interactive terminal interface with visualizations

## Docker Deployment

For testing and containerized deployments, use the [Docker setup]({{< relref "/docs/usage/docker/" >}}) which provides:

- Complete test environment
- Simulated attack traffic
- Nginx + Filebeat + cidrx stack
- Easy configuration management

## Quick Reference

### Common Static Mode Commands

```bash
# Basic analysis
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain

# Multi-strategy detection
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --plain

# Configuration-based
./cidrx static --config cidrx.toml --plain
```

### Common Live Mode Commands

```bash
# Basic live monitoring
./cidrx live --port 8080 \
  --jailFile /etc/cidrx/jail.json \
  --banFile /etc/cidrx/ban.txt \
  --slidingWindowMaxTime 2h \
  --slidingWindowMaxSize 100000

# Configuration-based
./cidrx live --config /etc/cidrx/config.toml
```

### Docker Commands

```bash
# Start test environment
docker compose up --build

# Monitor detections
docker compose logs -f cidrx

# Check ban list
docker compose exec cidrx cat /data/blocklist.txt
```

## Workflow Examples

### Emergency Response Workflow

1. Run static analysis on recent logs
2. Identify attack CIDR ranges
3. Add ranges to ban file
4. Deploy to firewall/WAF
5. Start live mode for ongoing protection

### Regular Security Audit Workflow

1. Configure multiple detection strategies in TOML
2. Run weekly analysis on log archives
3. Review detected patterns
4. Update whitelist/blacklist as needed
5. Archive results for compliance

### Development/Testing Workflow

1. Start Docker test environment
2. Configure detection parameters
3. Observe detection behavior
4. Fine-tune cluster settings
5. Deploy to production

## Next Steps

- [Static Mode Guide]({{< relref "/docs/usage/static-mode/" >}}) - Detailed static analysis usage
- [Live Mode Guide]({{< relref "/docs/usage/live-mode/" >}}) - Real-time protection setup
- [Docker Setup]({{< relref "/docs/usage/docker/" >}}) - Testing and containerization
- [Output Formats]({{< relref "/docs/usage/output/" >}}) - Understanding and using different outputs
