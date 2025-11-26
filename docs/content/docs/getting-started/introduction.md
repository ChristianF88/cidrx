---
title: "Introduction"
description: "Overview of cidrx - High-performance botnet detection and IP clustering tool"
summary: "Learn what cidrx does, its key features, and how it helps protect against botnets"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 100
toc: true
seo:
  title: "Introduction to cidrx"
  description: "Discover cidrx - a high-performance tool for botnet detection through intelligent IP clustering and log analysis"
  canonical: ""
  noindex: false
---

## What is cidrx?

cidrx is a botnet detection tool that analyzes HTTP logs and automatically identifies attack patterns by clustering IP addresses into CIDR ranges.

## Key Features

- **Static Mode**: Analyze historical log files
- **Live Mode**: Real-time protection with automated banning
- **Automatic IP Clustering**: Groups attacking IPs into CIDR ranges without manual configuration
- **Multi-Strategy Detection**: Run multiple detection strategies simultaneously
- **Flexible Filtering**: Whitelist/blacklist support with regex-based User-Agent and endpoint filtering
- **Multiple Output Formats**: JSON, compact JSON, plain text, and interactive TUI

## How It Works

1. **Log Parsing**: Parses HTTP logs using configurable format strings
2. **Filtering**: Applies time-based, pattern-based, and list-based filters
3. **Trie Building**: Constructs IP address tries for efficient clustering
4. **Cluster Detection**: Identifies suspicious CIDR ranges
5. **Jail Management**: Maintains persistent state of detected threats

## Use Cases

- **Emergency Response**: Quickly identify and block attacking networks
- **Real-Time Protection**: Continuous monitoring with automatic banning
- **Scanner Detection**: Identify and block security scanners and bots
- **Forensic Analysis**: Investigate specific time periods

## Limitations

- **IPv4 Only**: Currently only IPv4 addresses are supported. IPv6 is not implemented yet.
- **Lumberjack Protocol**: Live mode uses the Lumberjack protocol for log ingestion. HTTP/JSON API support is planned for future releases.
- **Single IP Field**: Log format must contain exactly one `%h` (IP address) field. Multiple IP fields are not supported.
- **No Duplicate Fields**: Log format cannot contain duplicate field specifiers (e.g., two `%t` timestamp fields or two `%s` status fields).

## Next Steps

Ready to get started? Check out the [Installation Guide]({{< relref "/docs/getting-started/installation/" >}}) to install cidrx, or jump straight to the [Quick Start]({{< relref "/docs/getting-started/quick-start/" >}}) to see it in action.
