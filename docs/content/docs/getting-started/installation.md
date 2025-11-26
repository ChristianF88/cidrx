---
title: "Installation"
description: "How to install cidrx on your system"
summary: "Step-by-step instructions for installing cidrx from source or using Docker"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 110
toc: true
seo:
  title: "Install cidrx"
  description: "Complete installation guide for cidrx including source builds, Docker, and dependencies"
  canonical: ""
  noindex: false
---

## Prerequisites

Before installing cidrx, ensure you have the following:

- **Go 1.21 or later** (for building from source)
- **Docker** (optional, for containerized deployment)
- **Git** (for cloning the repository)

## Installation from Source

### Clone the Repository

```bash
git clone https://github.com/ChristianF88/cidrx.git
cd cidrx/cidrx/src
```

### Build the Binary

Basic build:

```bash
go build -o cidrx .
```

Build with optimizations (smaller binary, slightly faster):

```bash
go build -ldflags="-s -w" -o cidrx .
```

The `-ldflags="-s -w"` flags strip debug information and symbol tables, reducing binary size.

### Verify Installation

Check that cidrx is working:

```bash
./cidrx --help
```

You should see the help message with available commands and options.

### Install System-Wide (Optional)

To make cidrx available system-wide:

```bash
sudo mv cidrx /usr/local/bin/
```

Now you can run `cidrx` from anywhere:

```bash
cidrx --help
```

## Docker Installation

### Build Docker Image

From the `cidrx` directory (not `cidrx/src`):

```bash
cd cidrx/cidrx
docker build -t cidrx .
```

### Pull from Docker Hub (Future)

Once published to Docker Hub, you'll be able to pull directly:

```bash
# Coming soon
docker pull christianf88/cidrx:latest
```

### Run Docker Container

Basic run:

```bash
docker run -v /var/log:/logs cidrx static \
  --logfile /logs/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

With configuration file:

```bash
docker run \
  -v /etc/cidrx:/config \
  -v /var/log:/logs \
  cidrx static --config /config/cidrx.toml --plain
```

## Development Setup

If you plan to contribute to cidrx or run tests:

### Install Dependencies

```bash
cd cidrx/cidrx/src
go mod download
```

### Install Development Tools

For code quality checks:

```bash
# Install staticcheck for static analysis
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### Run Tests

Verify everything is working:

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. -benchtime=1ms ./...
```

### Run Static Analysis

```bash
staticcheck ./...
```

## Deployment Considerations

### File Permissions

cidrx needs read access to log files and write access to jail/ban files:

```bash
# Create directories
sudo mkdir -p /etc/cidrx /var/lib/cidrx

# Set permissions for log access
sudo usermod -a -G adm cidrx-user

# Set ownership for state files
sudo chown cidrx-user:cidrx-user /var/lib/cidrx
```

### System Service (systemd)

Create a systemd service for continuous operation:

```ini
[Unit]
Description=cidrx Botnet Protection
After=network.target

[Service]
Type=simple
User=cidrx-user
ExecStart=/usr/local/bin/cidrx live --config /etc/cidrx/config.toml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Save as `/etc/systemd/system/cidrx.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cidrx
sudo systemctl start cidrx
```

### Log Rotation

If using live mode with log files, ensure log rotation doesn't break file handles. cidrx uses the Lumberjack protocol which handles this automatically.

## Platform-Specific Notes

### Linux

No special considerations. cidrx is optimized for Linux.

### macOS

Works without issues. Use Homebrew to install Go if needed:

```bash
brew install go
```

### Windows

While cidrx can be built on Windows, it's primarily designed for Unix-like systems. Use WSL2 for best compatibility.

## Troubleshooting

### Build Errors

**Error: `go: command not found`**

Install Go from https://golang.org/dl/ or use your package manager.

**Error: `package X is not in GOROOT`**

Run `go mod download` to fetch dependencies.

### Permission Errors

**Error: `permission denied` when reading logs**

Add your user to the appropriate group (usually `adm` on Debian/Ubuntu):

```bash
sudo usermod -a -G adm $USER
```

Log out and back in for the change to take effect.

### Runtime Errors

**Error: Cannot create jail file**

Ensure the directory exists and is writable:

```bash
mkdir -p /tmp/cidrx
chmod 755 /tmp/cidrx
```

## Next Steps

Now that you have cidrx installed, head over to the [Quick Start Guide]({{< relref "/docs/getting-started/quick-start/" >}}) to learn how to use it effectively.

For production deployments, check out the [Configuration Guide]({{< relref "/docs/configuration/config-files/" >}}) to set up comprehensive protection strategies.
