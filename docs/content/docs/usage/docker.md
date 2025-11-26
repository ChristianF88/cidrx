---
title: "Docker Setup"
description: "Using cidrx with Docker for testing and deployment"
summary: "Complete guide to running cidrx in Docker with the included test environment"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 230
slug: "docker"
toc: true
seo:
  title: "cidrx Docker Setup Guide"
  description: "Learn how to deploy cidrx with Docker including test environment with simulated attacks"
  canonical: ""
  noindex: false
---

cidrx includes a complete Docker-based test environment that simulates realistic attack scenarios. This is perfect for testing, development, and understanding how cidrx works.

## Overview

The Docker test environment includes:

- **Nginx**: Web server receiving simulated traffic
- **Filebeat**: Log shipper forwarding to cidrx
- **cidrx**: Running in live mode with detection
- **Attack Clients**: 44 simulated attackers across multiple networks

## Quick Start

### Start Test Environment

```bash
cd cidrx/cidrx
docker compose up --build
```

This command:
1. Builds the cidrx Docker image
2. Starts all containers (nginx, filebeat, cidrx, attack clients)
3. Begins simulated attack traffic
4. Shows logs in real-time

### Watch Detections

In a separate terminal:

```bash
docker compose logs -f cidrx
```

You'll see detection events as they occur:

```
cidrx-1 | {"timestamp":"2025-10-09T10:15:23Z","detected_cidrs":["172.16.1.32/30"],"count":4523}
cidrx-1 | {"timestamp":"2025-10-09T10:15:33Z","detected_cidrs":["172.16.16.32/27"],"count":33142}
```

### View Active Bans

Check the generated ban list:

```bash
docker compose exec cidrx cat /data/blocklist.txt
```

Output:

```
172.16.1.32/30
172.16.2.32/31
172.16.3.32/30
172.16.3.36/32
172.16.16.32/27
172.16.16.64/32
```

### View Jail State

Inspect the jail file for detailed information:

```bash
docker compose exec cidrx cat /data/jail.json
```

Output (formatted):

```json
{
  "172.16.1.32/30": {
    "cidr": "172.16.1.32/30",
    "count": 4523,
    "first_seen": "2025-10-09T10:14:15Z",
    "last_seen": "2025-10-09T10:15:20Z",
    "detection_strategy": "default"
  }
}
```

### Stop Environment

```bash
docker compose down
```

To also remove volumes:

```bash
docker compose down -v
```

## Test Environment Architecture

### Network Topology

The test environment creates multiple Docker networks simulating different attack sources:

- **net1** (172.16.1.0/24): 4 attack clients → Expected: `172.16.1.32/30`
- **net2** (172.16.2.0/24): 2 attack clients → Expected: `172.16.2.32/31`
- **net3** (172.16.3.0/24): 5 attack clients → Expected: `172.16.3.32/30` + `172.16.3.36/32`
- **net4** (172.16.16.0/24): 33 attack clients → Expected: `172.16.16.32/27` + `172.16.16.64/32`

Total: **44 simulated attackers**

### Container Roles

**nginx:**
- Receives HTTP requests from attack clients
- Logs in combined format to `/var/log/nginx/access.log`
- Mounted to shared volume

**filebeat:**
- Monitors nginx access log
- Ships log entries to cidrx via Lumberjack protocol
- Runs continuously

**cidrx:**
- Listens on port 8080 for Lumberjack
- Runs live mode with sliding windows
- Updates `/data/jail.json` and `/data/blocklist.txt`
- Configuration mounted from `docker-test-config.toml`

**attack-net1-client-X, attack-net2-client-X, etc:**
- Generate HTTP requests to nginx
- Simulate realistic botnet traffic
- Each makes periodic requests

## Expected Detection Results

Within 1-2 minutes of starting, cidrx should detect:

| Network | CIDR Range | Clients | Status |
|---------|------------|---------|--------|
| net1 | 172.16.1.32/30 | 4 | ✓ Detected |
| net2 | 172.16.2.32/31 | 2 | ✓ Detected |
| net3 | 172.16.3.32/30 | 4 | ✓ Detected |
| net3 | 172.16.3.36/32 | 1 | ✓ Detected |
| net4 | 172.16.16.32/27 | 32 | ✓ Detected (main cluster) |
| net4 | 172.16.16.64/32 | 1 | ✓ Detected |

## Configuration

### Docker Test Configuration

The test environment uses `docker-test-config.toml`:

```toml
[global]
jailFile = "/data/jail.json"
banFile = "/data/blocklist.txt"

[live]
port = "8080"

[live.default]
slidingWindowMaxTime = "5m"
slidingWindowMaxSize = 10000
sleepBetweenIterations = 10
clusterArgSets = [
  [10,30,32,0.1],    # Detect small clusters (for testing)
  [50,28,32,0.2]     # Detect medium clusters
]
useForJail = [true, true]
```

**Note**: These parameters are tuned for quick detection in the test environment. Production values should be higher.

### Editing Configuration

You can edit `docker-test-config.toml` without rebuilding:

```bash
# Edit configuration
nano docker-test-config.toml

# Restart only cidrx container
docker compose restart cidrx

# Watch for new detection behavior
docker compose logs -f cidrx
```

### Volume Mounts

The Docker Compose configuration mounts:

```yaml
volumes:
  - ./docker-test-config.toml:/config/config.toml:ro
  - cidrx-data:/data
  - nginx-logs:/var/log/nginx
```

- **Config**: Read-only, can be updated without rebuild
- **Data**: Persistent jail and ban files
- **Logs**: Shared between nginx and filebeat

## Building Custom Images

### Build cidrx Image

```bash
cd cidrx/cidrx
docker build -t cidrx:latest .
```

### Multi-Stage Build

The Dockerfile uses a multi-stage build:

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /build
COPY src/ ./
RUN go build -ldflags="-s -w" -o cidrx .

# Stage 2: Runtime
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /build/cidrx /usr/local/bin/
ENTRYPOINT ["cidrx"]
```

This produces a small (~20MB) final image.

### Custom Build

To build with specific optimizations:

```bash
docker build \
  --build-arg LDFLAGS="-s -w -X main.version=1.0.0" \
  -t cidrx:1.0.0 \
  .
```

## Production Deployment

### Using Docker in Production

For production deployments, create a custom compose file:

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  cidrx:
    image: cidrx:latest
    restart: always
    ports:
      - "8080:8080"
    volumes:
      - /etc/cidrx/config.toml:/config/config.toml:ro
      - /var/lib/cidrx:/data
    environment:
      - TZ=UTC
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

Deploy:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Docker with Host Networking

For better performance, use host networking:

```yaml
services:
  cidrx:
    image: cidrx:latest
    network_mode: host
    volumes:
      - /etc/cidrx/config.toml:/config/config.toml:ro
      - /var/lib/cidrx:/data
```

This eliminates Docker network overhead.

### Resource Limits

Set resource limits for production:

```yaml
services:
  cidrx:
    image: cidrx:latest
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

## Running Static Mode in Docker

Use Docker for static analysis of log files:

```bash
docker run -v /var/log/nginx:/logs cidrx:latest \
  static \
  --logfile /logs/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

With configuration file:

```bash
docker run \
  -v /etc/cidrx:/config \
  -v /var/log:/logs \
  cidrx:latest static --config /config/cidrx.toml --plain
```

## Integration Testing

### Testing Detection Behavior

Modify attack intensity to test detection:

Edit `docker-compose.yml`:

```yaml
attack-net1-client-1:
  build: ./test-client
  environment:
    - REQUEST_INTERVAL=0.5  # Change from 1 to 0.5 (more aggressive)
    - TARGET_URL=http://nginx
```

Rebuild and restart:

```bash
docker compose up --build
```

### Testing False Positives

Add legitimate traffic to ensure it's not flagged:

```yaml
legitimate-client:
  build: ./test-client
  environment:
    - REQUEST_INTERVAL=10  # Slower, legitimate-looking traffic
    - TARGET_URL=http://nginx
  networks:
    - legitimate_net

networks:
  legitimate_net:
    ipam:
      config:
        - subnet: 192.168.1.0/24
```

### Testing Whitelists

Create a whitelist and mount it:

```bash
# Create whitelist
echo "192.168.1.0/24" > whitelist.txt

# Mount in docker-compose.yml
volumes:
  - ./whitelist.txt:/config/whitelist.txt:ro
```

Update `docker-test-config.toml`:

```toml
[global]
whitelist = "/config/whitelist.txt"
```

## Troubleshooting

### No Logs Received

Check Filebeat connectivity:

```bash
# Check Filebeat status
docker compose exec filebeat filebeat test output

# View Filebeat logs
docker compose logs filebeat

# Verify cidrx is listening
docker compose exec cidrx netstat -tlnp
```

### No Detections

Verify attack clients are running:

```bash
# Check all containers
docker compose ps

# View attack client logs
docker compose logs attack-net1-client-1

# Check nginx access log
docker compose exec nginx tail -f /var/log/nginx/access.log
```

### Container Crashes

View crash logs:

```bash
# Check exit code
docker compose ps -a

# View recent logs
docker compose logs --tail=100 cidrx

# Inspect container
docker inspect cidrx_cidrx_1
```

### Permission Issues

Fix volume permissions:

```bash
# Check current ownership
docker compose exec cidrx ls -la /data

# Fix from host (if needed)
sudo chown -R 1000:1000 ./cidrx-data
```

## Advanced Configuration

### Custom Attack Scenarios

Create custom attack patterns by modifying the test client:

```dockerfile
# custom-test-client/Dockerfile
FROM alpine:latest
RUN apk add --no-cache curl bash
COPY attack-script.sh /attack-script.sh
RUN chmod +x /attack-script.sh
CMD ["/attack-script.sh"]
```

```bash
#!/bin/bash
# attack-script.sh
while true; do
  # Simulate slow scan
  curl -s http://nginx/login >/dev/null
  sleep 30
done
```

### Multiple cidrx Instances

Run multiple instances with different configurations:

```yaml
services:
  cidrx-aggressive:
    image: cidrx:latest
    volumes:
      - ./config-aggressive.toml:/config/config.toml:ro
    ports:
      - "8081:8080"

  cidrx-conservative:
    image: cidrx:latest
    volumes:
      - ./config-conservative.toml:/config/config.toml:ro
    ports:
      - "8082:8080"
```

## Benchmarking in Docker

Test performance in Docker:

```bash
# Generate large log file
docker compose exec nginx sh -c \
  'for i in {1..100000}; do echo "192.0.2.$((RANDOM%256)) - - [09/Oct/2025:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl\""; done > /var/log/nginx/test.log'

# Run static analysis
docker compose exec cidrx cidrx static \
  --logfile /var/log/nginx/test.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Best Practices

1. **Use volumes**: Mount configuration and data directories
2. **Set resource limits**: Prevent resource exhaustion
3. **Enable logging**: Use Docker logging drivers
4. **Health checks**: Add health check endpoints
5. **Security**: Run as non-root user
6. **Networks**: Use custom networks for isolation
7. **Version tags**: Use specific version tags, not `latest`
8. **Monitoring**: Integrate with monitoring solutions

## Next Steps

- Deploy to production with [Live Mode]({{< relref "/docs/usage/live-mode/" >}})
- Configure [Log Formats]({{< relref "/docs/configuration/log-formats/" >}}) for your setup
- Set up [Filtering]({{< relref "/docs/configuration/filtering/" >}}) with whitelists
- Review [Performance]({{< relref "/docs/advanced/performance/" >}}) optimization
