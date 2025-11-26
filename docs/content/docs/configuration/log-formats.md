---
title: "Log Formats"
description: "Configuring log format parsing in cidrx"
summary: "Complete guide to log format specifiers for parsing Apache, Nginx, and custom log formats"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 320
toc: true
seo:
  title: "cidrx Log Format Configuration"
  description: "Learn how to configure cidrx to parse Apache, Nginx, and custom log formats with format specifiers"
  canonical: ""
  noindex: false
---

cidrx uses flexible log format parsing to extract IP addresses, timestamps, and other relevant information from various log file formats.

## Overview

Log format configuration tells cidrx how to parse your log files. The format string uses specifiers similar to Apache's LogFormat directive but with cidrx-specific syntax.

## Format Specifiers

### Available Specifiers

| Specifier | Description | Example | Required |
|-----------|-------------|---------|----------|
| `%h` | IP address | `192.0.2.1` | **Yes** (exactly one) |
| `%t` | Timestamp | `[09/Oct/2025:10:15:23 +0000]` | No |
| `%r` | Request line | `"GET /index.html HTTP/1.1"` | No |
| `%m` | HTTP method | `GET` | No |
| `%U` | URI path | `/index.html` | No |
| `%s` | HTTP status code | `200` | No |
| `%b` | Response bytes | `1234` | No |
| `%u` | User-Agent | `"Mozilla/5.0..."` | No |
| `%^` | Skip field | (any value) | No (unlimited) |

### Required Specifiers

**Exactly one `%h` specifier is required** - this tells cidrx where to find the IP address.

All other specifiers are optional but recommended for better filtering capabilities.

## Common Log Formats

### Nginx Combined Log

Default Nginx combined log format:

```nginx
# nginx.conf
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

cidrx format:

```bash
--logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""
```

Or in TOML:

```toml
[static]
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""
```

### Nginx Combined with X-Forwarded-For

If using a reverse proxy that logs real IP in a custom field:

```nginx
# nginx.conf
log_format proxy '$remote_addr $http_x_forwarded_for - [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';
```

cidrx format (using last field as IP):

```bash
--logFormat "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
```

Note: `%h` is at the end to capture the X-Forwarded-For field.

### Apache Combined Log

Apache combined log format:

```apache
# httpd.conf
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
```

cidrx format:

```bash
--logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""
```

### Apache Common Log

Apache common log format (without User-Agent):

```apache
LogFormat "%h %l %u %t \"%r\" %>s %b" common
```

cidrx format:

```bash
--logFormat "%h %^ %^ [%t] \"%r\" %s %b"
```

## Field Parsing Details

### IP Address (%h)

Parses IPv4 addresses:

```
192.0.2.1
10.0.0.1
172.16.0.1
```

**Important**:
- Must appear exactly once in format string
- Currently supports IPv4 only (IPv6 planned)
- Can be in any position

### Timestamp (%t)

Parses timestamps in common log format:

```
[09/Oct/2025:10:15:23 +0000]
[15/Jan/2025:14:30:45 -0500]
```

Format: `[DD/MMM/YYYY:HH:MM:SS ±ZZZZ]`

**Months**: Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec

**Timezone**: Optional, supports `+HHMM` or `-HHMM`

### Request Line (%r)

Parses full HTTP request:

```
"GET /index.html HTTP/1.1"
"POST /api/login HTTP/1.1"
"HEAD / HTTP/1.0"
```

Extracts:
- HTTP Method (GET, POST, etc.)
- URI Path (/index.html, /api/login)
- HTTP Version (HTTP/1.1, HTTP/1.0)

### HTTP Method (%m)

Standalone method field (alternative to %r):

```
GET
POST
PUT
DELETE
```

Use when method is logged separately from URI.

### URI Path (%U)

Standalone URI field (alternative to %r):

```
/index.html
/api/login
/admin/dashboard
```

Use when URI is logged separately from method.

### HTTP Status (%s)

HTTP response status code:

```
200
404
500
301
```

### Response Bytes (%b)

Number of bytes sent:

```
1234
0
52847
```

### User-Agent (%u)

User-Agent string (typically quoted):

```
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
"curl/7.68.0"
"python-requests/2.25.1"
```

**Important**: User-Agent must be quoted in logs and format string.

### Skip Field (%^)

Skips any field. Can be used multiple times:

```bash
# Skip three fields
--logFormat "%h %^ %^ %^ [%t] \"%r\""

# Skip non-essential data
--logFormat "%^ %h %^ [%t] \"%r\" %s %^"
```

Use `%^` for:
- Fields you don't need
- Fields not supported by cidrx
- Variable-length fields

## Custom Log Formats

### Example 1: Minimal Format

Only IP and timestamp:

```bash
--logFormat "%h %^ %^ [%t]"
```

### Example 2: Custom Delimiter

Logs with pipe delimiters:

```
192.0.2.1|09/Oct/2025:10:15:23|GET|/index.html|200
```

Format:

```bash
--logFormat "%h|[%t]|%m|%U|%s"
```

**Note**: Delimiters in format string must match log file delimiters.

### Example 3: Extra Fields

Logs with additional fields:

```
host=192.0.2.1 user=john time=[09/Oct/2025:10:15:23] req="GET /" status=200
```

Format:

```bash
--logFormat "host=%h user=%^ time=[%t] req=\"%r\" status=%s"
```

### Example 4: JSON Logs

For JSON-formatted logs:

```json
{"ip":"192.0.2.1","time":"09/Oct/2025:10:15:23","request":"GET /"}
```

Format (treating JSON as fields):

```bash
--logFormat "{\"ip\":\"%h\",\"time\":\"[%t]\",\"request\":\"%r\"}"
```

**Note**: This is experimental. Native JSON parsing may be added in future versions.

## Format String Rules

### Quoting

Quotes in format string must match quotes in log file:

```bash
# Log has double quotes: "GET /"
--logFormat "\"%r\""  # Correct

# Log has single quotes: 'GET /'
--logFormat "'%r'"    # Correct
```

### Whitespace

Whitespace in format string must match log file:

```bash
# Log has: 192.0.2.1 - - [timestamp]
--logFormat "%h %^ %^ [%t]"  # Correct (spaces match)

# Log has: 192.0.2.1--[timestamp]
--logFormat "%h%^%^[%t]"     # Correct (no spaces)
```

### Brackets

Include brackets if present in log:

```bash
# Timestamp with brackets: [09/Oct/2025:10:15:23 +0000]
--logFormat "[%t]"   # Correct

# Timestamp without brackets: 09/Oct/2025:10:15:23
--logFormat "%t"     # Correct
```

## Testing Log Formats

### Verify Format

Test your format string on sample log lines:

```bash
# Create test log
echo '192.0.2.1 - - [09/Oct/2025:10:15:23 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl"' > test.log

# Test parsing
./cidrx static --logfile test.log \
  --logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"" \
  --clusterArgSets 1,32,32,0.01 \
  --plain
```

If parsing works, you'll see:
- Total Requests: 1
- Parse Rate: (some value)
- No parsing errors

### Debug Parsing

If parsing fails:

1. Check quotes match
2. Verify field positions
3. Count fields (use `%^` for extras)
4. Test with minimal format first
5. Add fields incrementally

## Configuration Examples

### TOML Configuration

```toml
[static]
logFile = "/var/log/nginx/access.log"
logFormat = "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""
```

### Command Line

```bash
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\"" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain
```

## Common Scenarios

### Scenario 1: Nginx Behind CloudFlare

CloudFlare adds `$http_cf_connecting_ip` with real IP:

```nginx
log_format cloudflare '$remote_addr $http_cf_connecting_ip - [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent"';
```

Format (using CF IP as primary):

```bash
--logFormat "%^ %h %^ [%t] \"%r\" %s %b %^ \"%u\""
```

### Scenario 2: Apache Behind AWS ALB

ALB logs X-Forwarded-For in access logs:

```apache
LogFormat "%h %{X-Forwarded-For}i %l %u %t \"%r\" %>s %b" alb
```

Format:

```bash
--logFormat "%^ %h %^ %^ [%t] \"%r\" %s %b"
```

### Scenario 3: Custom Application Logs

Application logs in custom format:

```
2025-10-09T10:15:23Z|192.0.2.1|GET|/api/users|200|{"user_agent":"curl"}
```

Format:

```bash
--logFormat "%^|%h|%m|%U|%s|%^"
```

### Scenario 4: Syslog Format

Logs via syslog with prefix:

```
Oct  9 10:15:23 webserver nginx: 192.0.2.1 - - [09/Oct/2025:10:15:23] "GET /" 200
```

Format:

```bash
--logFormat "%^ %^ %^ %^ %^ %h %^ %^ [%t] \"%r\" %s"
```

## Performance Considerations

### Format Complexity

Simpler formats parse faster:

```bash
# Faster (minimal parsing)
--logFormat "%h"

# Slower (full parsing)
--logFormat "%h %^ %^ [%t] \"%r\" %s %b %^ \"%u\""
```

**Impact**: Usually negligible (<5%) unless processing 10M+ requests.

### Field Extraction

Only extract fields you need:

```bash
# If not using timestamp filtering, skip it
--logFormat "%h %^ %^ %^ \"%r\" %s %b %^ \"%u\""

# If not using User-Agent filtering, skip it
--logFormat "%h %^ %^ [%t] \"%r\" %s %b"
```

## Troubleshooting

### Parsing Errors

**Error: No IP addresses found**

```
Error: Parsed 0 requests from log file
```

Fix: Verify `%h` position matches IP field

**Error: Malformed timestamp**

```
Warning: Failed to parse timestamp: [invalid]
```

Fix: Check timestamp format matches `[%t]` specification

**Error: Unexpected field**

```
Error: Format string doesn't match log structure
```

Fix: Add `%^` for extra fields

### Validation

Test format on first few lines:

```bash
# Extract first line
head -1 /var/log/nginx/access.log

# Manually verify format matches
```

Example:
```
192.0.2.1 - - [09/Oct/2025:10:15:23 +0000] "GET / HTTP/1.1" 200 1234 "-" "curl"
%h        %^ %^ [%t                      ] "%r             " %s  %b   %^  "%u"
```

## Best Practices

1. **Test first**: Verify format on sample logs
2. **Minimal format**: Only parse fields you need
3. **Document**: Comment why specific format was chosen
4. **Version control**: Store formats with configurations
5. **Consistent**: Use same format across environments
6. **Validate**: Check parsing metrics after deployment

## Future Enhancements

Planned features:

- **IPv6 support**: Parse IPv6 addresses
- **Native JSON**: Parse JSON logs directly
- **Custom patterns**: Define custom field parsers
- **Auto-detection**: Automatically detect common formats

## Next Steps

- Set up [Filtering]({{< relref "/docs/configuration/filtering/" >}}) with parsed fields
- Configure [Cluster Detection]({{< relref "/docs/configuration/clustering/" >}})
- Review [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) examples
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) deployment
