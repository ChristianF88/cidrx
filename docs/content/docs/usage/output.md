---
title: "Output Formats"
description: "Understanding cidrx output formats and how to use them"
summary: "Complete guide to JSON, compact JSON, plain text, and TUI output modes"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 240
slug: "output"
toc: true
seo:
  title: "cidrx Output Formats"
  description: "Learn about cidrx output formats including JSON, plain text, and interactive TUI for different use cases"
  canonical: ""
  noindex: false
---

cidrx supports multiple output formats to fit different workflows, from programmatic processing to human analysis.

## Output Format Overview

| Format | Flag | Use Case | Best For |
|--------|------|----------|----------|
| JSON | (default) | Programmatic processing | APIs, automation, parsing |
| Compact JSON | `--compact` | SIEM integration | Log aggregation, single-line |
| Plain Text | `--plain` | Human readability | Terminal output, reports |
| TUI | `--tui` | Interactive analysis | Visual exploration, demos |

## JSON Output (Default)

### Basic Usage

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1
```

### Example Output

```json
{
  "metadata": {
    "log_file": "/var/log/nginx/access.log",
    "analysis_type": "static",
    "generated_at": "2025-10-09T10:15:23Z",
    "duration_ms": 540
  },
  "parsing": {
    "total_requests": 1046826,
    "parse_time_ms": 437,
    "parse_rate": 2394927,
    "log_format": "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
  },
  "trie": {
    "name": "cli_trie",
    "requests_after_filtering": 1046826,
    "unique_ips": 1046826,
    "build_time_ms": 316,
    "active_filters": []
  },
  "cidr_ranges": [
    {
      "cidr": "14.160.0.0/12",
      "count": 58195,
      "percentage": 5.56
    },
    {
      "cidr": "198.51.0.0/16",
      "count": 1308,
      "percentage": 0.12
    }
  ],
  "clustering": [
    {
      "set_number": 1,
      "parameters": {
        "min_size": 1000,
        "min_depth": 24,
        "max_depth": 32,
        "threshold": 0.1
      },
      "execution_time_us": 95,
      "detected_ranges": [
        {
          "cidr": "20.171.207.2/32",
          "count": 1574,
          "percentage": 0.15
        },
        {
          "cidr": "45.40.50.192/26",
          "count": 3083,
          "percentage": 0.29
        },
        {
          "cidr": "198.51.205.91/32",
          "count": 1308,
          "percentage": 0.12
        }
      ],
      "total_count": 5965,
      "total_percentage": 0.57
    }
  ]
}
```

### JSON Schema

**Metadata Section:**
```json
{
  "metadata": {
    "log_file": "string",
    "analysis_type": "static|live",
    "generated_at": "RFC3339 timestamp",
    "duration_ms": "number"
  }
}
```

**Parsing Section:**
```json
{
  "parsing": {
    "total_requests": "number",
    "parse_time_ms": "number",
    "parse_rate": "number (requests/sec)",
    "log_format": "string"
  }
}
```

**Clustering Section:**
```json
{
  "clustering": [
    {
      "set_number": "number",
      "parameters": {
        "min_size": "number",
        "min_depth": "number",
        "max_depth": "number",
        "threshold": "number"
      },
      "execution_time_us": "number",
      "detected_ranges": [
        {
          "cidr": "string",
          "count": "number",
          "percentage": "number"
        }
      ],
      "total_count": "number",
      "total_percentage": "number"
    }
  ]
}
```

### Using JSON Output

**Parse with jq:**

```bash
# Extract all detected CIDRs
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr'

# Get CIDRs with > 1000 requests
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[] | select(.count > 1000) | .cidr'

# Total malicious requests
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq '.clustering[].total_count'
```

**Python processing:**

```python
import json
import subprocess

# Run cidrx and capture output
result = subprocess.run(
    ['./cidrx', 'static', '--logfile', 'access.log',
     '--clusterArgSets', '1000,24,32,0.1'],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)

# Extract threat ranges
for cluster_set in data['clustering']:
    for detected in cluster_set['detected_ranges']:
        print(f"Block: {detected['cidr']} ({detected['count']} requests)")
```

## Compact JSON Output

### Basic Usage

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact
```

### Example Output

Single line JSON, minified:

```json
{"metadata":{"log_file":"/var/log/nginx/access.log","analysis_type":"static","generated_at":"2025-10-09T10:15:23Z","duration_ms":540},"parsing":{"total_requests":1046826,"parse_time_ms":437,"parse_rate":2394927},"clustering":[{"set_number":1,"parameters":{"min_size":1000,"min_depth":24,"max_depth":32,"threshold":0.1},"detected_ranges":[{"cidr":"45.40.50.192/26","count":3083,"percentage":0.29}]}]}
```

### Use Cases

**SIEM Integration:**

```bash
# Send to Elasticsearch
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact | \
  curl -X POST "localhost:9200/cidrx-detections/_doc" \
       -H 'Content-Type: application/json' \
       -d @-

# Send to Splunk HEC
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact | \
  curl -X POST "https://splunk:8088/services/collector" \
       -H "Authorization: Splunk <token>" \
       -d @-
```

**Log Aggregation:**

```bash
# Append to log file
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --compact >> \
  /var/log/cidrx/detections.log
```

**Streaming:**

```bash
# Process with stream processors
./cidrx live --config config.toml --compact | \
  kafka-console-producer --topic cidrx-detections
```

## Plain Text Output

### Basic Usage

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain
```

### Example Output

```
═══════════════════════════════════════════════════════════════════════════════
                               cidrx Analysis Results
═══════════════════════════════════════════════════════════════════════════════

📊 ANALYSIS OVERVIEW
────────────────────────────────────────────────────────────────────────────────
Log File:        /var/log/nginx/access.log
Analysis Type:   static
Generated:       2025-10-09 10:15:23 UTC
Duration:        540 ms

⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Time:      437 ms
Parse Rate:      2,394,927 requests/sec
Log Format:      %^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"

🎯 TRIE: cli_trie
────────────────────────────────────────────────────────────────────────────────
Requests After Filtering: 1,046,826
Unique IPs:              1,046,826
Trie Build Time:         316 ms
Active Filters:          None

📍 CIDR RANGE ANALYSIS
...............................................................................
  14.160.0.0/12             58,195 requests  (  5.56%)
  198.51.0.0/16              1,308 requests  (  0.12%)

🔍 CLUSTERING RESULTS (1 set)
...............................................................................
  Set 1: min_size=1000, depth=24-32, threshold=0.10
  Execution Time: 95 μs
  Detected Threat Ranges:
    20.171.207.2/32            1,574 requests  (  0.15%)
    45.40.50.192/26            3,083 requests  (  0.29%)
    198.51.205.91/32           1,308 requests  (  0.12%)
    ───────────────────        5,965 requests  (  0.57%) [TOTAL]

═══════════════════════════════════════════════════════════════════════════════
```

### Features

- **Box Drawing**: Unicode box characters for visual hierarchy
- **Number Formatting**: Thousands separators for readability
- **Emoji Icons**: Quick visual identification of sections
- **Aligned Columns**: Easy to scan tabular data
- **Summary Stats**: Total counts and percentages

### Use Cases

**Terminal Display:**

```bash
# Direct terminal output
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain

# Page through results
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | less
```

**Reports:**

```bash
# Generate daily report
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --startTime "2025-10-09T00:00:00Z" \
  --endTime "2025-10-09T23:59:59Z" \
  --clusterArgSets 1000,24,32,0.1 \
  --plain > daily-report-$(date +%Y%m%d).txt
```

**Email Alerts:**

```bash
# Email report
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | \
  mail -s "cidrx Daily Report" admin@example.com
```

## Interactive TUI

### Basic Usage

```bash
./cidrx static --config cidrx.toml --tui
```

**Note**: TUI mode requires a configuration file (doesn't work with command-line only parameters).

### Features

**Visual Elements:**
- **Heatmaps**: Visual representation of IP distribution
- **Interactive Tables**: Navigate detected ranges
- **Real-time Updates**: In live mode, updates continuously
- **Color Coding**: Severity-based coloring

**Navigation:**
- Arrow keys: Navigate tables
- Tab: Switch between panels
- Enter: Drill down into details
- Q: Quit

### Screenshots

The TUI provides:

1. **Overview Panel**: Summary statistics
2. **Detection Panel**: List of detected CIDR ranges
3. **Detail Panel**: In-depth information on selected range
4. **Timeline Panel**: Temporal distribution of requests

### Use Cases

**Interactive Analysis:**

```bash
# Explore detection results interactively
./cidrx static --config cidrx.toml --tui
```

**Live Monitoring:**

```bash
# Real-time visual monitoring
./cidrx live --config config.toml --tui
```

**Demonstrations:**

TUI mode is excellent for:
- Security team presentations
- Training sessions
- Customer demonstrations
- Executive briefings

## Choosing the Right Format

### Decision Matrix

**Use JSON when:**
- Integrating with other tools
- Building automation
- Need programmatic access
- Archiving for later analysis

**Use Compact JSON when:**
- Sending to SIEM/log aggregators
- Streaming to message queues
- Space-constrained storage
- Single-line requirement

**Use Plain Text when:**
- Reading in terminal
- Generating reports
- Email alerts
- Human consumption

**Use TUI when:**
- Interactive exploration
- Real-time monitoring
- Demonstrations
- Visual analysis

## Output Redirection

### Saving Output

**JSON to file:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 > results.json
```

**Plain text to file:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain > report.txt
```

**Both stdout and file:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 --plain | tee report.txt
```

### Filtering Output

**Extract only CIDRs:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr' > blocklist.txt
```

**Format for iptables:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr' | \
  sed 's/^/iptables -A INPUT -s /' | \
  sed 's/$/ -j DROP/' > iptables-rules.sh
```

**Format for nginx:**

```bash
./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 | \
  jq -r '.clustering[].detected_ranges[].cidr' | \
  sed 's/^/deny /' | \
  sed 's/$/;/' > nginx-deny.conf
```

## Error Handling

### JSON Error Format

On error, JSON output includes error information:

```json
{
  "error": true,
  "message": "Failed to open log file: /var/log/nginx/access.log",
  "code": "FILE_NOT_FOUND"
}
```

### Plain Text Error Format

```
═══════════════════════════════════════════════════════════════════════════════
                                    ERROR
═══════════════════════════════════════════════════════════════════════════════

❌ Failed to open log file: /var/log/nginx/access.log

Possible causes:
  - File does not exist
  - Insufficient permissions
  - Path is incorrect

═══════════════════════════════════════════════════════════════════════════════
```

### Checking for Errors

**Shell script:**

```bash
#!/bin/bash

if ./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1 > output.json 2>&1; then
    echo "Analysis successful"
    # Process output.json
else
    echo "Analysis failed"
    cat output.json
    exit 1
fi
```

**With jq:**

```bash
OUTPUT=$(./cidrx static --logfile access.log --clusterArgSets 1000,24,32,0.1)

if echo "$OUTPUT" | jq -e '.error' > /dev/null 2>&1; then
    echo "Error occurred:"
    echo "$OUTPUT" | jq -r '.message'
    exit 1
else
    echo "Success!"
    echo "$OUTPUT" | jq '.clustering[].detected_ranges[].cidr'
fi
```

## Performance Considerations

### Output Format Impact

| Format | Speed | Size | CPU | Memory |
|--------|-------|------|-----|--------|
| JSON | Fast | Large | Low | Low |
| Compact JSON | Fast | Medium | Low | Low |
| Plain Text | Medium | Large | Medium | Low |
| TUI | Slow | N/A | High | Medium |

**Recommendations:**
- Use `--compact` for automated pipelines
- Use `--plain` for manual analysis
- Avoid TUI for very large datasets
- Use JSON for archival

## Best Practices

1. **Choose wisely**: Select format based on use case
2. **Parse safely**: Handle JSON parsing errors
3. **Version outputs**: Archive analysis results
4. **Automate**: Use JSON for scripting
5. **Monitor**: Use TUI for live monitoring
6. **Report**: Use plain text for human reports
7. **Stream**: Use compact JSON for SIEM integration

## Examples

### Complete Workflow Example

```bash
#!/bin/bash
# analyze-and-block.sh

# Run analysis
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  > analysis.json

# Check for errors
if jq -e '.error' analysis.json > /dev/null 2>&1; then
    echo "Analysis failed:"
    jq -r '.message' analysis.json
    exit 1
fi

# Extract CIDRs
jq -r '.clustering[].detected_ranges[].cidr' analysis.json > blocklist.txt

# Apply to firewall
while read cidr; do
    iptables -I INPUT -s "$cidr" -j DROP
    echo "Blocked: $cidr"
done < blocklist.txt

# Generate human report
./cidrx static \
  --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain > report.txt

# Email report
mail -s "Botnet Analysis Report" admin@example.com < report.txt

echo "Analysis complete. Blocked $(wc -l < blocklist.txt) CIDR ranges."
```

## Next Steps

- Learn about [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) for detailed analysis
- Explore [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) for real-time output
- Configure [Filtering]({{< relref "/docs/configuration/filtering/" >}}) to refine results
- Review [Performance Tips]({{< relref "/docs/advanced/performance/" >}}) for optimization
