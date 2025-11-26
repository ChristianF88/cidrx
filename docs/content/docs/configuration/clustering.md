---
title: "Cluster Detection"
description: "Configuring cluster detection parameters for optimal threat detection"
summary: "Complete guide to tuning cluster detection algorithms and parameters in cidrx"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 340
slug: "clustering"
toc: true
seo:
  title: "cidrx Cluster Detection Configuration"
  description: "Learn how to configure and tune cidrx cluster detection parameters for optimal botnet detection"
  canonical: ""
  noindex: false
---

Cluster detection is the core algorithm in cidrx that identifies groups of malicious IPs and aggregates them into CIDR ranges for efficient blocking.

## Overview

cidrx uses a trie-based clustering algorithm to detect IP ranges with abnormally high request volumes. The algorithm can be tuned with four key parameters.

## Cluster Parameters

### Parameter Format

Cluster arguments are specified as arrays of four values:

```toml
clusterArgSets = [[minSize, minDepth, maxDepth, threshold]]
```

Or command line:

```bash
--clusterArgSets minSize,minDepth,maxDepth,threshold
```

### The Four Parameters

| Parameter | Type | Description | Example Values |
|-----------|------|-------------|----------------|
| `minSize` | integer | Minimum requests to flag a cluster | 100, 1000, 10000 |
| `minDepth` | integer | Smallest CIDR prefix to consider | 16, 20, 24 |
| `maxDepth` | integer | Largest CIDR prefix to consider | 28, 30, 32 |
| `threshold` | float | Percentage of total requests (0.0-1.0) | 0.05, 0.1, 0.3 |

## Parameter Details

### minSize - Minimum Cluster Size

**What it does**: Minimum number of requests required for a cluster to be flagged

**Values**:
- Small: 50-500 requests
- Medium: 500-5,000 requests
- Large: 5,000+ requests

**Examples**:

```bash
# Catch small attacks early
--clusterArgSets 100,30,32,0.05

# Balanced detection
--clusterArgSets 1000,24,32,0.1

# Only major attacks
--clusterArgSets 10000,16,24,0.3
```

**Tuning guide**:

| Traffic Volume | Recommended minSize | Reasoning |
|----------------|---------------------|-----------|
| < 10k req/day | 50-100 | Catch small attacks |
| 10k-100k req/day | 500-1000 | Balance signal/noise |
| 100k-1M req/day | 1000-5000 | Focus on significant attacks |
| > 1M req/day | 5000+ | Only major threats |

### minDepth - Minimum CIDR Depth

**What it does**: Smallest CIDR prefix (widest range) to consider

**Values**: Typically 12-24

**CIDR Size Reference**:

| Prefix | IP Count | Use Case |
|--------|----------|----------|
| /12 | 1,048,576 | Entire ISPs, major botnets |
| /16 | 65,536 | Large organizations, ASNs |
| /20 | 4,096 | Medium networks |
| /24 | 256 | Small networks, typical subnets |
| /28 | 16 | Small clusters |

**Examples**:

```bash
# Wide ranges (catch large botnets)
--clusterArgSets 10000,12,24,0.3

# Medium ranges (balanced)
--clusterArgSets 1000,20,28,0.1

# Narrow ranges (focused attacks)
--clusterArgSets 100,28,32,0.05
```

**Tuning guide**:

| Attack Type | Recommended minDepth | Reasoning |
|-------------|----------------------|-----------|
| Large botnets | 12-16 | Catch network-wide patterns |
| Distributed attacks | 20-24 | Balance coverage |
| Focused attacks | 28-30 | Target specific subnets |
| Single-host | 32 | Individual IPs only |

### maxDepth - Maximum CIDR Depth

**What it does**: Largest CIDR prefix (narrowest range) to consider

**Values**: Typically 24-32

**Common ranges**:

| Prefix | IP Count | Use Case |
|--------|----------|----------|
| /24 | 256 | Standard subnet |
| /28 | 16 | Small cluster |
| /30 | 4 | Tiny cluster |
| /32 | 1 | Single IP |

**Examples**:

```bash
# Only large clusters
--clusterArgSets 10000,16,24,0.3

# Include medium clusters
--clusterArgSets 1000,24,28,0.1

# Include individual IPs
--clusterArgSets 100,28,32,0.05
```

**Tuning guide**:

| Goal | Recommended maxDepth | Reasoning |
|------|----------------------|-----------|
| Block networks only | 24 | Avoid blocking individual IPs |
| Include small clusters | 28-30 | Catch coordinated groups |
| Include single IPs | 32 | Maximum granularity |

### threshold - Percentage Threshold

**What it does**: Minimum percentage of total requests for cluster to be flagged

**Values**: 0.0-1.0 (0%-100%)

**Common values**:
- Aggressive: 0.01-0.05 (1%-5%)
- Balanced: 0.1-0.2 (10%-20%)
- Conservative: 0.3+ (30%+)

**Examples**:

```bash
# Aggressive (catch small percentage)
--clusterArgSets 100,28,32,0.01

# Balanced
--clusterArgSets 1000,24,32,0.1

# Conservative (major attacks only)
--clusterArgSets 10000,16,24,0.3
```

**Tuning guide**:

| Total Requests | Recommended Threshold | Reasoning |
|----------------|----------------------|-----------|
| < 10,000 | 0.05-0.1 (5%-10%) | Avoid single-IP false positives |
| 10,000-100,000 | 0.1-0.2 (10%-20%) | Balance detection |
| 100,000-1M | 0.1-0.3 (10%-30%) | Focus on significant patterns |
| > 1M | 0.2-0.5 (20%-50%) | Only major attacks |

## Multiple Detection Strategies

### Why Multiple Strategies?

Different attack patterns require different detection parameters. Use multiple cluster sets to catch:

1. **Large botnets** - Wide ranges, high thresholds
2. **Distributed attacks** - Medium ranges, medium thresholds
3. **Focused attacks** - Narrow ranges, low thresholds

### Example: Three-Tier Detection

```toml
[static.comprehensive]
clusterArgSets = [
  [10000, 16, 24, 0.3],  # Tier 1: Large botnets
  [1000, 24, 28, 0.1],   # Tier 2: Distributed attacks
  [100, 30, 32, 0.05]    # Tier 3: Focused attacks
]
useForJail = [true, true, true]
```

This configuration:
- **Tier 1**: Catches massive botnets (10k+ requests, /16-/24 ranges, 30%+ of traffic)
- **Tier 2**: Catches distributed attacks (1k+ requests, /24-/28 ranges, 10%+ of traffic)
- **Tier 3**: Catches focused attacks (100+ requests, /30-/32 ranges, 5%+ of traffic)

### Attack-Specific Strategies

```toml
# Scanner detection
[static.scanners]
useragentRegex = ".*scanner.*|.*nikto.*"
clusterArgSets = [[50, 30, 32, 0.01]]  # Very sensitive
useForJail = [true]

# API abuse
[static.api_abuse]
endpointRegex = "/api/.*"
clusterArgSets = [[500, 28, 32, 0.05]]  # Moderately sensitive
useForJail = [true]

# General botnet
[static.botnet]
clusterArgSets = [[5000, 20, 28, 0.2]]  # Less sensitive
useForJail = [true]
```

## Tuning for Different Scenarios

### Scenario 1: Emergency Botnet Response

**Goal**: Quickly identify and block active attacks

```bash
./cidrx static --logfile access.log \
  --clusterArgSets 500,28,32,0.1 \
  --clusterArgSets 2000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain
```

**Parameters**:
- Low minSize (500-10000) to catch attacks early
- Multiple ranges to catch different patterns
- Moderate thresholds for quick detection

### Scenario 2: Security Audit

**Goal**: Comprehensive analysis of historical data

```toml
[static.audit]
clusterArgSets = [
  [100, 28, 32, 0.05],   # Small attacks
  [1000, 24, 28, 0.1],   # Medium attacks
  [5000, 20, 24, 0.2],   # Large attacks
  [10000, 16, 20, 0.3]   # Major botnets
]
useForJail = [false, false, false, false]
```

**Parameters**:
- Four tiers for comprehensive coverage
- Wide range of thresholds
- useForJail = false for analysis only (no blocking)

### Scenario 3: API Protection

**Goal**: Detect API abuse patterns

```toml
[static.api_protection]
endpointRegex = "/api/.*"
clusterArgSets = [
  [100, 30, 32, 0.05],   # Focused attacks
  [500, 28, 30, 0.1]     # Distributed attacks
]
useForJail = [true, true]
```

**Parameters**:
- Narrow ranges (/28-/32) for API attacks
- Low thresholds (5%-10%) to catch abuse early
- Endpoint filtering for precision

### Scenario 4: Scanner Detection

**Goal**: Identify and block security scanners

```toml
[static.scanners]
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
clusterArgSets = [[50, 30, 32, 0.01]]
useForJail = [true]
```

**Parameters**:
- Very low minSize (50) - scanners make few requests
- Narrow range (/30-/32) - usually single IPs
- Very low threshold (1%) - aggressive detection

### Scenario 5: Brute Force Detection

**Goal**: Catch login brute force attempts

```toml
[static.brute_force]
endpointRegex = "/login|/wp-login\\.php|/admin"
clusterArgSets = [[100, 28, 32, 0.05]]
useForJail = [true]
```

**Parameters**:
- Low minSize (100) - brute force can be slow
- Narrow range (/28-/32) - usually small clusters
- Low threshold (5%) - catch early

## Performance Considerations

### Execution Time

Cluster detection time depends on:

1. **Number of unique IPs**: More IPs = slower
2. **Number of cluster sets**: More sets = slower (linear)
3. **CIDR depth range**: Wider range = slightly slower

**Example timing** (1M requests, 500k unique IPs):

| Cluster Sets | Execution Time |
|--------------|----------------|
| 1 set | ~100 μs |
| 3 sets | ~300 μs |
| 5 sets | ~500 μs |

Clustering is very fast - typically <1ms even with multiple sets.

### Memory Usage

Memory usage is dominated by:

1. **Request storage**: ~50-100 bytes per request
2. **Trie structure**: ~50 bytes per unique IP
3. **Cluster results**: Negligible

**Example** (1M requests):
- Request data: ~50-100 MB
- Trie: ~25-50 MB
- Total: ~75-150 MB

### Optimization Tips

1. **Use fewer cluster sets** if performance is critical
2. **Increase minSize** to reduce processing overhead
3. **Narrow depth ranges** (e.g., 24-28 instead of 16-32)
4. **Filter before clustering** (use whitelist, regex, etc.)

## Real-World Examples

### Example 1: Production Web Server

**Traffic**: 1M requests/day, ~50k unique IPs/day

```toml
[static.production]
clusterArgSets = [
  [1000, 24, 32, 0.1],   # Main detection
  [5000, 20, 28, 0.2]    # Large attacks
]
useForJail = [true, true]
```

### Example 2: API Service

**Traffic**: 500k requests/day, heavy API usage

```toml
[static.api_general]
clusterArgSets = [[2000, 24, 28, 0.15]]
useForJail = [true]

[static.api_specific]
endpointRegex = "/api/v1/(login|register)"
clusterArgSets = [[100, 30, 32, 0.05]]
useForJail = [true]
```

### Example 3: E-commerce Site

**Traffic**: 2M requests/day, frequent attacks

```toml
[static.ecommerce]
clusterArgSets = [
  [500, 28, 32, 0.05],    # Quick detection
  [2000, 24, 28, 0.1],    # Medium attacks
  [10000, 16, 24, 0.3]    # Major attacks
]
useForJail = [true, true, true]

[static.checkout_protection]
endpointRegex = "/checkout|/cart"
clusterArgSets = [[200, 28, 32, 0.05]]
useForJail = [true]
```

### Example 4: WordPress Site

**Traffic**: 200k requests/day, frequent scanner attempts

```toml
[static.wordpress_general]
clusterArgSets = [[1000, 24, 32, 0.1]]
useForJail = [true]

[static.wordpress_admin]
endpointRegex = "/wp-admin/.*|/wp-login\\.php"
clusterArgSets = [[50, 30, 32, 0.01]]
useForJail = [true]

[static.wordpress_scanners]
endpointRegex = "/wp-content/.*\\.php|/wp-includes/.*\\.php"
clusterArgSets = [[50, 30, 32, 0.01]]
useForJail = [true]
```

## Validation and Testing

### Test Your Configuration

Use a known attack log to test parameters:

```bash
# Test with different parameters
./cidrx static --logfile known-attack.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain > results-1.txt

./cidrx static --logfile known-attack.log \
  --clusterArgSets 500,24,32,0.05 \
  --plain > results-2.txt

# Compare results
diff results-1.txt results-2.txt
```

### Measure False Positives

Check if legitimate traffic is flagged:

```bash
# Analyze normal traffic day
./cidrx static --logfile normal-day.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain

# Review detected ranges
# Verify none are legitimate (CDN, office IPs, etc.)
```

### Measure False Negatives

Check if attacks are missed:

```bash
# Analyze known attack with different thresholds
for threshold in 0.05 0.1 0.2 0.3; do
  echo "Testing threshold: $threshold"
  ./cidrx static --logfile attack.log \
    --clusterArgSets 1000,24,32,$threshold \
    --plain | grep "Detected Threat Ranges"
done
```

## Interpreting Results

### Understanding Output

```
Set 1: min_size=1000, depth=24-32, threshold=0.10
Execution Time: 95 μs
Detected Threat Ranges:
  45.40.50.192/26            3,083 requests  (  0.29%)
  198.51.205.91/32           1,308 requests  (  0.12%)
  ───────────────────        4,391 requests  (  0.42%) [TOTAL]
```

**Analysis**:
- Two ranges detected
- First is /26 (64 IPs) with 3,083 requests
- Second is /32 (single IP) with 1,308 requests
- Combined, they're 0.42% of total traffic

### Evaluating Effectiveness

Good detection should:
1. **Catch attacks**: Known malicious ranges are detected
2. **Avoid false positives**: Legitimate traffic not flagged
3. **Efficient blocking**: Ranges are appropriately sized (not too wide, not too narrow)

## Best Practices

1. **Start conservative**: Use high thresholds initially
2. **Layer strategies**: Use multiple cluster sets for different attack types
3. **Test thoroughly**: Validate on known attacks and normal traffic
4. **Monitor results**: Review detected ranges regularly
5. **Adjust gradually**: Change one parameter at a time
6. **Document decisions**: Comment why specific values were chosen
7. **Season to taste**: Tune based on your specific traffic patterns
8. **Review periodically**: Adjust as attack patterns evolve

## Common Mistakes

### Mistake 1: Threshold Too Low

```toml
# BAD: Will flag everything
clusterArgSets = [[10, 32, 32, 0.001]]
```

**Result**: Massive false positives

**Fix**: Increase threshold to 5-10%

### Mistake 2: minSize Too Small

```toml
# BAD: For high-traffic sites
clusterArgSets = [[10, 24, 32, 0.1]]
```

**Result**: Single-IP noise flagged as threats

**Fix**: Scale minSize with traffic volume

### Mistake 3: Depth Range Too Wide

```toml
# BAD: Inefficient
clusterArgSets = [[1000, 8, 32, 0.1]]
```

**Result**: Slow execution, poor clustering

**Fix**: Use focused depth ranges (e.g., 20-28)

### Mistake 4: Only One Strategy

```toml
# BAD: Misses different attack types
clusterArgSets = [[1000, 24, 32, 0.1]]
```

**Result**: Only catches one type of attack

**Fix**: Use multiple strategies

## Troubleshooting

### No Detections

**Problem**: No clusters detected despite visible attacks

**Solutions**:
1. Lower minSize
2. Lower threshold
3. Widen depth range
4. Check filters aren't too restrictive

### Too Many Detections

**Problem**: Legitimate traffic flagged

**Solutions**:
1. Increase minSize
2. Increase threshold
3. Add whitelist
4. Narrow depth range

### Wrong CIDR Sizes

**Problem**: Detected ranges too wide or too narrow

**Solutions**:
1. Adjust minDepth/maxDepth range
2. Use multiple strategies with different ranges
3. Review attack patterns manually

## Next Steps

- Review [Filtering]({{< relref "/docs/configuration/filtering/" >}}) to refine detection
- Explore [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) for analysis
- Deploy [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) for protection
- Optimize [Performance]({{< relref "/docs/advanced/performance/" >}})
