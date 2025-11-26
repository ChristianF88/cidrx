---
title: "Performance"
description: "Performance benchmarks and optimization guide for cidrx"
summary: "Complete guide to cidrx performance characteristics, benchmarking, and optimization techniques"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 410
toc: true
seo:
  title: "cidrx Performance Guide"
  description: "Learn about cidrx performance benchmarks and how to optimize for maximum throughput"
  canonical: ""
  noindex: false
---

cidrx is designed for high performance, capable of processing millions of log entries per second on commodity hardware.

## Performance Benchmarks

### Current Performance (v1.0)

Based on 1M+ request dataset:

| Metric | Value | Notes |
|--------|-------|-------|
| Parse Rate | ~1.3M requests/sec | File I/O optimized |
| End-to-end | ~1M requests/sec | Including clustering |
| Memory Usage | ~512MB | With memory pools |
| Cluster Time | <1ms | Multiple strategies |

### Real-World Example

From the README example (1,046,826 requests):

```
⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Time:      762 ms
Parse Rate:      1,373,322 requests/sec
```

With clustering:

```
🔍 CLUSTERING RESULTS (3 sets)
...............................................................................
  Set 1: Execution Time: 95 μs
  Set 2: Execution Time: 4 μs
  Set 3: Execution Time: 3 μs
```

Total clustering overhead: **102 μs** for 3 strategies

## Performance Breakdown

### Stage 1: File I/O and Parsing

**Bottleneck**: Disk I/O and log parsing

**Time**: ~60% of total execution

**Optimizations applied**:
- Buffered file reading
- Optimized string parsing
- Minimal allocations

### Stage 2: Filtering

**Bottleneck**: Regex matching, IP lookups

**Time**: ~20% of total execution

**Optimizations applied**:
- Compiled regex caching (5x speedup)
- Adaptive concurrent/sequential filtering
- IP range tree for fast whitelist/blacklist lookups

**Typical performance**:
- Whitelist/blacklist: <1μs per request
- Regex matching: 1-10μs per request
- Time window: <1μs per request

### Stage 3: Trie Building

**Bottleneck**: Memory allocation, tree construction

**Time**: ~15% of total execution

**Optimizations applied**:
- Memory pools for reduced allocation overhead
- Efficient trie node structure
- Batch insertions

**Typical performance**:
- ~2-3M insertions/sec
- ~50 bytes per unique IP
- O(1) lookup complexity

### Stage 4: Cluster Detection

**Bottleneck**: Tree traversal, threshold calculations

**Time**: ~5% of total execution

**Optimizations applied**:
- Efficient depth-first traversal
- Early termination
- Minimal allocations

**Typical performance**:
- <1ms for most datasets
- Scales linearly with unique IPs
- Multiple strategies add minimal overhead

## Optimization Techniques

### 1. Whitelist Optimization

**Impact**: 10-30% faster overall

Exclude legitimate traffic early:

```toml
[global]
whitelist = "/etc/cidrx/whitelist.txt"
```

**Best practices**:
- Include CDN IPs (CloudFlare, Cloudfront, etc.)
- Include office/internal networks
- Include monitoring services
- Keep whitelist under 1000 entries for best performance

**Benchmark**:
```bash
# Without whitelist
time ./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain

# With whitelist
time ./cidrx static --logfile access.log \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 --plain
```

### 2. Regex Optimization

**Impact**: 5x faster User-Agent filtering

Keep regex patterns simple:

```toml
# Slower - complex pattern
useragentRegex = "(?i)(scanner|nikto|sqlmap|acunetix|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

# Faster - simple patterns
useragentRegex = ".*scanner.*|.*nikto.*|.*sqlmap.*"
```

**Best practices**:
- Avoid complex lookaheads/lookbehinds
- Use simple `.*pattern.*` format
- Combine with `|` instead of multiple regex calls
- Use User-Agent blacklist file instead of regex when possible

### 3. Cluster Parameter Tuning

**Impact**: 10-20% faster clustering

Reduce number of strategies:

```toml
# Slower - many strategies
clusterArgSets = [
  [100,30,32,0.05],
  [500,28,32,0.1],
  [1000,24,32,0.1],
  [5000,20,28,0.2],
  [10000,16,24,0.3]
]

# Faster - focused strategies
clusterArgSets = [
  [1000,24,32,0.1],
  [5000,20,28,0.2]
]
```

**Best practices**:
- Start with 2-3 strategies
- Add more only if needed
- Higher minSize = faster detection
- Narrower depth ranges = faster traversal

### 4. Memory Pool Optimization

**Impact**: Already applied (10% improvement)

cidrx uses memory pools internally. No configuration needed.

**Technical details**:
- Pre-allocated request objects
- Reduced GC pressure
- ~10% faster parsing

### 5. Concurrent vs Sequential Filtering

**Impact**: Automatic optimization

cidrx automatically chooses:

- **Sequential**: For small datasets (<10k requests)
- **Concurrent**: For large datasets (>10k requests)

**Technical details**:
- Goroutines for parallel filtering
- Adaptive work stealing
- Minimal synchronization overhead

## Benchmarking

### Running Benchmarks

```bash
cd cidrx/src

# Run all benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkIsAllowed -benchtime=1ms ./...

# With memory stats
go test -bench=. -benchmem ./...
```

### Real-World Benchmarking

```bash
# Benchmark your actual log file
time ./cidrx static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain

# Multiple runs for average
for i in {1..5}; do
  time ./cidrx static --logfile access.log \
    --clusterArgSets 1000,24,32,0.1 \
    --plain > /dev/null
done
```

### Benchmark Different Configurations

```bash
#!/bin/bash
# benchmark-configs.sh

LOGFILE="access.log"

echo "=== No filters ==="
time ./cidrx static --logfile $LOGFILE \
  --clusterArgSets 1000,24,32,0.1 --plain > /dev/null

echo "=== With whitelist ==="
time ./cidrx static --logfile $LOGFILE \
  --whitelist /etc/cidrx/whitelist.txt \
  --clusterArgSets 1000,24,32,0.1 --plain > /dev/null

echo "=== With regex ==="
time ./cidrx static --logfile $LOGFILE \
  --useragentRegex ".*bot.*" \
  --clusterArgSets 1000,24,32,0.1 --plain > /dev/null

echo "=== Multiple strategies ==="
time ./cidrx static --logfile $LOGFILE \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 5000,20,28,0.2 \
  --clusterArgSets 10000,16,24,0.3 \
  --plain > /dev/null
```

## Memory Management

### Memory Usage

Typical memory usage for 1M requests:

| Component | Memory | Notes |
|-----------|--------|-------|
| Request storage | 50-100 MB | ~50-100 bytes per request |
| Trie structure | 25-50 MB | ~50 bytes per unique IP |
| Cluster results | <1 MB | Minimal overhead |
| **Total** | **75-150 MB** | Scales linearly with requests |

### Memory Optimization

**For large log files** (>10M requests):

1. **Use live mode** with sliding windows instead of static mode
2. **Split files** and analyze separately
3. **Increase minSize** to reduce unique IPs tracked
4. **Use whitelist** to exclude traffic early

**Live mode memory management**:

```toml
[live.optimized]
slidingWindowMaxTime = "1h"      # Shorter window
slidingWindowMaxSize = 50000     # Smaller size
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1]]
useForJail = [true]
```

This limits memory to ~50MB per window.

### Monitoring Memory

```bash
# Monitor memory during execution
/usr/bin/time -v ./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain

# Key metrics:
# - Maximum resident set size
# - Page faults
```

## Scaling Strategies

### Horizontal Scaling

For very large deployments, run multiple cidrx instances:

```bash
# Split by time
./cidrx static --logfile access.log \
  --startTime "2025-10-09T00:00:00Z" \
  --endTime "2025-10-09T06:00:00Z" &

./cidrx static --logfile access.log \
  --startTime "2025-10-09T06:00:00Z" \
  --endTime "2025-10-09T12:00:00Z" &

# Merge results
wait
```

### Vertical Scaling

cidrx benefits from:

- **Fast CPU**: Faster parsing and clustering
- **Fast storage**: SSD for faster file I/O
- **More RAM**: Larger datasets in memory

**Diminishing returns**:
- >4 cores: Minimal benefit (most operations single-threaded)
- >16GB RAM: Only needed for 100M+ request datasets

### Live Mode Scaling

For high-throughput live mode:

```toml
# Multiple windows, staggered execution
[live.window1]
slidingWindowMaxTime = "2h"
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1]]

[live.window2]
slidingWindowMaxTime = "1h"
sleepBetweenIterations = 5  # Different interval
clusterArgSets = [[500,28,32,0.1]]
```

## Real-World Performance Testing

### Test Setup

From the CLAUDE.local.md instructions:

```bash
# Real-world performance test
time go run . static \
  --config ../../cidrx.toml \
  --plain
```

**With whitelists/blacklists**:

```bash
time go run . static \
  --config ../../cidrx-testing.toml \
  --plain
```

### Performance Goals

Based on project requirements:

- **Parse rate**: >2M requests/sec
- **Total time**: <1 second for 1M requests
- **Memory**: <512MB for typical workloads

**Verification**:

```bash
# Should complete in <1 second
time ./cidrx static --logfile 1m-requests.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain

# Check memory
/usr/bin/time -v ./cidrx static --logfile 1m-requests.log \
  --clusterArgSets 1000,24,32,0.1 \
  --plain | grep "Maximum resident"
```

## Performance Tips by Use Case

### Emergency Response

**Goal**: Fastest possible detection

```bash
# Minimal processing
./cidrx static --logfile access.log \
  --clusterArgSets 10000,20,28,0.3 \
  --plain
```

**Optimizations**:
- High minSize (fast clustering)
- Single strategy (minimal overhead)
- Wide CIDR range (fewer clusters)
- High threshold (less processing)

### Comprehensive Audit

**Goal**: Thorough analysis, speed less critical

```toml
[static.comprehensive]
clusterArgSets = [
  [100,28,32,0.05],
  [1000,24,28,0.1],
  [5000,20,24,0.2],
  [10000,16,20,0.3]
]
whitelist = "/etc/cidrx/whitelist.txt"
```

**Trade-offs**:
- More strategies (slower but comprehensive)
- Lower thresholds (more detections)
- Still optimized with whitelist

### Real-Time Protection

**Goal**: Continuous operation, balanced performance

```toml
[live.balanced]
slidingWindowMaxTime = "2h"
slidingWindowMaxSize = 100000
sleepBetweenIterations = 10
clusterArgSets = [[1000,24,32,0.1]]
whitelist = "/etc/cidrx/whitelist.txt"
```

**Optimizations**:
- Moderate window size
- Whitelist for early exclusion
- Single strategy per window
- 10-second iterations (balanced)

## Performance Monitoring

### Metrics to Track

1. **Parse rate** - Requests/sec during parsing
2. **Total duration** - End-to-end execution time
3. **Memory usage** - Peak memory consumption
4. **Cluster time** - Time spent in detection
5. **Result count** - Number of detections

### Logging Performance

cidrx logs performance metrics:

```
⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Time:      762 ms
Parse Rate:      1,373,322 requests/sec
```

Extract and monitor:

```bash
# Parse rate over time
./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain | \
  grep "Parse Rate" | \
  awk '{print $3}' >> parse-rates.log
```

### Performance Regression Testing

Track performance over time:

```bash
#!/bin/bash
# performance-test.sh

LOGFILE="test-1m.log"
RESULTS="performance-results.csv"

echo "date,parse_time,total_time,parse_rate" >> $RESULTS

OUTPUT=$(./ cidrx static --logfile $LOGFILE \
  --clusterArgSets 1000,24,32,0.1 --plain)

PARSE_TIME=$(echo "$OUTPUT" | grep "Parse Time" | awk '{print $3}')
PARSE_RATE=$(echo "$OUTPUT" | grep "Parse Rate" | awk '{print $3}')
DURATION=$(echo "$OUTPUT" | grep "Duration" | awk '{print $2}')

echo "$(date +%Y-%m-%d),$PARSE_TIME,$DURATION,$PARSE_RATE" >> $RESULTS
```

## Future Optimizations

Planned performance improvements:

1. **Parallel log parsing**: Multi-threaded file reading
2. **Streaming mode**: Process logs without loading entirely
3. **Native JSON parsing**: Faster JSON log processing
4. **mmap file reading**: Faster I/O for large files
5. **SIMD optimizations**: Vectorized string parsing

## Best Practices

1. **Benchmark your workload**: Test with your actual logs
2. **Profile before optimizing**: Identify actual bottlenecks
3. **Use whitelist**: Biggest single optimization
4. **Keep regex simple**: Complex patterns slow down parsing
5. **Start minimal**: Add complexity only when needed
6. **Monitor memory**: Ensure you don't exceed available RAM
7. **Test at scale**: Verify performance with largest expected files

## Troubleshooting Performance

### Slow Parsing

**Symptoms**: Parse rate <500k requests/sec

**Possible causes**:
1. Slow disk I/O (use SSD)
2. Complex regex patterns (simplify)
3. Large whitelist (optimize)

**Debug**:
```bash
# Check disk I/O
time cat access.log > /dev/null

# Test without filters
time ./cidrx static --logfile access.log \
  --clusterArgSets 10000,24,32,0.5 --plain
```

### High Memory Usage

**Symptoms**: Memory usage >2GB for 1M requests

**Possible causes**:
1. Memory leak (report bug)
2. Too many unique IPs
3. Large sliding windows (live mode)

**Debug**:
```bash
# Monitor memory
/usr/bin/time -v ./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain
```

### Slow Clustering

**Symptoms**: Cluster time >100ms

**Possible causes**:
1. Too many cluster strategies
2. Very wide depth ranges
3. Too many unique IPs

**Debug**:
```bash
# Reduce strategies
--clusterArgSets 1000,24,32,0.1  # Only one

# Narrow depth range
--clusterArgSets 1000,24,28,0.1  # Instead of 16-32
```

## Next Steps

- Understand the [Architecture]({{< relref "/docs/advanced/architecture/" >}}) behind these optimizations
- Review [Configuration]({{< relref "/docs/configuration/config-files/" >}}) for tuning options
- Test [Static Mode]({{< relref "/docs/usage/static-mode/" >}}) performance
- Deploy [Live Mode]({{< relref "/docs/usage/live-mode/" >}}) at scale
