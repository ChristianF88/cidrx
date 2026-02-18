---
title: "Performance"
description: "Performance benchmarks and optimization guide for cidrx"
summary: "Benchmarks, memory management, scaling approaches, and optimization techniques"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 420
toc: true
seo:
  title: "cidrx Performance Guide"
  description: "Learn about cidrx performance benchmarks and how to optimize for maximum throughput"
  canonical: ""
  noindex: false
---

cidrx processes millions of log entries per second on commodity hardware.

## Benchmarks

Based on 1M+ request dataset:

| Metric | Value | Notes |
|--------|-------|-------|
| Parse Rate | ~1.3M requests/sec | File I/O optimized |
| End-to-end | ~1M requests/sec | Including clustering |
| Memory Usage | ~512MB | With memory pools |
| Cluster Time | <1ms | Multiple cluster sets |

### Real-World Example

From the reference dataset (1,046,826 requests):

```
⚡ PARSING PERFORMANCE
────────────────────────────────────────────────────────────────────────────────
Total Requests:  1,046,826
Parse Time:      762 ms
Parse Rate:      1,373,322 requests/sec

🔍 CLUSTERING RESULTS (3 sets)
...............................................................................
  Set 1: Execution Time: 95 μs
  Set 2: Execution Time: 4 μs
  Set 3: Execution Time: 3 μs
```

Total clustering overhead: **102 μs** for 3 cluster sets.

## Performance Breakdown

### Stage 1: File I/O and Parsing (~60% of total)

**Bottleneck**: Disk I/O and log parsing

Optimizations applied: buffered file reading (256KB buffers), optimized string parsing, minimal allocations.

### Stage 2: Filtering (~20% of total)

**Bottleneck**: Regex matching, IP lookups

Optimizations applied: compiled regex caching (5x speedup), adaptive concurrent/sequential filtering, IP range tree for fast whitelist/blacklist lookups.

Typical per-request cost:
- Whitelist/blacklist: <1μs
- Regex matching: 1-10μs
- Time window: <1μs

### Stage 3: Trie Building (~15% of total)

**Bottleneck**: Memory allocation, tree construction

Optimizations applied: memory pools, efficient trie node structure, batch insertions.

Typical: ~2-3M insertions/sec, ~50 bytes per unique IP.

### Stage 4: Cluster Detection (~5% of total)

**Bottleneck**: Tree traversal, threshold calculations

Optimizations applied: efficient depth-first traversal, early termination, minimal allocations.

Typical: <1ms for most datasets, scales linearly with unique IPs.

## Optimization Tips

### Whitelists (10-30% faster overall)

Exclude legitimate traffic early to reduce trie size and clustering work. Keep whitelists under 1000 entries for best performance. See [Filtering]({{< relref "/docs/reference/filtering/" >}}).

### Regex Patterns (up to 5x difference)

Keep patterns simple:

```
# Slower - complex pattern
(?i)(crawler|spider|fetcher|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})

# Faster - simple patterns
.*crawler.*|.*spider.*|.*fetcher.*
```

Avoid complex lookaheads/lookbehinds. Use User-Agent blacklist files instead of regex when possible.

### Cluster Arg Sets (10-20% faster clustering)

Fewer sets = faster. Start with 2-3 cluster arg sets. Higher `minSize` and narrower depth ranges both reduce traversal time. See [Clustering]({{< relref "/docs/reference/clustering/" >}}).

## Memory Management

### Typical Memory Usage (1M requests)

| Component | Memory | Notes |
|-----------|--------|-------|
| Request storage | 50-100 MB | ~50-100 bytes per request |
| Trie structure | 25-50 MB | ~50 bytes per unique IP |
| Cluster results | <1 MB | Minimal overhead |
| **Total** | **75-150 MB** | Scales linearly |

### Reducing Memory

For large log files (>10M requests):

1. Use live mode with sliding windows instead of static mode
2. Split files and analyze time ranges separately
3. Increase `minSize` to reduce tracked IPs
4. Use whitelists to exclude traffic early

Live mode memory is bounded by `slidingWindowMaxSize` (~50MB per window at 50,000 requests).

### Monitoring Memory

```bash
/usr/bin/time -v ./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain
# Look for: Maximum resident set size
```

## Benchmarking

### Go Benchmarks

```bash
cd cidrx/src

go test -bench=. ./...              # Run all benchmarks
go test -bench=. -benchmem ./...    # With memory stats
go test -bench=BenchmarkIsAllowed -benchtime=1ms ./...  # Specific benchmark
```

### Real-World Benchmarking

```bash
# Single run
time ./cidrx static --logfile access.log \
  --clusterArgSets 1000,24,32,0.1 --plain

# Multiple runs for average
for i in {1..5}; do
  time ./cidrx static --logfile access.log \
    --clusterArgSets 1000,24,32,0.1 --plain > /dev/null
done
```

## Scaling

### Horizontal Scaling

For very large datasets, split by time range:

```bash
./cidrx static --logfile access.log \
  --startTime "2025-10-09" --endTime "2025-10-09 06" &

./cidrx static --logfile access.log \
  --startTime "2025-10-09 06" --endTime "2025-10-09 12" &

wait  # Merge results
```

### Vertical Scaling

cidrx benefits from:

- **Fast CPU**: Faster parsing and clustering
- **Fast storage**: SSD for faster file I/O
- **More RAM**: Larger datasets in memory

Diminishing returns: >4 cores provides minimal benefit (most operations single-threaded), >16GB RAM only needed for 100M+ request datasets.

### Live Mode Scaling

Use multiple windows with staggered intervals for different detection speeds. See [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for window configuration.

## Troubleshooting

### Slow Parsing (<500k requests/sec)

Possible causes: slow disk I/O, complex regex patterns, large whitelist.

Debug by testing without filters first:

```bash
time ./cidrx static --logfile access.log \
  --clusterArgSets 10000,24,32,0.5 --plain
```

### High Memory (>2GB for 1M requests)

Possible causes: too many unique IPs, large sliding windows in live mode.

### Slow Clustering (>100ms)

Possible causes: too many cluster arg sets, very wide depth ranges, too many unique IPs. Reduce to a single set with narrow depth range to isolate.

## Performance Goals

Based on project requirements:

| Goal | Target |
|------|--------|
| Parse rate | >1.3M requests/sec |
| Total time | <1 second for 1M requests |
| Memory | <512MB for typical workloads |
| Cluster detection | <5ms |
