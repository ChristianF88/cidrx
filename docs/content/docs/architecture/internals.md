---
title: "Internals"
description: "cidrx internal architecture and design"
summary: "Deep dive into how cidrx works: pipeline, binary trie, cluster detection, jail system, and code organization"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 410
toc: true
seo:
  title: "cidrx Internals"
  description: "Learn about cidrx's internal architecture including trie-based IP clustering and detection algorithms"
  canonical: ""
  noindex: false
---

## Pipeline

cidrx is built around a multi-stage pipeline:

```
Log Files → Parser → Filter → Trie → Cluster Detector → Jail → Ban File
```

### Core Components

1. **Log Parser**: Extracts IP, timestamp, User-Agent, endpoint, status, and bytes from each line
2. **Filter Engine**: Whitelist, blacklist, regex, time windows
3. **Trie Builder**: Constructs binary prefix tree of IPs
4. **Cluster Detector**: Identifies high-volume CIDR ranges
5. **Jail Manager**: Maintains persistent detection state with escalating bans
6. **Ban File Writer**: Outputs blockable CIDR list

## Static Mode Architecture

```
┌─────────────┐
│  Log File   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Parser    │ ← Parse entire file
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Filter    │ ← Apply filters
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Trie     │ ← Build IP tree
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Cluster    │ ← Detect clusters
│  Detector   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Output    │ ← JSON/Plain/TUI
└─────────────┘
```

**Characteristics**:
- Entire log loaded into memory
- Single-pass processing
- Fast for files <10M requests
- Suitable for batch analysis

## Live Mode Architecture

```
┌─────────────┐
│  Filebeat   │
│  (Lumber-   │
│   jack)     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│     cidrx Live Server           │
│  ┌───────────────────────────┐  │
│  │  Sliding Window Manager   │  │
│  │                           │  │
│  │  ┌─────────────────────┐  │  │
│  │  │    Window 1         │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │  Filter    │     │  │  │
│  │  │  └─────┬──────┘     │  │  │
│  │  │        ▼            │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │   Trie     │     │  │  │
│  │  │  └─────┬──────┘     │  │  │
│  │  │        ▼            │  │  │
│  │  │  ┌────────────┐     │  │  │
│  │  │  │  Cluster   │     │  │  │
│  │  │  └────────────┘     │  │  │
│  │  └─────────────────────┘  │  │
│  │                           │  │
│  │  ┌─────────────────────┐  │  │
│  │  │    Window 2         │  │  │
│  │  │     (similar)       │  │  │
│  │  └─────────────────────┘  │  │
│  └───────────┬───────────────┘  │
│              ▼                  │
│  ┌───────────────────────────┐  │
│  │    Jail Manager           │  │
│  └───────────┬───────────────┘  │
└──────────────┬──────────────────┘
               │
               ▼
       ┌───────────────┐
       │  Ban File     │
       └───────────────┘
```

**Characteristics**:
- Continuous operation
- Multiple independent windows
- Bounded memory (sliding windows)
- Real-time detection
- Automatic jail updates

## Data Structures

### Request

Each log entry is parsed into a cache-line-optimized struct:

```go
type Request struct {
    // Hot fields -- first cache line (accessed by trie insertion, filtering, clustering)
    IPUint32  uint32     // Primary IP storage - eliminates net.IP allocation
    Status    uint16     // Smaller type for status code
    Method    HTTPMethod // 1 byte enum
    Bytes     uint32
    Timestamp time.Time  // Needed for time-range filtering

    // Cold fields -- second cache line (only accessed during output or string filtering)
    URI       string
    UserAgent string
}
```

IPs are stored as `uint32` -- no string allocation per IP, no `net.IP` overhead.

### Binary Trie

IP addresses are stored in a binary prefix tree where each bit of the IP determines the path:

```
Example IPs: 192.168.1.1, 192.168.1.2, 192.168.2.1

           Root
          /    \
        0        1
       /        / \
      ...     1    ...
            /  \
          0      ...
         / \
        0   1
       /     \
  192.168  192.168
     |        |
     1        2
     |        |
     1        1
```

```go
type TrieNode struct {
    Children [2]*TrieNode   // 0 and 1 bit children
    Count    uint32          // Requests at this node
}
```

**Properties**:
- **O(32) insertion**: Fixed depth for IPv4 (32 bits)
- **O(32) lookup**: Fixed depth traversal
- **Memory efficient**: Shared prefixes reduce node count
- **Natural CIDR aggregation**: Parent nodes represent CIDR ranges (depth = prefix length)

### Cluster Detection Algorithm

The detector performs depth-first traversal of the trie:

```
For each trie node at depths [minDepth, maxDepth]:
    Calculate percentage = node.Count / totalRequests
    If (node.Count >= minSize AND percentage >= threshold):
        Mark as cluster
        Add to results
        Skip children (don't detect sub-ranges)
```

**Pseudocode**:

```go
func detectClusters(node *TrieNode, depth int, params ClusterParams) []Cluster {
    if depth < params.MinDepth {
        // Too shallow, recurse deeper
        return detectClusters(node.Left, depth+1, params) +
               detectClusters(node.Right, depth+1, params)
    }

    if depth > params.MaxDepth {
        return []Cluster{}  // Too deep, stop
    }

    percentage := float64(node.Count) / float64(totalRequests)

    if node.Count >= params.MinSize && percentage >= params.Threshold {
        // Found cluster -- don't recurse into children
        return []Cluster{{
            CIDR:       nodeToCIDR(node, depth),
            Count:      node.Count,
            Percentage: percentage,
        }}
    }

    // Below threshold, check children
    return detectClusters(node.Left, depth+1, params) +
           detectClusters(node.Right, depth+1, params)
}
```

**Complexity**:
- **Time**: O(N) where N = unique IPs (worst case)
- **Space**: O(D) where D = max depth (recursion stack)
- **Typical**: <1ms for 500k unique IPs

For parameter tuning, see [Clustering]({{< relref "/docs/reference/clustering/" >}}).

### Multi-Trie Processing

Each [cluster arg set]({{< relref "/docs/reference/clustering/" >}}) runs against the same trie independently. Results from multiple sets are combined, and the `useForJail` flag controls which sets contribute to the jail:

- Same CIDR from multiple sets = single jail entry
- Sub-ranges merged when parent range detected
- Repeat offenders escalate through ban tiers

## Jail System

The jail uses a tiered cell system with escalating ban durations:

```go
type Prisoner struct {
    CIDR      string    // e.g., "45.40.50.192/26"
    BanStart  time.Time // When current ban started
    BanActive bool      // Whether ban is currently active
}

type Cell struct {
    ID          int
    Description string
    BanDuration time.Duration
    Prisoners   []Prisoner
}

type Jail struct {
    Cells    []Cell
    AllCIDRs []string  // All ranges currently in jail
}
```

### Default Cells (5 Escalating Tiers)

| Cell | Description | Duration |
|------|-------------|----------|
| 1 | Stage 1 Ban | 10 minutes |
| 2 | Stage 2 Ban | 4 hours |
| 3 | Stage 3 Ban | 7 days |
| 4 | Stage 4 Ban | 30 days |
| 5 | Stage 5 Ban | 180 days |

### Behavior

- **Tiered escalation**: Repeat offenders move to higher cells with longer bans
- **Ban expiry**: Bans expire after the cell's duration
- **Re-detection**: If detected again after ban expires, prisoner moves to next cell
- **Range merging**: If a parent CIDR is detected, sub-ranges are consolidated
- **Sub-range awareness**: Existing jailed ranges that are sub-ranges of a new detection are merged

### Jail File Format

The jail file (`--jailFile`) persists detection state as JSON. It is read on startup and written after each detection cycle.

## Data Flow

### Static Mode

```
1. Read log file
2. For each line:
   a. Parse to Request
   b. Apply time filter (if configured)
   c. Apply IP whitelist (if configured)
   d. Apply IP blacklist (if configured)
   e. Apply User-Agent filters (if configured)
   f. Apply endpoint filter (if configured)
   g. If passed all filters, add to request list
3. Build trie from filtered requests
4. For each cluster arg set:
   a. Traverse trie
   b. Detect clusters
   c. Add to results
5. Merge all detected clusters
6. Update jail file
7. Write ban file
8. Output results (JSON/Plain/TUI)
```

### Live Mode

```
1. Start Lumberjack server on port
2. Initialize sliding windows
3. For each incoming log entry:
   a. Parse to Request
   b. Add to all windows
4. For each window (on timer):
   a. Expire old requests
   b. Apply filters
   c. Build trie
   d. Detect clusters
   e. Update jail
5. On jail update:
   a. Write ban file
   b. Log detection event
6. Repeat from step 3
```

## Sliding Window

Live mode uses sliding windows to bound memory usage:

- **Time-bounded**: Old requests expire based on `slidingWindowMaxTime`
- **Size-bounded**: Capped at `slidingWindowMaxSize` to prevent unbounded growth
- **Lazy cleanup**: Cleanup runs on the detection timer, not per-request

Multiple windows can run concurrently with different parameters. See [Live Protection Guide]({{< relref "/docs/guides/live-protection/" >}}) for configuration.

## Lumberjack Protocol

cidrx implements the Lumberjack protocol (Beats protocol) for receiving logs from Filebeat:

```
Client (Filebeat) → [Lumberjack Protocol] → cidrx Server
```

**Protocol features**: compressed transport (zlib/gzip), acknowledgments, windowing for flow control, reliable delivery.

## Optimization Techniques

### Memory Pools

Pre-allocated object pools reduce GC pressure (~10% faster parsing, stable memory usage).

### Regex Caching

Compiled regex patterns are cached -- same pattern used across tries is compiled once (5x faster User-Agent filtering).

### Adaptive Filtering

Filtering automatically switches between sequential (<10k requests) and concurrent (>10k requests) processing.

### Buffered I/O

File reading uses 256KB buffers, reducing syscalls (~10% faster parsing on large files).

See [Performance]({{< relref "/docs/architecture/performance/" >}}) for benchmarks and tuning.

## Package Structure

```
cidrx/src/
├── main.go              # Entry point
├── analysis/            # Analysis orchestration
├── cidr/                # CIDR parsing utilities
├── cli/                 # CLI commands and API entry points
├── config/              # Configuration structs and loading
├── ingestor/            # Static/live mode ingestion, Request struct
├── iputils/             # IP address utilities
├── jail/                # Ban/jail management (tiered cells)
├── logparser/           # Log format parsing
├── output/              # Output formatting (JSON, plain text)
├── pools/               # Memory pool management, TrieNode struct
├── sliding/             # Sliding window for live mode
├── trie/                # IP trie building and cluster detection
├── tui/                 # Terminal user interface
└── version/             # Version info
```

## Complexity Summary

### Time

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Parse line | O(N) | N = line length |
| Filter check | O(1) | Whitelist/blacklist |
| Regex match | O(M) | M = pattern complexity |
| Trie insert | O(32) | Fixed IPv4 depth |
| Trie lookup | O(32) | Fixed IPv4 depth |
| Cluster detect | O(U) | U = unique IPs |

### Space

| Component | Complexity | Notes |
|-----------|------------|-------|
| Request storage | O(R) | R = total requests |
| Trie nodes | O(U) | U = unique IPs |
| Jail entries | O(C) | C = detected clusters |
