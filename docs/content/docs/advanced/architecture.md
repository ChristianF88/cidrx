---
title: "Architecture"
description: "cidrx internal architecture and design"
summary: "Deep dive into how cidrx works: trie-based clustering, detection algorithms, and data flow"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-10-09T10:00:00+00:00
draft: false
weight: 420
toc: true
seo:
  title: "cidrx Architecture"
  description: "Learn about cidrx's internal architecture including trie-based IP clustering and detection algorithms"
  canonical: ""
  noindex: false
---

Understanding cidrx's architecture helps you optimize configurations, debug issues, and contribute to development.

## High-Level Overview

cidrx is built around a multi-stage pipeline:

```
Log Files → Parser → Filter → Trie → Cluster Detector → Jail → Ban File
```

### Core Components

1. **Log Parser**: Extracts IP, timestamp, User-Agent, etc.
2. **Filter Engine**: Whitelist, blacklist, regex, time windows
3. **Trie Builder**: Constructs binary prefix tree of IPs
4. **Cluster Detector**: Identifies malicious CIDR ranges
5. **Jail Manager**: Maintains persistent threat state
6. **Ban File Writer**: Outputs blockable CIDR list

## Operating Modes

### Static Mode Architecture

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
│  Cluster    │ ← Detect threats
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

### Live Mode Architecture

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

### Request Structure

Each log entry is parsed into a Request object:

```go
type Request struct {
    IP          string      // IPv4 address
    Timestamp   time.Time   // Request time
    Method      string      // HTTP method (GET, POST, etc.)
    URI         string      // Request path
    Status      int         // HTTP status code
    Bytes       int         // Response size
    UserAgent   string      // User-Agent string
}
```

**Memory**: ~50-100 bytes per request (depends on string lengths)

### Binary Trie

IP addresses are stored in a binary prefix tree:

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

**Structure**:
```go
type TrieNode struct {
    Left    *TrieNode   // 0 bit
    Right   *TrieNode   // 1 bit
    Count   int         // Requests at this node
    IsLeaf  bool        // Terminal node
}
```

**Properties**:
- **O(32) insertion**: Fixed depth for IPv4 (32 bits)
- **O(32) lookup**: Fixed depth traversal
- **Memory efficient**: Shared prefixes
- **Natural CIDR aggregation**: Parent nodes represent CIDR ranges

### Cluster Detection Algorithm

The detector performs depth-first traversal:

```
For each trie node at depths [minDepth, maxDepth]:
    Calculate percentage = node.Count / totalRequests
    If (node.Count >= minSize AND percentage >= threshold):
        Mark as malicious cluster
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
        // Too deep, stop
        return []Cluster{}
    }

    percentage := float64(node.Count) / float64(totalRequests)

    if node.Count >= params.MinSize && percentage >= params.Threshold {
        // Found malicious cluster
        cluster := Cluster{
            CIDR:  nodeToCI DR(node, depth),
            Count: node.Count,
            Percentage: percentage,
        }
        return []Cluster{cluster}  // Don't recurse into children
    }

    // Not malicious, check children
    return detectClusters(node.Left, depth+1, params) +
           detectClusters(node.Right, depth+1, params)
}
```

**Complexity**:
- **Time**: O(N) where N = unique IPs (worst case)
- **Space**: O(D) where D = max depth (recursion stack)
- **Typical**: <1ms for 500k unique IPs

### Jail Structure

The jail maintains persistent threat state:

```go
type JailEntry struct {
    CIDR      string      // e.g., "45.40.50.192/26"
    Count     int         // Total requests
    FirstSeen time.Time   // First detection
    LastSeen  time.Time   // Most recent detection
    Strategy  string      // Which strategy detected it
}

type Jail map[string]JailEntry  // Key: CIDR string
```

**File format** (JSON):

```json
{
  "45.40.50.192/26": {
    "cidr": "45.40.50.192/26",
    "count": 3083,
    "first_seen": "2025-10-09T08:15:23Z",
    "last_seen": "2025-10-09T10:22:15Z",
    "detection_strategy": "realtime_protection"
  }
}
```

**Behavior**:
- **Append-only**: Once jailed, always jailed
- **Cumulative counts**: Counts increase over time
- **Timestamp tracking**: First and last seen updated
- **Multi-strategy**: Multiple strategies can jail same CIDR

## Data Flow

### Static Mode Flow

```
1. Read log file
   ↓
2. For each line:
   a. Parse to Request
   b. Apply time filter (if configured)
   c. Apply IP whitelist (if configured)
   d. Apply IP blacklist (if configured)
   e. Apply User-Agent filters (if configured)
   f. Apply endpoint filter (if configured)
   g. If passed all filters, add to request list
   ↓
3. Build trie from filtered requests
   ↓
4. For each cluster strategy:
   a. Traverse trie
   b. Detect clusters
   c. Add to results
   ↓
5. Merge all detected clusters
   ↓
6. Update jail file
   ↓
7. Write ban file
   ↓
8. Output results (JSON/Plain/TUI)
```

### Live Mode Flow

```
1. Start Lumberjack server on port
   ↓
2. Initialize sliding windows
   ↓
3. For each incoming log entry:
   a. Parse to Request
   b. Add to all windows
   ↓
4. For each window (on timer):
   a. Expire old requests
   b. Apply filters
   c. Build trie
   d. Detect clusters
   e. Update jail
   ↓
5. On jail update:
   a. Write ban file
   b. Log detection event
   ↓
6. Repeat from step 3
```

## Optimization Techniques

### Memory Pools

cidrx uses object pools to reduce allocations:

```go
var requestPool = sync.Pool{
    New: func() interface{} {
        return &Request{}
    },
}

// Get from pool
req := requestPool.Get().(*Request)

// Use request
// ...

// Return to pool
requestPool.Put(req)
```

**Benefits**:
- Reduced GC pressure
- ~10% faster parsing
- Stable memory usage

### Regex Caching

Compiled regex patterns are cached:

```go
var regexCache = make(map[string]*regexp.Regexp)

func getCompiledRegex(pattern string) *regexp.Regexp {
    if cached, ok := regexCache[pattern]; ok {
        return cached
    }

    compiled := regexp.MustCompile(pattern)
    regexCache[pattern] = compiled
    return compiled
}
```

**Benefits**:
- 5x faster User-Agent filtering
- Same pattern used across scenarios compiled once

### Adaptive Filtering

Filtering switches between sequential and concurrent:

```go
func filterRequests(requests []Request, filter Filter) []Request {
    if len(requests) < 10000 {
        // Sequential for small datasets
        return filterSequential(requests, filter)
    } else {
        // Concurrent for large datasets
        return filterConcurrent(requests, filter)
    }
}
```

**Benefits**:
- Small datasets: No goroutine overhead
- Large datasets: Parallel processing
- Automatic optimization

### Buffered I/O

File reading uses large buffers:

```go
file, _ := os.Open(logFile)
reader := bufio.NewReaderSize(file, 256*1024)  // 256KB buffer

for {
    line, _ := reader.ReadString('\n')
    // Process line
}
```

**Benefits**:
- Reduced syscalls
- Faster I/O on large files
- ~10% faster parsing

## Multi-Strategy Architecture

### Independent Processing

Each cluster strategy runs independently:

```go
for _, strategy := range config.ClusterStrategies {
    // Build trie (shared or per-strategy)
    trie := buildTrie(filteredRequests, strategy)

    // Detect clusters with this strategy
    clusters := detectClusters(trie, strategy.Params)

    // Add to results
    if strategy.UseForJail {
        updateJail(clusters)
    }

    results.Strategies = append(results.Strategies, clusters)
}
```

**Benefits**:
- Different thresholds catch different attack types
- Results combined for comprehensive detection
- Each strategy independently configurable

### Jail Aggregation

Multiple strategies contribute to single jail:

```
Strategy 1: Detects 45.40.50.192/26
Strategy 2: Detects 45.40.50.192/26 (same range)
Strategy 3: Detects 45.40.50.192/27 (subset)

Jail result:
- 45.40.50.192/26 (from Strategy 1 or 2)
- 45.40.50.192/27 (from Strategy 3, more specific)
```

**Deduplication**:
- Same CIDR from multiple strategies = single entry
- Counts aggregated
- Most recent timestamp updated

## Sliding Window Implementation

### Window Management

```go
type SlidingWindow struct {
    Requests     []Request
    MaxTime      time.Duration
    MaxSize      int
    LastCleanup  time.Time
}

func (w *SlidingWindow) Add(req Request) {
    w.Requests = append(w.Requests, req)

    // Check if cleanup needed
    if time.Since(w.LastCleanup) > cleanupInterval {
        w.Cleanup()
    }
}

func (w *SlidingWindow) Cleanup() {
    cutoffTime := time.Now().Add(-w.MaxTime)

    // Remove old requests
    newRequests := []Request{}
    for _, req := range w.Requests {
        if req.Timestamp.After(cutoffTime) {
            newRequests = append(newRequests, req)
        }
    }

    // Limit size
    if len(newRequests) > w.MaxSize {
        newRequests = newRequests[len(newRequests)-w.MaxSize:]
    }

    w.Requests = newRequests
    w.LastCleanup = time.Now()
}
```

**Characteristics**:
- Time-bounded: Old requests expire
- Size-bounded: Prevents unbounded growth
- Lazy cleanup: Only on timer, not per-request

## Lumberjack Protocol

### Protocol Overview

cidrx implements the Lumberjack protocol (Beats protocol) for receiving logs:

```
Client (Filebeat) → [Lumberjack Protocol] → cidrx Server
```

**Protocol features**:
- Compressed transport (zlib/gzip)
- Acknowledgments
- Windowing for flow control
- Reliable delivery

### Server Implementation

```go
func startLumberjackServer(port string, windows []*SlidingWindow) {
    listener, _ := net.Listen("tcp", ":"+port)

    for {
        conn, _ := listener.Accept()
        go handleConnection(conn, windows)
    }
}

func handleConnection(conn net.Conn, windows []*SlidingWindow) {
    decoder := lumberjack.NewDecoder(conn)

    for {
        events, _ := decoder.Decode()

        for _, event := range events {
            req := parseEvent(event)

            // Add to all windows
            for _, window := range windows {
                window.Add(req)
            }
        }
    }
}
```

## Code Organization

### Package Structure

```
cidrx/src/
├── main.go              # Entry point, CLI
├── parser/              # Log parsing
│   ├── parser.go        # Main parser
│   └── formats.go       # Format specifiers
├── filter/              # Filtering engine
│   ├── filter.go        # Filter interface
│   ├── ip_filter.go     # IP whitelist/blacklist
│   ├── ua_filter.go     # User-Agent filters
│   └── time_filter.go   # Time window filter
├── trie/                # Trie implementation
│   ├── trie.go          # Trie structure
│   └── cluster.go       # Cluster detection
├── jail/                # Jail management
│   ├── jail.go          # Jail struct
│   └── persistence.go   # JSON serialization
├── live/                # Live mode
│   ├── server.go        # Lumberjack server
│   └── window.go        # Sliding window
└── output/              # Output formatting
    ├── json.go          # JSON output
    ├── plain.go         # Plain text output
    └── tui.go           # TUI output
```

## Future Architecture Improvements

### Planned Enhancements

1. **IPv6 Support**
   - 128-bit trie instead of 32-bit
   - Dual-stack processing

2. **Distributed Mode**
   - Multiple cidrx nodes
   - Shared jail state (Redis/etcd)
   - Load balancing

3. **HTTP API**
   - RESTful API for live mode
   - WebSocket for real-time updates
   - Dashboard integration

4. **Streaming Parser**
   - Process logs without full load
   - Reduced memory footprint
   - Faster startup

5. **Plugin System**
   - Custom filters
   - Custom output formats
   - External threat feeds

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Parse line | O(N) | N = line length |
| Filter check | O(1) | Whitelist/blacklist |
| Regex match | O(M) | M = pattern complexity |
| Trie insert | O(32) | Fixed IPv4 depth |
| Trie lookup | O(32) | Fixed IPv4 depth |
| Cluster detect | O(U) | U = unique IPs |

### Space Complexity

| Component | Complexity | Notes |
|-----------|------------|-------|
| Request storage | O(R) | R = total requests |
| Trie nodes | O(U) | U = unique IPs |
| Jail entries | O(C) | C = detected clusters |

## Best Practices for Developers

1. **Profile before optimizing**: Use Go's profiler
2. **Benchmark changes**: Ensure performance doesn't regress
3. **Minimize allocations**: Use object pools
4. **Avoid locks**: Prefer lock-free data structures
5. **Test at scale**: Verify with large datasets
6. **Document algorithms**: Explain complex logic
7. **Follow Go idioms**: Use standard Go patterns

## Contributing to Architecture

### Running Tests

```bash
cd cidrx/src

# Unit tests
go test ./...

# Benchmarks
go test -bench=. ./...

# Coverage
go test -cover ./...

# Race detector
go test -race ./...
```

### Adding Features

1. **Design first**: Document approach
2. **Add tests**: Unit and integration tests
3. **Benchmark**: Ensure no performance regression
4. **Update docs**: Document new features
5. **Submit PR**: With description and tests

## Next Steps

- Review [Performance]({{< relref "/docs/advanced/performance/" >}}) optimizations
- Explore [Configuration]({{< relref "/docs/configuration/config-files/" >}}) options
- Contribute on [GitHub](https://github.com/ChristianF88/cidrx)
