---
title: "Developer Guide"
description: "Developer guide for contributing to cidrx"
summary: "Performance requirements, testing, and development workflow for cidrx contributors"
date: 2025-10-09T10:00:00+00:00
lastmod: 2025-11-26T10:00:00+00:00
draft: false
weight: 500
toc: true
seo:
  title: "Contributing to cidrx"
  description: "Developer guide for contributing to the cidrx botnet detection tool"
  canonical: ""
  noindex: false
---

cidrx is open source and welcomes contributions. This guide covers cidrx-specific development requirements.

## Quick Start

### 1. Prerequisites

- **Go 1.21+** (check: `go version`)
- **staticcheck** (install: `go install honnef.co/go/tools/cmd/staticcheck@latest`)

### 2. Clone and Build

```bash
git clone https://github.com/YOUR_USERNAME/cidrx.git
cd cidrx/cidrx/src
go mod download
go build -o cidrx .
```

### 3. Verify Setup

```bash
# Run tests
go test ./...

# Run linter
staticcheck ./...

# Test binary
./cidrx --version
```

## Performance Requirements

**cidrx is performance-critical.** All changes must maintain or improve these benchmarks:

- **Parse Rate**: ≥1.3M requests/sec
- **End-to-end Processing**: ≥1M requests/sec
- **Cluster Detection**: <5ms for typical workloads
- **Memory**: No unbounded growth

## Development Workflow

### Making Changes

```bash
cd cidrx/src

# 1. Make your changes

# 2. Run tests
go test ./...

# 3. Run benchmarks (REQUIRED for performance-sensitive code)
go test -bench=. -benchmem ./...

# 4. Run static analysis
staticcheck ./...

# 5. Format code
go fmt ./...
```

### Running Benchmarks

**Critical**: Always benchmark before and after performance-related changes.

```bash
# Before making changes
go test -bench=. -benchmem ./... > bench-before.txt

# Make your changes

# After changes
go test -bench=. -benchmem ./... > bench-after.txt

# Compare results
diff bench-before.txt bench-after.txt
```

Example output:
```
BenchmarkParseLogLine-8    1373322    762 ns/op    256 B/op    8 allocs/op
BenchmarkTrieInsert-8      5000000    112 ns/op     64 B/op    2 allocs/op
```

### Real-World Performance Test

Test with the reference dataset:

```bash
cd cidrx/src
time go run . static --logfile /var/log/nginx/access.log \
  --clusterArgSets 1000,24,32,0.1 \
  --clusterArgSets 10000,16,24,0.2 \
  --plain
```

**Expected performance** (1M+ requests):
- Parse Time: ~750ms
- Parse Rate: 1.3M+ requests/sec
- Total Duration: ~1s

## Testing

### Run All Tests

```bash
go test ./...
```

### Run with Coverage

```bash
go test -cover ./...
```

### Run Specific Package

```bash
go test ./logparser -v
```

### Test with Race Detector

```bash
go test -race ./...
```

## Code Quality

### Required Checks

Run before every commit:

```bash
# Format
go fmt ./...

# Vet
go vet ./...

# Static analysis (REQUIRED)
staticcheck ./...

# Tests
go test ./...
```

### All Checks in One Command

```bash
go fmt ./... && go vet ./... && staticcheck ./... && go test ./...
```

## Writing Tests

### Test Conventions

- Place tests in `*_test.go` files
- Use table-driven tests
- Test edge cases and error conditions
- Include benchmarks for performance-critical code

### Example Test

```go
func TestParseIPAddress(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"valid IPv4", "192.168.1.1", "192.168.1.1", false},
        {"invalid IP", "not-an-ip", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := ParseIPAddress(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("expected error=%v, got error=%v", tt.wantErr, err)
            }
            if result != tt.expected {
                t.Errorf("expected %s, got %s", tt.expected, result)
            }
        })
    }
}
```

### Example Benchmark

```go
func BenchmarkParseIPAddress(b *testing.B) {
    input := "192.168.1.1"
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseIPAddress(input)
    }
}
```

## Pull Request Checklist

Before submitting a PR:

- [ ] Tests pass: `go test ./...`
- [ ] Benchmarks run (for performance changes)
- [ ] No performance regression
- [ ] Static analysis passes: `staticcheck ./...`
- [ ] Code formatted: `go fmt ./...`
- [ ] Real-world test passes (if applicable)
- [ ] Documentation updated (if needed)

## Repository Structure

```
cidrx/
├── cidrx/src/          # Main Go application
│   ├── cli/            # CLI commands
│   ├── ingestor/       # Static/live mode ingestion
│   ├── logparser/      # Log parsing
│   ├── models/         # Data structures
│   ├── trie/           # IP trie clustering
│   ├── version/        # Version info
│   └── main.go
├── docs/               # Hugo documentation
├── .github/workflows/  # CI/CD
├── .goreleaser.yaml    # Release configuration
└── README.md
```

## Profiling

### CPU Profiling

```bash
go test -cpuprofile=cpu.prof -bench=. ./logparser
go tool pprof cpu.prof
```

In pprof:
```
(pprof) top10
(pprof) list FunctionName
```

### Memory Profiling

```bash
go test -memprofile=mem.prof -bench=. ./logparser
go tool pprof mem.prof
```

## Debugging

### Race Detector

```bash
go build -race -o cidrx .
./cidrx static --logfile test.log --clusterArgSets 1000,24,32,0.1
```

### Delve Debugger

```bash
# Install
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug a test
dlv test ./logparser -- -test.run TestParseLogLine
```

## Cleanup

Remove build artifacts:

```bash
cd cidrx/src
rm -f cidrx cidrx
rm -f *.prof *.out
go clean -cache
```

## Contributing Guidelines

1. **One feature per PR** - Keep changes focused
2. **Maintain performance** - Benchmark everything
3. **Add tests** - All new code needs tests
4. **Document changes** - Update docs when needed
5. **Follow Go conventions** - Use `go fmt` and `staticcheck`

## Common Issues

### Import errors

```bash
go mod tidy
go mod download
```

### Stale test cache

```bash
go test -count=1 ./...
```

### staticcheck not found

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
# Ensure $(go env GOPATH)/bin is in PATH
```

## Resources

- [GitHub Repository](https://github.com/ChristianF88/cidrx)
- [Issue Tracker](https://github.com/ChristianF88/cidrx/issues)
- [Discussions](https://github.com/ChristianF88/cidrx/discussions)

## Next Steps

- Review [Architecture]({{< relref "/docs/advanced/architecture/" >}}) to understand internals
- Check [Documentation Guide]({{< relref "/docs/contributing/documentation/" >}}) for docs changes
- See [Performance]({{< relref "/docs/advanced/performance/" >}}) for optimization tips
