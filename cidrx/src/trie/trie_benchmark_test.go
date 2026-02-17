package trie

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ChristianF88/cidrx/iputils"
)

// ============================================================================
// INSERT BENCHMARKS (from trie_insert_benchmark_test.go)
// ============================================================================

// BenchmarkInsertPerformance tests current insert performance
func BenchmarkInsertPerformance(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		// Pre-generate IPs to avoid IP generation overhead in benchmark
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		b.Run(fmt.Sprintf("Insert_%d_IPs", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})
	}
}

// BenchmarkTrieVsSlice compares trie insertion vs slice append for same data
func BenchmarkTrieVsSlice(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		ips, _ := iputils.RandomIPsFromRange("192.168.1.0/24", size)

		b.Run(fmt.Sprintf("Trie_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("Slice_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				slice := make([]net.IP, 0, size)
				slice = append(slice, ips...)
				_ = slice // Prevent unused variable warning
			}
		})
	}
}

// BenchmarkIPConversion tests different IP conversion strategies
func BenchmarkIPConversion(b *testing.B) {
	testIPs := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		net.ParseIP("172.16.0.1"),
		net.ParseIP("8.8.8.8"),
	}

	b.Run("IPToUint32", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ip := range testIPs {
				_ = iputils.IPToUint32(ip)
			}
		}
	})

	b.Run("DirectBytes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ip := range testIPs {
				ip4 := ip.To4()
				if ip4 != nil {
					_ = uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
				}
			}
		}
	})
}

// BenchmarkInsertWithPreconvertedIPs tests performance when IPs are pre-converted
func BenchmarkInsertWithPreconvertedIPs(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		ips, _ := iputils.RandomIPsFromRange("10.0.0.0/8", size)

		// Pre-convert IPs to uint32
		uint32IPs := make([]uint32, len(ips))
		for i, ip := range ips {
			uint32IPs[i] = iputils.IPToUint32(ip)
		}

		b.Run(fmt.Sprintf("PreconvertedInsert_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips { // Still use net.IP for Insert interface
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("StandardInsert_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips {
					trie.Insert(ip)
				}
			}
		})
	}
}

// BenchmarkStandardIPConversion tests standard net.IP operations
func BenchmarkStandardIPConversion(b *testing.B) {
	testIPStrings := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
	}

	b.Run("ParseIP", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ipStr := range testIPStrings {
				_ = net.ParseIP(ipStr)
			}
		}
	})

	b.Run("ParseIP_To4", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, ipStr := range testIPStrings {
				ip := net.ParseIP(ipStr)
				_ = ip.To4()
			}
		}
	})
}

// ============================================================================
// COLLECT BENCHMARKS (from trie_collect_benchmark_test.go)
// ============================================================================

// BenchmarkCollectCIDRs benchmarks the optimized parallel implementation (now default)
func BenchmarkCollectCIDRs(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			// Create a trie with random IPs
			trie := NewTrie()
			ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
			if err != nil {
				b.Fatalf("Failed to generate IPs: %v", err)
			}

			for _, ip := range ips {
				trie.Insert(ip)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(10, 8, 24, 0.5)
			}
		})
	}
}

// BenchmarkCollectCIDRsSequential benchmarks the sequential numeric implementation
func BenchmarkCollectCIDRsSequential(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 1000000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			trie := NewTrie()
			ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
			if err != nil {
				b.Fatalf("Failed to generate IPs: %v", err)
			}

			for _, ip := range ips {
				trie.Insert(ip)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = trie.collectCIDRsSequentialNumeric(10, 8, 24, 500)
			}
		})
	}
}

// BenchmarkCollectCIDRsStringVsNumeric compares string vs numeric CIDR collection
func BenchmarkCollectCIDRsStringVsNumeric(b *testing.B) {
	sizes := []int{1000, 10000, 50000}

	for _, size := range sizes {
		// Create test trie
		trie := NewTrie()
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}
		for _, ip := range ips {
			trie.Insert(ip)
		}

		b.Run(fmt.Sprintf("String_size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(10, 8, 24, 0.5)
			}
		})

		b.Run(fmt.Sprintf("Numeric_size_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRsNumeric(10, 8, 24, 0.5)
			}
		})
	}
}

// BenchmarkParallelizationOverhead measures the overhead of parallelization
func BenchmarkParallelizationOverhead(b *testing.B) {
	trie := NewTrie()
	// Small dataset where sequential should be faster
	ips, _ := iputils.RandomIPsFromRange("192.168.1.0/24", 100)
	for _, ip := range ips {
		trie.Insert(ip)
	}

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = trie.CollectCIDRs(5, 16, 30, 0.5)
		}
	})

	b.Run("sequential", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = trie.collectCIDRsSequentialNumeric(5, 16, 30, 500)
		}
	})
}

// ============================================================================
// PARALLEL BENCHMARKS (from trie_parallel_benchmark_test.go)
// ============================================================================

// BenchmarkParallelCollectCIDRs benchmarks parallel vs sequential performance
func BenchmarkParallelCollectCIDRs(b *testing.B) {
	sizes := []int{10000, 100000, 1000000}

	for _, size := range sizes {
		// Create a large trie for testing
		trie := NewTrie()
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		for _, ip := range ips {
			trie.Insert(ip)
		}

		b.Run(fmt.Sprintf("Parallel_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(1000, 16, 24, 0.5)
			}
		})
	}
}

// BenchmarkScalability tests scalability across different CPU counts
func BenchmarkScalability(b *testing.B) {
	trie := NewTrie()
	ips, _ := iputils.RandomIPsFromRange("10.0.0.0/12", 200000)
	for _, ip := range ips {
		trie.Insert(ip)
	}

	maxProcs := runtime.NumCPU()
	procCounts := []int{1, 2, 4, 8, 16}

	for _, procs := range procCounts {
		if procs > maxProcs {
			continue
		}
		b.Run(fmt.Sprintf("procs_%d", procs), func(b *testing.B) {
			oldProcs := runtime.GOMAXPROCS(procs)
			defer runtime.GOMAXPROCS(oldProcs)

			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = trie.CollectCIDRs(10, 8, 24, 0.5)
			}
		})
	}
}

// ============================================================================
// WORKER BENCHMARKS (from trie_worker_benchmark_test.go)
// ============================================================================

// BenchmarkWorkerDistribution tests different worker configurations
func BenchmarkWorkerDistribution(b *testing.B) {
	// Create a large trie for testing
	trie := createLargeTrie(100000) // 100k IPs

	workerCounts := []int{1, 2, 4, 8, 16, runtime.NumCPU(), runtime.NumCPU() * 2}

	for _, workers := range workerCounts {
		b.Run(fmt.Sprintf("Workers_%d", workers), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = benchmarkWorkerDistribution(trie, workers)
			}
		})
	}
}

// BenchmarkParallelizationDepth tests different parallelization depths
func BenchmarkParallelizationDepth(b *testing.B) {
	trie := createLargeTrie(50000) // 50k IPs
	workers := runtime.NumCPU()

	depths := []uint32{1, 2, 3, 4, 5, 6, 8}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("Depth_%d", depth), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = benchmarkParallelizationDepth(trie, workers, depth)
			}
		})
	}
}

// BenchmarkWorkBalance measures work distribution balance
func BenchmarkWorkBalance(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("WorkBalance_%d_IPs", size), func(b *testing.B) {
			trie := createLargeTrie(size)
			workers := runtime.NumCPU()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				balance := measureWorkBalance(trie, workers)
				_ = balance
			}
		})
	}
}

// ============================================================================
// SORTED INSERTION BENCHMARKS (from sorted_insertion_benchmark_test.go)
// ============================================================================

// BenchmarkSortedInsertion compares sorted vs random insertion performance
func BenchmarkSortedInsertion(b *testing.B) {
	sizes := []int{1000, 10000, 100000}

	for _, size := range sizes {
		// Generate IPs
		ips, err := iputils.RandomIPsFromRange("10.0.0.0/8", size)
		if err != nil {
			b.Fatalf("Failed to generate IPs: %v", err)
		}

		// Create sorted version by converting to uint32, sorting, then back
		uint32IPs := make([]uint32, len(ips))
		for i, ip := range ips {
			uint32IPs[i] = iputils.IPToUint32(ip)
		}

		// Simple insertion sort for uint32 values
		for i := 1; i < len(uint32IPs); i++ {
			for j := i; j > 0 && uint32IPs[j] < uint32IPs[j-1]; j-- {
				uint32IPs[j], uint32IPs[j-1] = uint32IPs[j-1], uint32IPs[j]
			}
		}

		// Convert back to net.IP
		sortedIPs := make([]net.IP, len(uint32IPs))
		for i, ipVal := range uint32IPs {
			sortedIPs[i] = iputils.Uint32ToIP(ipVal)
		}

		b.Run(fmt.Sprintf("Random_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range ips { // Original random order
					trie.Insert(ip)
				}
			}
		})

		b.Run(fmt.Sprintf("Sorted_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				trie := NewTrie()
				for _, ip := range sortedIPs { // Sorted order
					trie.Insert(ip)
				}
			}
		})
	}
}

// ============================================================================
// HELPER FUNCTIONS (consolidated from various files)
// ============================================================================

// Non-pooled TrieNode for comparison
type TrieNodeClassic struct {
	Children [2]*TrieNodeClassic
	Count    uint32
}

type TrieClassic struct {
	Root *TrieNodeClassic
}

func NewTrieClassic() *TrieClassic {
	return &TrieClassic{Root: &TrieNodeClassic{}}
}

func (t *TrieClassic) Insert(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = &TrieNodeClassic{}
		}
		node = node.Children[bit]
		node.Count++
	}
}

func (t *TrieClassic) Count(ip net.IP) uint32 {
	node := t.Root
	val := iputils.IPToUint32(ip)
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return 0
		}
		node = node.Children[bit]
	}
	return node.Count
}

func (t *TrieClassic) Delete(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	var stack []*TrieNodeClassic

	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return
		}
		node = node.Children[bit]
		stack = append(stack, node)
	}

	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].Count == 0 {
			return
		}
		stack[i].Count--
	}
}

// createLargeTrie creates a trie with specified number of IPs for testing
func createLargeTrie(numIPs int) *Trie {
	trie := NewTrie()

	// Create diverse IP patterns to test different trie structures
	for i := 0; i < numIPs; i++ {
		var ip net.IP
		switch i % 4 {
		case 0:
			// Clustered IPs (10.x.x.x)
			ip = net.IPv4(10, byte((i/256)%256), byte(i%256), byte(i%256))
		case 1:
			// Scattered IPs (192.168.x.x)
			ip = net.IPv4(192, 168, byte(i%256), byte((i/256)%256))
		case 2:
			// Different class B (172.16.x.x)
			ip = net.IPv4(172, 16, byte(i%256), byte((i/256)%256))
		case 3:
			// Random distribution
			ip = net.IPv4(byte((i*7)%256), byte((i*11)%256), byte((i*13)%256), byte((i*17)%256))
		}

		trie.Insert(ip)
	}

	return trie
}

// benchmarkWorkerDistribution tests worker distribution with custom worker count
func benchmarkWorkerDistribution(trie *Trie, workers int) []string {
	// Simulate the collectCIDRsWorkerPool function with custom worker count
	totalCount := trie.Root.Count
	parallelizationDepth := calculateCustomParallelizationDepth(totalCount, workers)
	return collectCIDRsWithCustomWorkers(trie, 1000, 16, 24, 0.5, parallelizationDepth, workers)
}

// benchmarkParallelizationDepth tests with custom parallelization depth
func benchmarkParallelizationDepth(trie *Trie, workers int, depth uint32) []string {
	return collectCIDRsWithCustomWorkers(trie, 1000, 16, 24, 0.5, depth, workers)
}

// measureWorkBalance measures how balanced work is distributed among workers
func measureWorkBalance(trie *Trie, workers int) float64 {
	workCounts := make([]int, workers)
	workQueue := make(chan subtreeWork, workers*4)

	// Generate work items
	totalCount := trie.Root.Count
	parallelizationDepth := calculateCustomParallelizationDepth(totalCount, workers)

	go func() {
		defer close(workQueue)
		generateWorkItems(trie.Root, 0, 0, parallelizationDepth, workQueue)
	}()

	// Distribute work to workers and count
	workerIdx := 0
	for work := range workQueue {
		workCounts[workerIdx] += int(work.node.Count)
		workerIdx = (workerIdx + 1) % workers
	}

	// Calculate balance (coefficient of variation)
	if len(workCounts) == 0 {
		return 0
	}

	sum := 0
	for _, count := range workCounts {
		sum += count
	}
	mean := float64(sum) / float64(len(workCounts))

	variance := 0.0
	for _, count := range workCounts {
		diff := float64(count) - mean
		variance += diff * diff
	}
	variance /= float64(len(workCounts))

	if mean == 0 {
		return 0
	}

	return variance / (mean * mean) // Coefficient of variation squared
}

// Helper functions for benchmarking
func calculateCustomParallelizationDepth(totalCount uint32, workers int) uint32 {
	targetItemsPerWorker := uint32(5000)

	depth := uint32(1)
	for depth < 16 {
		estimatedSubtrees := uint32(1) << depth
		if estimatedSubtrees >= uint32(workers*2) {
			break
		}
		depth++
	}

	if totalCount/uint32(workers) < targetItemsPerWorker {
		if depth > 1 {
			depth--
		}
	}

	return depth
}

func collectCIDRsWithCustomWorkers(trie *Trie, minClusterSize, minDepth, maxDepth uint32, threshold float64, parallelizationDepth uint32, workers int) []string {
	workBufferSize := workers * 4
	if workBufferSize < 16 {
		workBufferSize = 16
	}

	workQueue := make(chan subtreeWork, workBufferSize)
	resultQueue := make(chan []string, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workQueue {
				localResults := make([]string, 0, 32)
				// Simplified processing for benchmark
				if work.node.Count >= minClusterSize {
					localResults = append(localResults, fmt.Sprintf("test.cidr.%d", work.node.Count))
				}
				if len(localResults) > 0 {
					resultQueue <- localResults
				}
			}
		}()
	}

	go func() {
		defer close(workQueue)
		generateWorkItems(trie.Root, 0, 0, parallelizationDepth, workQueue)
	}()

	go func() {
		wg.Wait()
		close(resultQueue)
	}()

	var results []string
	for batch := range resultQueue {
		results = append(results, batch...)
	}

	return results
}

func generateWorkItems(node *TrieNode, prefix, depth, maxDepth uint32, workQueue chan<- subtreeWork) {
	if node == nil || depth >= maxDepth {
		if node != nil {
			select {
			case workQueue <- subtreeWork{node, prefix, depth}:
			case <-time.After(100 * time.Millisecond):
				// Avoid hanging in benchmark
			}
		}
		return
	}

	if node.Children[0] != nil {
		generateWorkItems(node.Children[0], prefix, depth+1, maxDepth, workQueue)
	}
	if node.Children[1] != nil {
		generateWorkItems(node.Children[1], prefix|(1<<(31-depth)), depth+1, maxDepth, workQueue)
	}
}
