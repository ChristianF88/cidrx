package trie

import (
	"net"
	"runtime"
	"sync"

	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/pools"
)

// --- Core Data Structures ---

// TrieNode is now defined in pools package to enable pooling
type TrieNode = pools.TrieNode

type Trie struct {
	Root      *TrieNode
	allocator *pools.NodeAllocator
}

// NewTrie creates a new binary trie optimized for IP address storage
// Tuning via https://medium.com/@piyanin/boost-performance-binary-trees-of-a-benchmark-game-more-than-3x-times-for-go-language-ccafe813278c
func NewTrie() *Trie {
	allocator := pools.NewNodeAllocator()
	return &Trie{
		Root:      allocator.GetNode(),
		allocator: allocator,
	}
}

// Insert adds an IP address to the Trie and increments counts along the path
func (t *Trie) Insert(ip net.IP) {
	val := iputils.IPToUint32(ip)
	t.InsertUint32(val)
}

// InsertUint32 adds a uint32 IP directly - ELIMINATES net.IP conversion overhead
func (t *Trie) InsertUint32(val uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.allocator.GetNode()
		}
		node = node.Children[bit]
		node.Count++
	}
}

// BatchInsertUint32 efficiently inserts multiple uint32 IPs
func (t *Trie) BatchInsertUint32(ips []uint32) {
	for _, ip := range ips {
		t.InsertUint32(ip)
	}
}

// BatchInsertSortedUint32 efficiently inserts sorted uint32 IPs with optimized traversal
// This method takes advantage of:
// 1. Batching identical IPs (only one traversal, but increment count by batch size)
// 2. Reusing common prefixes between consecutive IPs
// 3. Caching traversal state to avoid re-traversing from root
func (t *Trie) BatchInsertSortedUint32(ips []uint32) {
	if len(ips) == 0 {
		return
	}

	i := 0
	for i < len(ips) {
		currentIP := ips[i]

		// Count consecutive identical IPs
		count := 1
		for i+count < len(ips) && ips[i+count] == currentIP {
			count++
		}

		// Insert this IP with the batch count
		t.insertUint32WithCount(currentIP, uint32(count))

		i += count
	}
}

// insertUint32WithCount adds a uint32 IP with a specific count increment
func (t *Trie) insertUint32WithCount(val uint32, count uint32) {
	node := t.Root
	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			node.Children[bit] = t.allocator.GetNode()
		}
		node = node.Children[bit]
		node.Count += count // Increment by the batch count instead of just 1
	}
}

// Delete removes an IP address from the Trie. It traverses the Trie
// based on the binary representation of the IP address and decrements
// the count of nodes along the path. If a node's count reaches zero,
// it removes the corresponding child node to free up memory.
//
// Parameters:
//   - ip: The IP address to be removed, represented as a net.IP.
//
// Note:
//   - If the IP address does not exist in the Trie, the function exits
//     without making any changes.
func (t *Trie) Delete(ip net.IP) {
	node := t.Root
	val := iputils.IPToUint32(ip)
	var stack []*TrieNode

	for i := 31; i >= 0; i-- {
		bit := (val >> i) & 1
		if node.Children[bit] == nil {
			return
		}
		node = node.Children[bit]
		stack = append(stack, node)
	}

	// The IP was found, then the counts need to be modified at each node
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].Count == 0 {
			return
		}
		stack[i].Count--
	}
}

// Count returns the count of a specific IP address in the Trie
func (t *Trie) Count(ip net.IP) uint32 {
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

// CountAll returns the total count of all IPs in the Trie
func (t *Trie) CountAll() uint32 {
	if t.Root == nil {
		return 0
	} else if t.Root.Children[0] == nil && t.Root.Children[1] == nil {
		return t.Root.Count
	} else {
		var leftCount, rightCount uint32
		leftCount = 0
		rightCount = 0
		if t.Root.Children[0] != nil {
			leftCount = t.Root.Children[0].Count
		}
		if t.Root.Children[1] != nil {
			rightCount = t.Root.Children[1].Count
		}
		return leftCount + rightCount
	}
}

// CountInRange counts all IPs of a Trie within a specific CIDR range
// Uses optimized tree traversal that correctly handles all range boundaries
func (t *Trie) CountInRange(cidr string) (uint32, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	return t.CountInRangeIPNet(ipNet), nil
}

// CountInRangeIPNet counts all IPs of a Trie within a specific IPNet range
// High-performance version that avoids string parsing overhead
func (t *Trie) CountInRangeIPNet(ipNet *net.IPNet) uint32 {
	rangeStart := iputils.IPToUint32(ipNet.IP)
	maskBits, _ := ipNet.Mask.Size()

	// Calculate the end of the range
	rangeSize := uint32(1) << (32 - maskBits)
	rangeEnd := rangeStart + rangeSize - 1

	return t.countInRangeOptimized(t.Root, rangeStart, rangeEnd, 0, 0)
}

// countInRangeOptimized traverses the trie efficiently using proper range intersection
func (t *Trie) countInRangeOptimized(node *TrieNode, rangeStart, rangeEnd uint32, currentPrefix, depth uint32) uint32 {
	if node == nil {
		return 0
	}

	// Calculate the range of IPs that this node represents
	var nodeStart, nodeEnd uint32
	if depth == 32 {
		// Leaf node represents a single IP
		nodeStart = currentPrefix
		nodeEnd = currentPrefix
	} else {
		// Internal node represents a range of IPs
		nodeStart = currentPrefix
		nodeEnd = currentPrefix | ((uint32(1) << (32 - depth)) - 1)
	}

	// Check if the node's range intersects with our target range
	if nodeEnd < rangeStart || nodeStart > rangeEnd {
		// No intersection
		return 0
	}

	// If we're at a leaf node (depth 32), return the count if it's in range
	if depth == 32 {
		return node.Count
	}

	// If the target range completely contains the node's range, return all counts
	if rangeStart <= nodeStart && rangeEnd >= nodeEnd {
		return node.Count
	}

	// Partial intersection - need to recurse into children
	var count uint32

	// Check left child (bit 0)
	if node.Children[0] != nil {
		leftPrefix := currentPrefix
		count += t.countInRangeOptimized(node.Children[0], rangeStart, rangeEnd, leftPrefix, depth+1)
	}

	// Check right child (bit 1)
	if node.Children[1] != nil {
		rightPrefix := currentPrefix | (uint32(1) << (31 - depth))
		count += t.countInRangeOptimized(node.Children[1], rangeStart, rangeEnd, rightPrefix, depth+1)
	}

	return count
}

// CollectCIDRsCoreParallelNumeric - Optimized non-recursive version returning numeric CIDRs
func (t *Trie) CollectCIDRsCoreParallelNumeric(node *TrieNode, prefix uint32, depth uint32, results *[]cidr.NumericCIDR,
	minClusterSize, minDepth, maxDepth uint32, threshold uint32) {

	// Use a stack-based approach to avoid recursion
	type stackItem struct {
		node   *TrieNode
		prefix uint32
		depth  uint32
	}

	// Optimized stack capacity - account for branching factor
	stack := make([]stackItem, 0, 64)
	stack = append(stack, stackItem{node, prefix, depth})

	for len(stack) > 0 {
		// Pop from stack
		idx := len(stack) - 1
		item := stack[idx]
		stack = stack[:idx]

		// Skip nil nodes
		if item.node == nil {
			continue
		}

		// Terminal case - max depth reached
		if item.depth == maxDepth {
			if item.node.Count >= minClusterSize {
				*results = append(*results, prefixToNumericCIDR(item.prefix, item.depth))
			}
			continue
		}

		// Early exit optimization: Skip nodes that can't meet minimum cluster size
		if item.node.Count < minClusterSize {
			continue
		}

		// Calculate whether this node should be appended as a CIDR
		var appendCluster bool
		hasLeft := item.node.Children[0] != nil
		hasRight := item.node.Children[1] != nil

		// Distribution check using optimized integer math
		if hasLeft && hasRight {
			// Fast path for equal counts
			if item.node.Children[0].Count == item.node.Children[1].Count {
				appendCluster = true
			} else {
				// Optimized mean difference calculation
				var diff uint32
				if item.node.Children[0].Count > item.node.Children[1].Count {
					diff = item.node.Children[0].Count - item.node.Children[1].Count
				} else {
					diff = item.node.Children[1].Count - item.node.Children[0].Count
				}
				// Efficient integer comparison
				appendCluster = (2000 * diff) < (threshold * item.node.Count)
			}
		}

		// Leaf node - skip further processing
		if !hasLeft && !hasRight {
			continue
		}

		// If criteria met, add CIDR and skip children
		if appendCluster && item.node.Count >= minClusterSize && item.depth >= minDepth {
			*results = append(*results, prefixToNumericCIDR(item.prefix, item.depth))
			continue // Stop processing this branch
		}

		// Add children to stack - process in optimized order with early exit optimization
		if hasLeft && hasRight {
			leftCount := item.node.Children[0].Count
			rightCount := item.node.Children[1].Count

			// Add larger subtree first to process smaller one first (LIFO stack)
			// Only add children that meet minimum cluster size requirement
			if leftCount > rightCount {
				// Right child (smaller) - only add if it meets minimum cluster size
				if rightCount >= minClusterSize {
					stack = append(stack, stackItem{
						item.node.Children[1],
						item.prefix | (1 << (31 - item.depth)),
						item.depth + 1,
					})
				}
				// Left child (larger) - only add if it meets minimum cluster size
				if leftCount >= minClusterSize {
					stack = append(stack, stackItem{
						item.node.Children[0],
						item.prefix,
						item.depth + 1,
					})
				}
			} else {
				// Left child (smaller) - only add if it meets minimum cluster size
				if leftCount >= minClusterSize {
					stack = append(stack, stackItem{
						item.node.Children[0],
						item.prefix,
						item.depth + 1,
					})
				}
				// Right child (larger) - only add if it meets minimum cluster size
				if rightCount >= minClusterSize {
					stack = append(stack, stackItem{
						item.node.Children[1],
						item.prefix | (1 << (31 - item.depth)),
						item.depth + 1,
					})
				}
			}
		} else if hasLeft && item.node.Children[0].Count >= minClusterSize {
			stack = append(stack, stackItem{
				item.node.Children[0],
				item.prefix,
				item.depth + 1,
			})
		} else if hasRight && item.node.Children[1].Count >= minClusterSize {
			stack = append(stack, stackItem{
				item.node.Children[1],
				item.prefix | (1 << (31 - item.depth)),
				item.depth + 1,
			})
		}
	}
}

// CollectCIDRsCoreSequentialNumeric - Sequential version returning numeric CIDRs
func (t *Trie) CollectCIDRsCoreSequentialNumeric(node *TrieNode, prefix uint32, depth uint32, results *[]cidr.NumericCIDR, minClusterSize, minDepth, maxDepth uint32, threshold uint32) {
	// Check for nil node
	if node == nil {
		return
	}

	if depth == maxDepth {
		if node.Count >= minClusterSize {
			*results = append(*results, prefixToNumericCIDR(prefix, depth))
		}
		return
	}

	// Calculate if this node should be appended
	var appendCluster bool
	hasLeft := node.Children[0] != nil
	hasRight := node.Children[1] != nil

	// Leaf node - exit early
	if !hasLeft && !hasRight {
		return
	}

	// Optimized distribution check using integer math
	if hasLeft && hasRight {
		// Fast path for equal counts
		if node.Children[0].Count == node.Children[1].Count {
			appendCluster = true
		} else {
			// Integer math version of mean difference calculation
			var diff uint32
			if node.Children[0].Count > node.Children[1].Count {
				diff = node.Children[0].Count - node.Children[1].Count
			} else {
				diff = node.Children[1].Count - node.Children[0].Count
			}
			// Compare (2000*diff)/node.Count < threshold using cross-multiplication
			appendCluster = (2000 * diff) < (threshold * node.Count)
		}
	}

	// If the node meets the cluster size and depth requirements, add it as a CIDR
	// and stop further processing of its children.
	if appendCluster && node.Count >= minClusterSize && depth >= minDepth {
		*results = append(*results, prefixToNumericCIDR(prefix, depth))
		// Stop further processing of child nodes to avoid including smaller CIDRs
		return
	}

	// Fast path for common case: both children exist with early exit optimization
	if hasLeft && hasRight {
		leftCount := node.Children[0].Count
		rightCount := node.Children[1].Count

		// Process smaller subtree first to minimize stack depth
		// Only process children that meet minimum cluster size requirement
		if leftCount <= rightCount {
			if leftCount >= minClusterSize {
				t.CollectCIDRsCoreSequentialNumeric(node.Children[0], prefix, depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
			if rightCount >= minClusterSize {
				t.CollectCIDRsCoreSequentialNumeric(node.Children[1], prefix|(1<<(31-depth)), depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
		} else {
			if rightCount >= minClusterSize {
				t.CollectCIDRsCoreSequentialNumeric(node.Children[1], prefix|(1<<(31-depth)), depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
			if leftCount >= minClusterSize {
				t.CollectCIDRsCoreSequentialNumeric(node.Children[0], prefix, depth+1,
					results, minClusterSize, minDepth, maxDepth, threshold)
			}
		}
		return
	}

	// Recursively traverse the left and right children with early exit optimization
	if hasLeft && node.Children[0].Count >= minClusterSize {
		t.CollectCIDRsCoreSequentialNumeric(node.Children[0], prefix, depth+1, results, minClusterSize, minDepth, maxDepth, threshold)
	}
	if hasRight && node.Children[1].Count >= minClusterSize {
		t.CollectCIDRsCoreSequentialNumeric(node.Children[1], prefix|(1<<(31-depth)), depth+1, results, minClusterSize, minDepth, maxDepth, threshold)
	}
}

// prefixToNumericCIDR converts a prefix and depth to numeric CIDR without string allocation
func prefixToNumericCIDR(prefix uint32, depth uint32) cidr.NumericCIDR {
	return cidr.NumericCIDR{
		IP:        prefix,
		PrefixLen: uint8(depth),
	}
}

// CollectCIDRsNumeric - Optimized parallel clustering algorithm returning numeric CIDRs
// Avoids string allocations in hot paths for maximum performance
func (t *Trie) CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []cidr.NumericCIDR {
	// Convert threshold once
	threshold := uint32(meanSubnetDifference * 1000)

	// Handle edge cases
	if t.Root == nil {
		return []cidr.NumericCIDR{}
	}

	if t.Root.Children[0] == nil && t.Root.Children[1] == nil {
		if t.Root.Count >= minClusterSize && 0 >= minDepth {
			return []cidr.NumericCIDR{{IP: 0, PrefixLen: 0}}
		}
		return []cidr.NumericCIDR{}
	}

	// Estimate workload size for adaptive parallelization
	totalCount := t.Root.Count

	// Optimized worker count based on dataset size and system characteristics
	workers := t.calculateOptimalWorkerCount(totalCount)

	// Use sequential processing for small workloads (lower overhead)
	if totalCount < 20000 || workers == 1 {
		return t.collectCIDRsSequentialNumeric(minClusterSize, minDepth, maxDepth, threshold)
	}

	// Adaptive parallelization depth based on workload
	parallelizationDepth := t.calculateOptimalParallelizationDepth(totalCount, workers)

	// Use optimized worker pool pattern
	return t.collectCIDRsWorkerPoolNumeric(minClusterSize, minDepth, maxDepth, threshold, parallelizationDepth, workers)
}

// CollectCIDRs - Optimized parallel clustering algorithm with adaptive parallelization
// Legacy string-based version for backward compatibility
func (t *Trie) CollectCIDRs(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []string {
	// Use the numeric version and convert to strings only at the end
	numericResults := t.CollectCIDRsNumeric(minClusterSize, minDepth, maxDepth, meanSubnetDifference)
	result := make([]string, len(numericResults))
	for i, nc := range numericResults {
		result[i] = nc.String()
	}
	return result
}

// collectCIDRsSequentialNumeric - Sequential version for small workloads returning numeric CIDRs
func (t *Trie) collectCIDRsSequentialNumeric(minClusterSize, minDepth, maxDepth, threshold uint32) []cidr.NumericCIDR {
	// Better capacity estimation
	estimatedCapacity := uint32(128)
	if t.Root.Count > 0 {
		estimatedCapacity = t.Root.Count / (minClusterSize * 8)
		if estimatedCapacity < 32 {
			estimatedCapacity = 32
		}
		if estimatedCapacity > 512 {
			estimatedCapacity = 512
		}
	}

	results := make([]cidr.NumericCIDR, 0, estimatedCapacity)
	t.CollectCIDRsCoreSequentialNumeric(t.Root, 0, 0, &results, minClusterSize, minDepth, maxDepth, threshold)
	return results
}

// calculateOptimalParallelizationDepth - Calculates optimal depth for parallelization
func (t *Trie) calculateOptimalParallelizationDepth(totalCount uint32, workers int) uint32 {
	// Optimized target based on empirical testing: ~10k-50k items per worker
	targetItemsPerWorker := uint32(20000)
	minItemsPerWorker := uint32(5000)

	// For small datasets, use sequential processing (it's faster)
	if totalCount < minItemsPerWorker*2 {
		return 16 // Deep enough to disable parallelization
	}

	// Calculate optimal depth based on actual data distribution
	depth := uint32(1)
	for depth < 12 { // Reduced max depth to prevent over-parallelization
		estimatedSubtrees := uint32(1) << depth
		itemsPerWorker := totalCount / estimatedSubtrees

		// Stop when we reach optimal items per worker
		if itemsPerWorker <= targetItemsPerWorker && estimatedSubtrees >= uint32(workers) {
			break
		}
		depth++
	}

	// Ensure minimum efficiency threshold
	if totalCount/uint32(workers) < minItemsPerWorker {
		depth = maxUint32(1, depth-1)
	}

	return depth
}

// calculateOptimalWorkerCount determines the optimal number of workers based on workload
func (t *Trie) calculateOptimalWorkerCount(totalCount uint32) int {
	// Base worker count on CPU cores but adapt for I/O vs CPU bound tasks
	baseCPUs := runtime.NumCPU()

	// For very small datasets, sequential is faster
	if totalCount < 10000 {
		return 1
	}

	// For medium datasets, use fewer workers to reduce coordination overhead
	if totalCount < 50000 {
		return max(1, baseCPUs/2)
	}

	// For large datasets, use more workers but cap to avoid excessive overhead
	if totalCount < 200000 {
		return baseCPUs
	}

	// For very large datasets, can benefit from more workers (up to 2x CPUs)
	return min(baseCPUs*2, 16) // Cap at 16 to prevent excessive context switching
}

// subtreeWork represents a work item for the worker pool
type subtreeWork struct {
	node   *TrieNode
	prefix uint32
	depth  uint32
}

// collectCIDRsWorkerPoolNumeric - Worker pool implementation returning numeric CIDRs
func (t *Trie) collectCIDRsWorkerPoolNumeric(minClusterSize, minDepth, maxDepth, threshold, parallelizationDepth uint32, workers int) []cidr.NumericCIDR {
	// Optimized buffer sizes to reduce blocking and contention
	workBufferSize := workers * 8 // Increased buffer to reduce blocking
	if workBufferSize < 32 {
		workBufferSize = 32
	}

	// Create work queue with larger buffers
	workQueue := make(chan subtreeWork, workBufferSize)
	resultQueue := make(chan []cidr.NumericCIDR, workers*4) // Larger result buffer

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go t.workerNumeric(workQueue, resultQueue, &wg, minClusterSize, minDepth, maxDepth, threshold)
	}

	// Generate work items
	go func() {
		defer close(workQueue)
		t.generateWorkItems(t.Root, 0, 0, parallelizationDepth, workQueue)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultQueue)
	}()

	// Merge results with better capacity estimation
	estimatedCapacity := uint32(256)
	if t.Root.Count > 0 {
		estimatedCapacity = t.Root.Count / (minClusterSize * 4)
		if estimatedCapacity < 64 {
			estimatedCapacity = 64
		}
		if estimatedCapacity > 1024 {
			estimatedCapacity = 1024
		}
	}

	results := make([]cidr.NumericCIDR, 0, estimatedCapacity)
	for localResults := range resultQueue {
		results = append(results, localResults...)
	}

	return results
}

// workerNumeric processes work items from the queue returning numeric CIDRs
func (t *Trie) workerNumeric(workQueue <-chan subtreeWork, resultQueue chan<- []cidr.NumericCIDR, wg *sync.WaitGroup, minClusterSize, minDepth, maxDepth, threshold uint32) {
	defer wg.Done()

	for work := range workQueue {
		// Estimate local capacity based on work size
		localCapacity := uint32(32)
		if work.node.Count > 0 {
			localCapacity = work.node.Count / (minClusterSize * 16)
			if localCapacity < 8 {
				localCapacity = 8
			}
			if localCapacity > 128 {
				localCapacity = 128
			}
		}

		localResults := make([]cidr.NumericCIDR, 0, localCapacity)
		t.CollectCIDRsCoreParallelNumeric(work.node, work.prefix, work.depth, &localResults, minClusterSize, minDepth, maxDepth, threshold)

		if len(localResults) > 0 {
			resultQueue <- localResults
		}
	}
}

// generateWorkItems generates work items for the worker pool
func (t *Trie) generateWorkItems(node *TrieNode, prefix, depth, maxDepth uint32, workQueue chan<- subtreeWork) {
	if node == nil || depth >= maxDepth {
		if node != nil {
			workQueue <- subtreeWork{node, prefix, depth}
		}
		return
	}

	// Generate work for left subtree
	if node.Children[0] != nil {
		t.generateWorkItems(node.Children[0], prefix, depth+1, maxDepth, workQueue)
	}

	// Generate work for right subtree
	if node.Children[1] != nil {
		t.generateWorkItems(node.Children[1], prefix|(1<<(31-depth)), depth+1, maxDepth, workQueue)
	}
}

// maxUint32 returns the maximum of two uint32 values
func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
