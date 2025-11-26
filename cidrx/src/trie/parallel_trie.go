package trie

import (
	"net"
	"runtime"
	"sort"
	"sync"

	"github.com/ChristianF88/cidrx/iputils"
)

// ParallelTrie provides thread-safe parallel insertion capabilities
type ParallelTrie struct {
	*Trie
	mutex sync.RWMutex
}

// NewParallelTrie creates a new thread-safe trie for parallel insertions
func NewParallelTrie() *ParallelTrie {
	return &ParallelTrie{
		Trie: NewTrie(),
	}
}

// ParallelInsert performs thread-safe insertion
func (pt *ParallelTrie) ParallelInsert(ip net.IP) {
	val := iputils.IPToUint32(ip)
	pt.ParallelInsertUint32(val)
}

// ParallelInsertUint32 performs thread-safe uint32 insertion
func (pt *ParallelTrie) ParallelInsertUint32(val uint32) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()
	pt.InsertUint32(val)
}

// BatchParallelInsert efficiently inserts a batch of IPs with parallel workers
func (pt *ParallelTrie) BatchParallelInsert(ips []net.IP, numWorkers int) {
	if len(ips) == 0 {
		return
	}

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// For small datasets, use sequential insertion (faster due to overhead)
	if len(ips) < 10000 || numWorkers == 1 {
		pt.mutex.Lock()
		for _, ip := range ips {
			pt.Insert(ip)
		}
		pt.mutex.Unlock()
		return
	}

	// Calculate optimal batch size to minimize lock contention
	batchSize := len(ips) / (numWorkers * 4) // 4 batches per worker for load balancing
	if batchSize < 1000 {
		batchSize = 1000 // Minimum batch size for efficiency
	}
	if batchSize > 50000 {
		batchSize = 50000 // Maximum batch size to prevent long lock holds
	}

	var wg sync.WaitGroup

	// Process in parallel batches
	for start := 0; start < len(ips); start += batchSize {
		end := start + batchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[start:end]

		wg.Add(1)
		go func(batch []net.IP) {
			defer wg.Done()

			// Convert to uint32 first (no lock needed)
			uint32IPs := make([]uint32, len(batch))
			for i, ip := range batch {
				uint32IPs[i] = iputils.IPToUint32(ip)
			}

			// Single lock for entire batch
			pt.mutex.Lock()
			for _, val := range uint32IPs {
				pt.InsertUint32(val)
			}
			pt.mutex.Unlock()
		}(batch)
	}

	wg.Wait()
}

// BatchParallelInsertUint32 efficiently inserts a batch of uint32 IPs with parallel workers
func (pt *ParallelTrie) BatchParallelInsertUint32(ips []uint32, numWorkers int) {
	if len(ips) == 0 {
		return
	}

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// For small datasets, use sequential insertion (faster due to overhead)
	if len(ips) < 10000 || numWorkers == 1 {
		pt.mutex.Lock()
		for _, ip := range ips {
			pt.InsertUint32(ip)
		}
		pt.mutex.Unlock()
		return
	}

	// Calculate optimal batch size
	batchSize := len(ips) / (numWorkers * 4)
	if batchSize < 1000 {
		batchSize = 1000
	}
	if batchSize > 50000 {
		batchSize = 50000
	}

	var wg sync.WaitGroup

	// Process in parallel batches
	for start := 0; start < len(ips); start += batchSize {
		end := start + batchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[start:end]

		wg.Add(1)
		go func(batch []uint32) {
			defer wg.Done()

			// Single lock for entire batch
			pt.mutex.Lock()
			for _, ip := range batch {
				pt.InsertUint32(ip)
			}
			pt.mutex.Unlock()
		}(batch)
	}

	wg.Wait()
}

// BatchParallelInsertSorted efficiently inserts a batch of IPs with sorting and deduplication optimization
func (pt *ParallelTrie) BatchParallelInsertSorted(ips []net.IP) {
	if len(ips) == 0 {
		return
	}

	// Convert to uint32 for faster sorting and deduplication
	ipUints := make([]uint32, len(ips))
	for i, ip := range ips {
		ipUints[i] = iputils.IPToUint32(ip)
	}

	// Sort for better cache locality and deduplication
	sort.Slice(ipUints, func(i, j int) bool {
		return ipUints[i] < ipUints[j]
	})

	// Deduplicate sorted IPs in-place
	if len(ipUints) > 0 {
		uniqueCount := 1
		for i := 1; i < len(ipUints); i++ {
			if ipUints[i] != ipUints[uniqueCount-1] {
				ipUints[uniqueCount] = ipUints[i]
				uniqueCount++
			}
		}
		ipUints = ipUints[:uniqueCount]
	}

	// For sorted insertion, use the optimized batch insertion method
	// The parallelization benefit comes from the sorting/deduplication phase above
	pt.mutex.Lock()
	pt.BatchInsertSortedUint32(ipUints)
	pt.mutex.Unlock()
}

// ChannelInsertWorker processes IPs from a channel with multiple workers
func (pt *ParallelTrie) ChannelInsertWorker(ipChan <-chan net.IP, numWorkers int) {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Batch IPs for efficient insertion
			const batchSize = 1000
			batch := make([]net.IP, 0, batchSize)

			for ip := range ipChan {
				batch = append(batch, ip)

				// Insert batch when full
				if len(batch) >= batchSize {
					pt.insertBatch(batch)
					batch = batch[:0] // Reset slice but keep capacity
				}
			}

			// Insert remaining IPs
			if len(batch) > 0 {
				pt.insertBatch(batch)
			}
		}()
	}

	wg.Wait()
}

// insertBatch is a helper to insert a batch with single lock
func (pt *ParallelTrie) insertBatch(batch []net.IP) {
	if len(batch) == 0 {
		return
	}

	pt.mutex.Lock()
	for _, ip := range batch {
		pt.Insert(ip)
	}
	pt.mutex.Unlock()
}

// Thread-safe wrapper methods for existing Trie functionality

// ParallelCount returns the count of a specific IP address thread-safely
func (pt *ParallelTrie) ParallelCount(ip net.IP) uint32 {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.Count(ip)
}

// ParallelCountAll returns the total count thread-safely
func (pt *ParallelTrie) ParallelCountAll() uint32 {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.CountAll()
}

// ParallelCountInRange returns count in CIDR range thread-safely
func (pt *ParallelTrie) ParallelCountInRange(cidr string) (uint32, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.CountInRange(cidr)
}

// ParallelCollectCIDRs performs CIDR collection thread-safely
func (pt *ParallelTrie) ParallelCollectCIDRs(minClusterSize, minDepth, maxDepth uint32, meanSubnetDifference float64) []string {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.CollectCIDRs(minClusterSize, minDepth, maxDepth, meanSubnetDifference)
}
