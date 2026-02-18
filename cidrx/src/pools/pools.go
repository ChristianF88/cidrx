package pools

import (
	"net"
	"strings"
	"sync"

	"github.com/ChristianF88/cidrx/ingestor"
)

// NewCIDRStringBuilderPool creates a string builder pool optimized for CIDR string creation
// Pre-allocates capacity for typical IPv4 CIDR string (e.g., "192.168.1.0/24")
func NewCIDRStringBuilderPool() *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			builder := &strings.Builder{}
			builder.Grow(18) // Pre-allocate for typical CIDR string
			return builder
		},
	}
}

// GetBuilderFromPool gets a string builder from the pool and resets it
func GetBuilderFromPool(pool *sync.Pool) *strings.Builder {
	builder := pool.Get().(*strings.Builder)
	builder.Reset()
	return builder
}

// ReturnBuilderToPool returns a string builder to the pool
func ReturnBuilderToPool(pool *sync.Pool, builder *strings.Builder) {
	pool.Put(builder)
}

// TrieNode structure (defined here to avoid import cycles)
type TrieNode struct {
	Children [2]*TrieNode
	Count    uint32
}

// NodeAllocator pre-allocates chunks of nodes for better performance
// Thread-safe allocator with mutex protection
type NodeAllocator struct {
	mu           sync.Mutex
	chunks       [][]TrieNode
	currentChunk int
	currentIndex int
	chunkSize    int
}

// NewNodeAllocator creates a new node allocator
func NewNodeAllocator() *NodeAllocator {
	return &NodeAllocator{
		chunks:    make([][]TrieNode, 0, 10),
		chunkSize: 16384, // Allocate nodes in chunks of 16K (~320KB per chunk, reduces mutex acquisitions)
	}
}

// GetNode returns a pointer to a new zeroed TrieNode.
// Thread-safe. Chunk allocation happens outside the lock to avoid
// holding the mutex during a ~49KB heap allocation.
func (na *NodeAllocator) GetNode() *TrieNode {
	na.mu.Lock()

	// Fast path: space available in current chunk
	if len(na.chunks) > 0 && na.currentIndex < na.chunkSize {
		node := &na.chunks[na.currentChunk][na.currentIndex]
		na.currentIndex++
		na.mu.Unlock()
		return node
	}
	na.mu.Unlock()

	// Slow path: allocate new chunk outside the lock
	newChunk := make([]TrieNode, na.chunkSize)

	na.mu.Lock()
	// Double-check: another goroutine may have already allocated a chunk
	if len(na.chunks) == 0 || na.currentIndex >= na.chunkSize {
		na.chunks = append(na.chunks, newChunk)
		na.currentChunk = len(na.chunks) - 1
		na.currentIndex = 0
	}

	node := &na.chunks[na.currentChunk][na.currentIndex]
	na.currentIndex++
	na.mu.Unlock()
	return node
}

// Reset clears all allocated chunks and resets counters
// Should be called to free memory when allocator is no longer needed
func (na *NodeAllocator) Reset() {
	na.mu.Lock()
	defer na.mu.Unlock()

	na.chunks = na.chunks[:0] // Clear slice but keep capacity
	na.currentChunk = 0
	na.currentIndex = 0
}

// GlobalPools provides centralized memory pooling for performance optimization
type GlobalPools struct {
	RequestSlices   sync.Pool
	StringSlices    sync.Pool
	IPSlices        sync.Pool
	StringMaps      sync.Pool
	IPMaps          sync.Pool
	CIDRBuilders    sync.Pool
	IPNetSlices     sync.Pool
	CIDRRangeSlices sync.Pool
}

// Pools is the global instance of memory pools
var Pools = &GlobalPools{
	RequestSlices: sync.Pool{
		New: func() interface{} {
			slice := make([]ingestor.Request, 0, 1024)
			return &slice
		},
	},
	StringSlices: sync.Pool{
		New: func() interface{} {
			slice := make([]string, 0, 256)
			return &slice
		},
	},
	IPSlices: sync.Pool{
		New: func() interface{} {
			slice := make([]net.IP, 0, 512)
			return &slice
		},
	},
	StringMaps: sync.Pool{
		New: func() interface{} {
			return make(map[string]bool, 1024)
		},
	},
	IPMaps: sync.Pool{
		New: func() interface{} {
			return make(map[string]net.IP, 512)
		},
	},
	CIDRBuilders: sync.Pool{
		New: func() interface{} {
			builder := &strings.Builder{}
			builder.Grow(20) // Pre-allocate for CIDR strings
			return builder
		},
	},
	IPNetSlices: sync.Pool{
		New: func() interface{} {
			slice := make([]*net.IPNet, 0, 256)
			return &slice
		},
	},
	CIDRRangeSlices: sync.Pool{
		New: func() interface{} {
			// For output.CIDRRange slices
			return make([]interface{}, 0, 128) // Generic slice for CIDRRange objects
		},
	},
}

// GetRequestSlice gets a request slice from the pool and resets it
func (gp *GlobalPools) GetRequestSlice() []ingestor.Request {
	slicePtr := gp.RequestSlices.Get().(*[]ingestor.Request)
	*slicePtr = (*slicePtr)[:0] // Reset length while keeping capacity
	return *slicePtr
}

// ReturnRequestSlice returns a request slice to the pool
func (gp *GlobalPools) ReturnRequestSlice(slice []ingestor.Request) {
	if cap(slice) < 8192 { // Prevent memory bloat
		emptySlice := slice[:0]
		gp.RequestSlices.Put(&emptySlice)
	}
}

// GetStringSlice gets a string slice from the pool and resets it
func (gp *GlobalPools) GetStringSlice() []string {
	slicePtr := gp.StringSlices.Get().(*[]string)
	*slicePtr = (*slicePtr)[:0]
	return *slicePtr
}

// ReturnStringSlice returns a string slice to the pool
func (gp *GlobalPools) ReturnStringSlice(slice []string) {
	if cap(slice) < 2048 {
		emptySlice := slice[:0]
		gp.StringSlices.Put(&emptySlice)
	}
}

// GetIPSlice gets an IP slice from the pool and resets it
func (gp *GlobalPools) GetIPSlice() []net.IP {
	slicePtr := gp.IPSlices.Get().(*[]net.IP)
	*slicePtr = (*slicePtr)[:0]
	return *slicePtr
}

// ReturnIPSlice returns an IP slice to the pool
func (gp *GlobalPools) ReturnIPSlice(slice []net.IP) {
	if cap(slice) < 2048 {
		emptySlice := slice[:0]
		gp.IPSlices.Put(&emptySlice)
	}
}

// GetStringMap gets a string map from the pool and clears it
func (gp *GlobalPools) GetStringMap() map[string]bool {
	m := gp.StringMaps.Get().(map[string]bool)
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

// ReturnStringMap returns a string map to the pool
func (gp *GlobalPools) ReturnStringMap(m map[string]bool) {
	if len(m) < 4096 { // Prevent memory bloat
		gp.StringMaps.Put(m)
	}
}

// GetIPMap gets an IP map from the pool and clears it
func (gp *GlobalPools) GetIPMap() map[string]net.IP {
	m := gp.IPMaps.Get().(map[string]net.IP)
	// Clear the map
	for k := range m {
		delete(m, k)
	}
	return m
}

// ReturnIPMap returns an IP map to the pool
func (gp *GlobalPools) ReturnIPMap(m map[string]net.IP) {
	if len(m) < 2048 {
		gp.IPMaps.Put(m)
	}
}

// GetCIDRBuilder gets a string builder from the pool for CIDR operations
func (gp *GlobalPools) GetCIDRBuilder() *strings.Builder {
	builder := gp.CIDRBuilders.Get().(*strings.Builder)
	builder.Reset()
	return builder
}

// ReturnCIDRBuilder returns a string builder to the pool
func (gp *GlobalPools) ReturnCIDRBuilder(builder *strings.Builder) {
	gp.CIDRBuilders.Put(builder)
}

// GetIPNetSlice gets an IPNet slice from the pool and resets it
func (gp *GlobalPools) GetIPNetSlice() []*net.IPNet {
	slicePtr := gp.IPNetSlices.Get().(*[]*net.IPNet)
	*slicePtr = (*slicePtr)[:0]
	return *slicePtr
}

// ReturnIPNetSlice returns an IPNet slice to the pool
func (gp *GlobalPools) ReturnIPNetSlice(slice []*net.IPNet) {
	if cap(slice) < 1024 {
		emptySlice := slice[:0]
		gp.IPNetSlices.Put(&emptySlice)
	}
}

// Reset clears all pools (useful for testing)
func (gp *GlobalPools) Reset() {
	gp.RequestSlices = sync.Pool{New: gp.RequestSlices.New}
	gp.StringSlices = sync.Pool{New: gp.StringSlices.New}
	gp.IPSlices = sync.Pool{New: gp.IPSlices.New}
	gp.StringMaps = sync.Pool{New: gp.StringMaps.New}
	gp.IPMaps = sync.Pool{New: gp.IPMaps.New}
	gp.CIDRBuilders = sync.Pool{New: gp.CIDRBuilders.New}
	gp.IPNetSlices = sync.Pool{New: gp.IPNetSlices.New}
	gp.CIDRRangeSlices = sync.Pool{New: gp.CIDRRangeSlices.New}
}
