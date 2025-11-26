package tui

import (
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/ChristianF88/cidrx/output"
)

// BlockKey represents a visualization block coordinate
type BlockKey struct {
	A, B  int
	Scale int
}

// VisualBlock represents a pre-computed visual block
type VisualBlock struct {
	Color      string
	Character  string
	Marker     string
	IsDetected bool
}

// IPMask represents a pre-computed IP network mask for fast overlap checks
type IPMask struct {
	NetIP     [4]byte
	Broadcast [4]byte
	Mask      [4]byte
}

// VisualizationCache contains pre-computed visualization data
type VisualizationCache struct {
	// Pre-computed block coverage for each CIDR
	BlockCoverage map[string]map[BlockKey]float64

	// Pre-computed IP masks for fast overlap checks
	IPMasks map[string]*IPMask

	// Pre-rendered visual blocks for common patterns
	VisualBlocks map[string]map[BlockKey]*VisualBlock

	// Cache metadata
	LastUpdated int64
	Version     int

	mu sync.RWMutex
}

// NewVisualizationCache creates a new visualization cache
func NewVisualizationCache() *VisualizationCache {
	return &VisualizationCache{
		BlockCoverage: make(map[string]map[BlockKey]float64),
		IPMasks:       make(map[string]*IPMask),
		VisualBlocks:  make(map[string]map[BlockKey]*VisualBlock),
	}
}

// PreComputeForClusterSet pre-computes visualization data for a cluster set
func (vc *VisualizationCache) PreComputeForClusterSet(clusterSet *output.ClusterResult, scale int) {
	if clusterSet == nil {
		return
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()

	cacheKey := vc.getClusterSetKey(clusterSet)

	// Initialize maps if needed
	if vc.BlockCoverage[cacheKey] == nil {
		vc.BlockCoverage[cacheKey] = make(map[BlockKey]float64)
	}
	if vc.VisualBlocks[cacheKey] == nil {
		vc.VisualBlocks[cacheKey] = make(map[BlockKey]*VisualBlock)
	}

	// Pre-compute for each CIDR range
	for _, cidrRange := range clusterSet.MergedRanges {
		vc.preComputeCIDR(cidrRange.CIDR, cacheKey, scale)
	}
}

// preComputeCIDR pre-computes data for a single CIDR range
func (vc *VisualizationCache) preComputeCIDR(cidrStr, cacheKey string, scale int) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return
	}

	// Pre-compute IP mask for fast operations
	if vc.IPMasks[cidrStr] == nil {
		vc.IPMasks[cidrStr] = vc.createIPMask(ipNet)
	}

	// Pre-compute block coverage for all relevant blocks
	vc.preComputeBlockCoverage(cidrStr, cacheKey, ipNet, scale)
}

// createIPMask creates a pre-computed IP mask
func (vc *VisualizationCache) createIPMask(ipNet *net.IPNet) *IPMask {
	netIP := ipNet.IP.To4()
	mask := ipNet.Mask

	if netIP == nil || len(mask) != 4 {
		return nil
	}

	ipMask := &IPMask{}
	copy(ipMask.NetIP[:], netIP)
	copy(ipMask.Mask[:], mask)

	// Calculate broadcast address
	for i := 0; i < 4; i++ {
		ipMask.Broadcast[i] = netIP[i] | ^mask[i]
	}

	return ipMask
}

// preComputeBlockCoverage pre-computes coverage for all blocks that might overlap
func (vc *VisualizationCache) preComputeBlockCoverage(cidrStr, cacheKey string, ipNet *net.IPNet, scale int) {
	ipMask := vc.IPMasks[cidrStr]
	if ipMask == nil {
		return
	}

	// Determine the range of blocks that might be affected
	startA := int(ipMask.NetIP[0])
	endA := int(ipMask.Broadcast[0])
	startB := int(ipMask.NetIP[1])
	endB := int(ipMask.Broadcast[1])

	// Expand to include adjacent blocks for visualization
	blockStartA := (startA / scale) * scale
	blockEndA := ((endA / scale) + 1) * scale
	blockStartB := (startB / scale) * scale
	blockEndB := ((endB / scale) + 1) * scale

	// Ensure bounds
	if blockStartA < 0 {
		blockStartA = 0
	}
	if blockEndA > 256 {
		blockEndA = 256
	}
	if blockStartB < 0 {
		blockStartB = 0
	}
	if blockEndB > 256 {
		blockEndB = 256
	}

	// Pre-compute coverage for relevant blocks
	for a := blockStartA; a < blockEndA; a += scale {
		for b := blockStartB; b < blockEndB; b += scale {
			blockKey := BlockKey{A: a, B: b, Scale: scale}
			coverage := vc.calculateBlockCoverageOptimized(a, b, scale, ipMask)

			if coverage > 0 {
				vc.BlockCoverage[cacheKey][blockKey] = coverage

				// Pre-compute visual block
				marker := vc.getDotSize(coverage)
				vc.VisualBlocks[cacheKey][blockKey] = &VisualBlock{
					Marker:     marker,
					IsDetected: true,
				}
			}
		}
	}
}

// calculateBlockCoverageOptimized uses pre-computed IP masks for fast coverage calculation
func (vc *VisualizationCache) calculateBlockCoverageOptimized(blockA, blockB, scale int, ipMask *IPMask) float64 {
	// Block's octet interval
	blockEndA := blockA + scale - 1
	blockEndB := blockB + scale - 1

	// Network's octet interval
	netStartA := int(ipMask.NetIP[0])
	netStartB := int(ipMask.NetIP[1])
	netEndA := int(ipMask.Broadcast[0])
	netEndB := int(ipMask.Broadcast[1])

	// Compute 1-D overlap lengths
	overlapALen := max(0, min(blockEndA, netEndA)-max(blockA, netStartA)+1)
	overlapBLen := max(0, min(blockEndB, netEndB)-max(blockB, netStartB)+1)

	// Fractional coverage on each axis
	covA := float64(overlapALen) / float64(scale)
	covB := float64(overlapBLen) / float64(scale)

	// Use the bigger one for dot size
	return math.Max(covA, covB)
}

// GetBlockCoverage returns cached block coverage
func (vc *VisualizationCache) GetBlockCoverage(clusterSet *output.ClusterResult, blockKey BlockKey) float64 {
	if clusterSet == nil {
		return 0
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()

	cacheKey := vc.getClusterSetKey(clusterSet)
	if coverageMap, exists := vc.BlockCoverage[cacheKey]; exists {
		return coverageMap[blockKey]
	}
	return 0
}

// GetVisualBlock returns cached visual block
func (vc *VisualizationCache) GetVisualBlock(clusterSet *output.ClusterResult, blockKey BlockKey) *VisualBlock {
	if clusterSet == nil {
		return nil
	}

	vc.mu.RLock()
	defer vc.mu.RUnlock()

	cacheKey := vc.getClusterSetKey(clusterSet)
	if blockMap, exists := vc.VisualBlocks[cacheKey]; exists {
		return blockMap[blockKey]
	}
	return nil
}

// FastOverlapCheck performs fast overlap checking using pre-computed masks
func (vc *VisualizationCache) FastOverlapCheck(cidrStr string, blockA, blockB, scale int) bool {
	vc.mu.RLock()
	ipMask, exists := vc.IPMasks[cidrStr]
	vc.mu.RUnlock()

	if !exists {
		return false
	}

	// Quick bounds check using pre-computed ranges
	if blockA+scale-1 < int(ipMask.NetIP[0]) || blockA > int(ipMask.Broadcast[0]) {
		return false
	}
	if blockB+scale-1 < int(ipMask.NetIP[1]) || blockB > int(ipMask.Broadcast[1]) {
		return false
	}

	// Detailed check for overlap
	for a := blockA; a < blockA+scale && a < 256; a++ {
		for b := blockB; b < blockB+scale && b < 256; b++ {
			if vc.ipInRange(byte(a), byte(b), ipMask) {
				return true
			}
		}
	}

	return false
}

// ipInRange checks if an IP (first two octets) is in the range using pre-computed mask
func (vc *VisualizationCache) ipInRange(a, b byte, ipMask *IPMask) bool {
	if a < ipMask.NetIP[0] || a > ipMask.Broadcast[0] {
		return false
	}
	if a == ipMask.NetIP[0] && b < ipMask.NetIP[1] {
		return false
	}
	if a == ipMask.Broadcast[0] && b > ipMask.Broadcast[1] {
		return false
	}
	return true
}

// getClusterSetKey generates a cache key for a cluster set
func (vc *VisualizationCache) getClusterSetKey(clusterSet *output.ClusterResult) string {
	// Use cluster parameters as key for cache consistency
	return fmt.Sprintf("cluster_%d_%d_%d_%.2f",
		clusterSet.Parameters.MinClusterSize,
		clusterSet.Parameters.MinDepth,
		clusterSet.Parameters.MaxDepth,
		clusterSet.Parameters.MeanSubnetDifference)
}

// getDotSize returns appropriate dot based on coverage percentage (same as original)
func (vc *VisualizationCache) getDotSize(coverage float64) string {
	switch {
	case coverage >= 0.8:
		return " ● "
	case coverage >= 0.2:
		return " • "
	case coverage > 0.0:
		return " · "
	default:
		return ""
	}
}

// Clear clears all cached data
func (vc *VisualizationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.BlockCoverage = make(map[string]map[BlockKey]float64)
	vc.IPMasks = make(map[string]*IPMask)
	vc.VisualBlocks = make(map[string]map[BlockKey]*VisualBlock)
	vc.Version++
}

// GetCacheSize returns the size of cached data
func (vc *VisualizationCache) GetCacheSize() (blocks int, masks int) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	for _, blockMap := range vc.BlockCoverage {
		blocks += len(blockMap)
	}
	masks = len(vc.IPMasks)
	return
}
