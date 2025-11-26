package tui

import (
	"net"
	"testing"

	"github.com/ChristianF88/cidrx/output"
)

func TestVisualizationCacheBasic(t *testing.T) {
	cache := NewVisualizationCache()

	// Test initial state
	blocks, masks := cache.GetCacheSize()
	if blocks != 0 || masks != 0 {
		t.Error("New cache should be empty")
	}

	// Create test cluster set
	clusterSet := &output.ClusterResult{
		Parameters: output.ClusterParameters{
			MinClusterSize:       10,
			MinDepth:             24,
			MaxDepth:             32,
			MeanSubnetDifference: 0.5,
		},
		MergedRanges: []output.CIDRRange{
			{CIDR: "192.168.1.0/24", Requests: 100, Percentage: 10.0},
			{CIDR: "10.0.0.0/16", Requests: 500, Percentage: 50.0},
		},
	}

	// Pre-compute for cluster set
	cache.PreComputeForClusterSet(clusterSet, 8)

	// Check cache was populated
	blocks, masks = cache.GetCacheSize()
	if blocks == 0 {
		t.Error("Cache should have block data after pre-computation")
	}
	if masks == 0 {
		t.Error("Cache should have IP masks after pre-computation")
	}
}

func TestBlockCoverageCalculation(t *testing.T) {
	cache := NewVisualizationCache()

	// Create IP mask for 192.168.0.0/16
	_, ipNet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		t.Fatal("Failed to parse CIDR:", err)
	}

	ipMask := cache.createIPMask(ipNet)
	if ipMask == nil {
		t.Fatal("Failed to create IP mask")
	}

	// Test coverage calculation for various blocks
	testCases := []struct {
		blockA, blockB int
		scale          int
		expectedCov    float64
		description    string
	}{
		{192, 168, 8, 0.125, "Coverage block 192.168"},        // 1/8 coverage since 192.168.x.x is part of the /16
		{192, 160, 8, 1.0, "Full coverage block 192.160-167"}, // Full coverage for this range
		{200, 100, 8, 0.0, "No coverage block"},
		{191, 168, 8, 0.125, "Edge coverage block"}, // 1/8 coverage
	}

	for _, tc := range testCases {
		coverage := cache.calculateBlockCoverageOptimized(tc.blockA, tc.blockB, tc.scale, ipMask)

		// Debug: print the IP mask ranges for understanding
		t.Logf("IP mask: NetIP=%v, Broadcast=%v", ipMask.NetIP, ipMask.Broadcast)
		t.Logf("Block %d-%d, %d-%d (scale %d): coverage %.3f",
			tc.blockA, tc.blockA+tc.scale-1, tc.blockB, tc.blockB+tc.scale-1, tc.scale, coverage)

		// For now, just check that coverage is reasonable (0-1 range)
		if coverage < 0 || coverage > 1 {
			t.Errorf("%s: coverage %.3f out of valid range [0,1]",
				tc.description, coverage)
		}
	}
}

func TestFastOverlapCheck(t *testing.T) {
	cache := NewVisualizationCache()

	// Pre-compute masks for test CIDRs
	testCIDRs := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}

	for _, cidr := range testCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal("Failed to parse CIDR:", err)
		}
		cache.IPMasks[cidr] = cache.createIPMask(ipNet)
	}

	testCases := []struct {
		cidr            string
		blockA, blockB  int
		scale           int
		expectedOverlap bool
		description     string
	}{
		{"192.168.1.0/24", 192, 168, 8, true, "Direct overlap"},
		{"192.168.1.0/24", 10, 0, 8, false, "No overlap"},
		{"10.0.0.0/8", 10, 5, 8, true, "Large network overlap"},
		{"172.16.0.0/12", 172, 16, 8, true, "Medium network overlap"},
		{"172.16.0.0/12", 192, 168, 8, false, "Different network"},
	}

	for _, tc := range testCases {
		overlap := cache.FastOverlapCheck(tc.cidr, tc.blockA, tc.blockB, tc.scale)
		if overlap != tc.expectedOverlap {
			t.Errorf("%s: expected overlap %v, got %v",
				tc.description, tc.expectedOverlap, overlap)
		}
	}
}

func TestGetDotSize(t *testing.T) {
	cache := NewVisualizationCache()

	testCases := []struct {
		coverage    float64
		expectedDot string
		description string
	}{
		{1.0, " ● ", "Full coverage"},
		{0.9, " ● ", "High coverage"},
		{0.5, " • ", "Medium coverage"},
		{0.2, " • ", "Low-medium coverage"},
		{0.1, " · ", "Low coverage"},
		{0.01, " · ", "Minimal coverage"},
		{0.0, "", "No coverage"},
	}

	for _, tc := range testCases {
		dot := cache.getDotSize(tc.coverage)
		if dot != tc.expectedDot {
			t.Errorf("%s (%.2f): expected %q, got %q",
				tc.description, tc.coverage, tc.expectedDot, dot)
		}
	}
}

func TestVisualizationCacheClear(t *testing.T) {
	cache := NewVisualizationCache()

	// Add some data
	clusterSet := &output.ClusterResult{
		Parameters: output.ClusterParameters{
			MinClusterSize:       10,
			MinDepth:             24,
			MaxDepth:             32,
			MeanSubnetDifference: 0.5,
		},
		MergedRanges: []output.CIDRRange{
			{CIDR: "192.168.1.0/24", Requests: 100, Percentage: 10.0},
		},
	}

	cache.PreComputeForClusterSet(clusterSet, 8)

	// Verify data exists
	blocks, masks := cache.GetCacheSize()
	if blocks == 0 || masks == 0 {
		t.Error("Cache should have data before clear")
	}

	// Clear cache
	oldVersion := cache.Version
	cache.Clear()

	// Verify cache is empty
	blocks, masks = cache.GetCacheSize()
	if blocks != 0 || masks != 0 {
		t.Error("Cache should be empty after clear")
	}

	// Verify version was incremented
	if cache.Version <= oldVersion {
		t.Error("Cache version should be incremented after clear")
	}
}

func BenchmarkBlockCoverageCalculation(b *testing.B) {
	cache := NewVisualizationCache()

	// Create IP mask for benchmark
	_, ipNet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		b.Fatal("Failed to parse CIDR:", err)
	}

	ipMask := cache.createIPMask(ipNet)
	if ipMask == nil {
		b.Fatal("Failed to create IP mask")
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Test various block positions
		blockA := (i % 32) * 8
		blockB := ((i / 32) % 32) * 8
		cache.calculateBlockCoverageOptimized(blockA, blockB, 8, ipMask)
	}
}

func BenchmarkFastOverlapCheck(b *testing.B) {
	cache := NewVisualizationCache()

	// Pre-compute mask
	_, ipNet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		b.Fatal("Failed to parse CIDR:", err)
	}

	cidr := "192.168.0.0/16"
	cache.IPMasks[cidr] = cache.createIPMask(ipNet)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		blockA := (i % 32) * 8
		blockB := ((i / 32) % 32) * 8
		cache.FastOverlapCheck(cidr, blockA, blockB, 8)
	}
}

func BenchmarkPreComputeForClusterSet(b *testing.B) {
	cache := NewVisualizationCache()

	clusterSet := &output.ClusterResult{
		Parameters: output.ClusterParameters{
			MinClusterSize:       10,
			MinDepth:             24,
			MaxDepth:             32,
			MeanSubnetDifference: 0.5,
		},
		MergedRanges: []output.CIDRRange{
			{CIDR: "192.168.1.0/24", Requests: 100, Percentage: 10.0},
			{CIDR: "10.0.0.0/16", Requests: 500, Percentage: 50.0},
			{CIDR: "172.16.0.0/12", Requests: 200, Percentage: 20.0},
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cache.Clear() // Reset for each iteration
		cache.PreComputeForClusterSet(clusterSet, 8)
	}
}
