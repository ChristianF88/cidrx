package trie

import (
	"fmt"
	"net"
	"runtime"
	"testing"

	"github.com/ChristianF88/cidrx/iputils"
)

func TestParallelTrieCorrectness(t *testing.T) {
	// Test that parallel insertion produces same results as sequential
	testSizes := []int{1000, 10000, 100000}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("Size_%d", size), func(t *testing.T) {
			// Generate test IPs
			ips, err := iputils.RandomIPsFromRange("192.168.0.0/16", size)
			if err != nil {
				t.Fatal(err)
			}

			// Sequential insertion
			seqTrie := NewTrie()
			for _, ip := range ips {
				seqTrie.Insert(ip)
			}

			// Parallel insertion
			parTrie := NewParallelTrie()
			parTrie.BatchParallelInsert(ips, runtime.NumCPU())

			// Compare total counts
			seqCount := seqTrie.CountAll()
			parCount := parTrie.ParallelCountAll()

			if seqCount != parCount {
				t.Errorf("Count mismatch: sequential=%d, parallel=%d", seqCount, parCount)
			}

			// Test individual IP counts for a sample
			sampleSize := 100
			if size < sampleSize {
				sampleSize = size
			}

			for i := 0; i < sampleSize; i++ {
				ip := ips[i]
				seqIPCount := seqTrie.Count(ip)
				parIPCount := parTrie.ParallelCount(ip)

				if seqIPCount != parIPCount {
					t.Errorf("IP %s count mismatch: sequential=%d, parallel=%d",
						ip.String(), seqIPCount, parIPCount)
				}
			}
		})
	}
}

func TestParallelTrieChannelWorker(t *testing.T) {
	// Test channel-based worker approach
	size := 10000
	ips, err := iputils.RandomIPsFromRange("10.0.0.0/16", size)
	if err != nil {
		t.Fatal(err)
	}

	// Sequential reference
	seqTrie := NewTrie()
	for _, ip := range ips {
		seqTrie.Insert(ip)
	}

	// Channel workers
	parTrie := NewParallelTrie()
	ipChan := make(chan net.IP, 1000)

	// Start workers
	done := make(chan bool)
	go func() {
		parTrie.ChannelInsertWorker(ipChan, 4)
		done <- true
	}()

	// Send IPs
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Wait for completion
	<-done

	// Compare results
	if seqTrie.CountAll() != parTrie.ParallelCountAll() {
		t.Errorf("Channel worker count mismatch: sequential=%d, parallel=%d",
			seqTrie.CountAll(), parTrie.ParallelCountAll())
	}
}

func TestParallelTrieThreadSafety(t *testing.T) {
	// Test concurrent access to parallel trie
	parTrie := NewParallelTrie()

	const numGoroutines = 10
	const ipsPerGoroutine = 1000

	// Insert from multiple goroutines
	done := make(chan bool, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer func() { done <- true }()

			baseIP := fmt.Sprintf("10.%d.0.0/24", goroutineID)
			ips, err := iputils.RandomIPsFromRange(baseIP, ipsPerGoroutine)
			if err != nil {
				t.Errorf("Failed to generate IPs for goroutine %d: %v", goroutineID, err)
				return
			}

			for _, ip := range ips {
				parTrie.ParallelInsert(ip)
			}
		}(g)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify we have reasonable count (some IPs might be duplicates)
	totalCount := parTrie.ParallelCountAll()
	if totalCount == 0 {
		t.Error("No IPs were inserted")
	}

	// Test concurrent reads
	readDone := make(chan bool, numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer func() { readDone <- true }()

			// Perform various read operations
			_ = parTrie.ParallelCountAll()

			testIP := net.ParseIP("10.1.0.1")
			if testIP != nil {
				_ = parTrie.ParallelCount(testIP)
			}

			_, _ = parTrie.ParallelCountInRange("10.0.0.0/8")
		}()
	}

	// Wait for read operations
	for i := 0; i < numGoroutines; i++ {
		<-readDone
	}
}

func TestParallelTrieEdgeCases(t *testing.T) {
	// Test edge cases
	parTrie := NewParallelTrie()

	// Empty slice
	parTrie.BatchParallelInsert([]net.IP{}, 4)
	if parTrie.ParallelCountAll() != 0 {
		t.Error("Expected 0 count for empty insert")
	}

	// Single IP
	singleIP := net.ParseIP("192.168.1.1")
	if singleIP != nil {
		parTrie.BatchParallelInsert([]net.IP{singleIP}, 4)
		if parTrie.ParallelCountAll() != 1 {
			t.Error("Expected 1 count for single IP insert")
		}
	}

	// Duplicate IPs
	duplicateIPs := []net.IP{singleIP, singleIP, singleIP}
	parTrie2 := NewParallelTrie()
	parTrie2.BatchParallelInsert(duplicateIPs, 2)
	if parTrie2.ParallelCountAll() != 3 {
		t.Errorf("Expected 3 count for duplicate IPs, got %d", parTrie2.ParallelCountAll())
	}
}
