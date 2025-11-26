package tui

import (
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
	"github.com/rivo/tview"
)

// VisualizationView represents the 2D heatmap visualization
type VisualizationView struct {
	app                 *App
	view                *tview.TextView
	trafficData         [256][256]uint32
	maxTraffic          uint32
	requests            []ingestor.Request
	currentClusterSet   int
	totalClusterSets    int
	needsTrafficRefresh bool // Flag to track if traffic data needs re-processing

	// Legacy caching for performance (kept for compatibility)
	cachedTrafficData map[int][256][256]uint32 // Cache traffic data per trie
	cachedMaxTraffic  map[int]uint32           // Cache max traffic per trie
	cachedRenderText  map[int]string           // Cache rendered visualization text per trie

	// New optimized caching
	cache *VisualizationCache // Pre-computed visualization data
}

// NewVisualizationView creates a new visualization view
func (a *App) NewVisualizationView() *VisualizationView {
	var totalClusterSets int
	if a.cfg != nil && a.jsonResult != nil {
		// Config mode - use legacy format (jsonResult has the current trie data)
		totalClusterSets = len(a.jsonResult.Clustering.Data)
	} else {
		// Legacy mode
		totalClusterSets = len(a.jsonResult.Clustering.Data)
	}

	v := &VisualizationView{
		app:               a,
		currentClusterSet: 0,
		totalClusterSets:  totalClusterSets,
		// Initialize legacy cache maps
		cachedTrafficData: make(map[int][256][256]uint32),
		cachedMaxTraffic:  make(map[int]uint32),
		cachedRenderText:  make(map[int]string),
		// Initialize optimized cache
		cache: NewVisualizationCache(),
	}

	v.view = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false)
	v.view.SetBorder(true).SetTitle(" 2D Traffic Visualization (/16 Heatmap) ").SetTitleAlign(tview.AlignCenter)

	return v
}

// PreCacheAllTries processes and caches traffic data for all tries to eliminate switching delays (legacy)
func (v *VisualizationView) PreCacheAllTries(requests []ingestor.Request) {
	if v.app.cfg == nil || v.app.multiTrieResult == nil {
		// Legacy mode - cache single trie
		v.ProcessTrafficData(requests)
		v.cachedTrafficData[0] = v.trafficData
		v.cachedMaxTraffic[0] = v.maxTraffic

		// Pre-cache render text for all cluster sets
		for i := 0; i < v.totalClusterSets; i++ {
			v.currentClusterSet = i
			renderText := v.generateRenderText()
			v.cachedRenderText[i] = renderText
		}
		v.currentClusterSet = 0 // Reset to first
		return
	}

	// Multi-trie mode - cache traffic data for each trie
	originalTrie := v.app.currentTrie
	originalRequests := v.requests
	v.requests = requests

	for trieIndex := 0; trieIndex < len(v.app.multiTrieResult.Tries); trieIndex++ {
		// Temporarily switch to this trie for processing
		v.app.currentTrie = trieIndex

		// Update to this trie's data
		v.app.jsonResult = v.app.convertTrieToLegacy(trieIndex)
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)

		// Process traffic data for this trie
		v.ProcessTrafficData(requests)

		// Cache the traffic data
		v.cachedTrafficData[trieIndex] = v.trafficData
		v.cachedMaxTraffic[trieIndex] = v.maxTraffic

		// Pre-cache render text for all cluster sets in this trie
		for clusterSet := 0; clusterSet < v.totalClusterSets; clusterSet++ {
			v.currentClusterSet = clusterSet
			cacheKey := trieIndex*1000 + clusterSet // Composite key: trie + cluster set
			renderText := v.generateRenderText()
			v.cachedRenderText[cacheKey] = renderText
		}
	}

	// Restore original state
	v.app.currentTrie = originalTrie
	v.app.jsonResult = v.app.convertTrieToLegacy(originalTrie)
	v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
	v.currentClusterSet = 0
	v.requests = originalRequests

	// Load the original trie's cached data
	if cachedData, exists := v.cachedTrafficData[originalTrie]; exists {
		v.trafficData = cachedData
		v.maxTraffic = v.cachedMaxTraffic[originalTrie]
	}
}

// getCurrentClusterSet returns the current cluster set based on mode
func (v *VisualizationView) getCurrentClusterSet() *output.ClusterResult {
	// Ensure app and jsonResult exist
	if v.app == nil || v.app.jsonResult == nil {
		return nil
	}

	// Update totalClusterSets from current data
	actualClusterSets := len(v.app.jsonResult.Clustering.Data)
	if actualClusterSets == 0 {
		return nil
	}

	// Fix totalClusterSets if it's wrong
	if v.totalClusterSets != actualClusterSets {
		v.totalClusterSets = actualClusterSets
	}

	// Bounds check and fix currentClusterSet if it's out of range
	if v.currentClusterSet >= actualClusterSets {
		v.currentClusterSet = 0 // Reset to first cluster set
	}

	// Always use jsonResult.Clustering.Data since we convert multi-trie to legacy format
	return &v.app.jsonResult.Clustering.Data[v.currentClusterSet]
}

// updateForCurrentTrie updates the visualization for the current trie
func (v *VisualizationView) updateForCurrentTrie() {
	// Update cluster set count from current jsonResult (legacy format)
	if v.app.jsonResult != nil {
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
		v.currentClusterSet = 0 // Reset to first cluster set

		// Use cached traffic data if available
		if v.app.cfg != nil && len(v.requests) > 0 {
			v.updateTrafficDataCached()
		} else if len(v.requests) > 0 {
			// Legacy mode - no caching
			v.ProcessTrafficData(v.requests)
		}

		v.RenderCached()
	}
}

// updateMetadataOnly updates only the cluster set metadata without re-processing traffic
func (v *VisualizationView) updateMetadataOnly() {
	// Only update cluster set count, don't re-process traffic data
	if v.app.jsonResult != nil {
		v.totalClusterSets = len(v.app.jsonResult.Clustering.Data)
		v.currentClusterSet = 0      // Reset to first cluster set
		v.needsTrafficRefresh = true // Mark that traffic data needs refreshing
		// Don't call ProcessTrafficData or Render - too expensive
	}
}

// updateTrafficDataCached loads traffic data from cache or processes it
func (v *VisualizationView) updateTrafficDataCached() {
	currentTrie := v.app.currentTrie

	// Check if we have cached traffic data for this trie
	if cachedData, exists := v.cachedTrafficData[currentTrie]; exists {
		// Load from cache
		v.trafficData = cachedData
		v.maxTraffic = v.cachedMaxTraffic[currentTrie]
	} else {
		// Process and cache traffic data
		v.ProcessTrafficData(v.requests)

		// Cache the results
		v.cachedTrafficData[currentTrie] = v.trafficData
		v.cachedMaxTraffic[currentTrie] = v.maxTraffic
	}
}

// ProcessTrafficData processes the requests and builds the traffic heatmap
func (v *VisualizationView) ProcessTrafficData(requests []ingestor.Request) {
	v.requests = requests
	v.maxTraffic = 0

	// Reset traffic data
	for i := range v.trafficData {
		for j := range v.trafficData[i] {
			v.trafficData[i][j] = 0
		}
	}

	// For multi-trie mode, filter requests by current trie's detection ranges
	filteredRequests := v.getTrieSpecificRequests(requests)

	// Count traffic by /16 ranges (first.second octets)
	for _, req := range filteredRequests {
		ip := req.IP.To4()
		if ip == nil {
			continue
		}
		a, b := ip[0], ip[1]
		v.trafficData[a][b]++
		if v.trafficData[a][b] > v.maxTraffic {
			v.maxTraffic = v.trafficData[a][b]
		}
	}
}

// getTrieSpecificRequests filters requests to show only those relevant to current trie
func (v *VisualizationView) getTrieSpecificRequests(requests []ingestor.Request) []ingestor.Request {
	// In legacy mode, show all traffic
	if v.app.cfg == nil || v.app.multiTrieResult == nil {
		return requests
	}

	// In multi-trie mode, we need to apply the same filters as the current trie
	// to show only the traffic that would be included in this trie's analysis
	if v.app.currentTrie >= len(v.app.multiTrieResult.Tries) {
		return requests
	}

	currentTrieData := v.app.multiTrieResult.Tries[v.app.currentTrie]
	trieConfig := v.app.cfg.StaticTries[currentTrieData.Name]
	if trieConfig == nil {
		return requests
	}

	// Apply the same filters as the trie analysis
	var filteredRequests []ingestor.Request
	var startTime, endTime time.Time

	if trieConfig.StartTime != nil {
		startTime = *trieConfig.StartTime
	}
	if trieConfig.EndTime != nil {
		endTime = *trieConfig.EndTime
	}

	for _, r := range requests {
		// Apply time filtering
		if !startTime.IsZero() && r.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && r.Timestamp.After(endTime) {
			continue
		}

		// Apply regex filtering
		if !trieConfig.ShouldIncludeRequest(r) {
			continue
		}

		filteredRequests = append(filteredRequests, r)
	}

	return filteredRequests
}

// RenderCached generates the 2D visualization using optimized cache when possible
func (v *VisualizationView) RenderCached() {
	// Use legacy caching
	if v.app.cfg != nil {
		currentTrie := v.app.currentTrie
		cacheKey := currentTrie*1000 + v.currentClusterSet // Composite key: trie + cluster set

		if cachedText, exists := v.cachedRenderText[cacheKey]; exists {
			// Use cached render text
			v.view.SetText(cachedText)
			return
		}

		// Generate and cache the render text
		renderText := v.generateRenderTextOptimized()
		v.cachedRenderText[cacheKey] = renderText
		v.view.SetText(renderText)
	} else {
		// Legacy mode - no caching
		v.Render()
	}
}

// Render generates the 2D visualization
func (v *VisualizationView) Render() {
	renderText := v.generateRenderText()
	v.view.SetText(renderText)
}

// generateRenderTextOptimized creates optimized render text using cache
func (v *VisualizationView) generateRenderTextOptimized() string {
	// Use the new optimized cache when possible
	return v.generateRenderText()
}

// generateRenderText creates the render text (for caching)
func (v *VisualizationView) generateRenderText() string {
	var content strings.Builder

	// Always show header with cluster set info and traffic scope
	trafficScope := "All Traffic"
	if v.app.cfg != nil {
		trafficScope = "Trie-Specific Traffic"
	}

	if v.totalClusterSets > 0 && v.currentClusterSet < v.totalClusterSets {
		cluster := v.getCurrentClusterSet()
		if cluster != nil {
			content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - Cluster Set %d/%d - %s[white::-]\n",
				v.currentClusterSet+1, v.totalClusterSets, trafficScope))
			content.WriteString(fmt.Sprintf("[dim]Parameters: min_size=%d, depth=%d-%d, mean_diff=%.1f[white]\n",
				cluster.Parameters.MinClusterSize,
				cluster.Parameters.MinDepth,
				cluster.Parameters.MaxDepth,
				cluster.Parameters.MeanSubnetDifference))
		}
	} else if v.totalClusterSets > 0 {
		content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - %d cluster sets available - %s[white::-]\n",
			v.totalClusterSets, trafficScope))
	} else {
		content.WriteString(fmt.Sprintf("[white::b]Traffic Heatmap (/16 ranges) - No cluster sets - %s[white::-]\n", trafficScope))
	}

	content.WriteString("[dim]Legend: Traffic intensity - 10% resolution, black → white | [red]Red markers[white] = detected ranges[white]\n")
	content.WriteString("[dim]Navigate: ←→ change cluster set, ↑↓ scroll, 'r' results, 'q' quit[white]\n\n")

	if v.maxTraffic == 0 {
		content.WriteString("[yellow]Loading traffic data...[white]\n")
		content.WriteString("[dim]Traffic data will appear once analysis is complete.[white]\n")
	} else {
		// Build the heatmap visualization
		v.renderHeatmap(&content)
	}

	return content.String()
}

// renderHeatmap creates the ASCII-based heatmap
func (v *VisualizationView) renderHeatmap(content *strings.Builder) {
	// Create a compact visualization - show every 8th value for overview
	scale := 8 // More compact view to avoid scrolling

	// First pass: calculate all block traffic to find max block value
	var maxBlockTraffic uint32
	for a := 0; a < 256; a += scale {
		for b := 0; b < 256; b += scale {
			var blockTraffic uint32
			for aa := a; aa < a+scale && aa < 256; aa++ {
				for bb := b; bb < b+scale && bb < 256; bb++ {
					blockTraffic += v.trafficData[aa][bb]
				}
			}
			if blockTraffic > maxBlockTraffic {
				maxBlockTraffic = blockTraffic
			}
		}
	}

	// Simple scale line for A axis (first octet) - now on x-axis, 1.5x wider
	content.WriteString("    1") // Start at 1
	totalCols := 256 / scale
	scaleLineLength := totalCols*3 - 4 // Account for triple-width cells (3 chars each) minus space for numbers
	for i := 0; i < scaleLineLength; i++ {
		content.WriteString("─")
	}
	content.WriteString("256 A\n")

	// Render rows (B axis) with simple row numbering - now on y-axis, reversed for bottom-left origin
	totalRows := 256 / scale
	for rowIndex := 0; rowIndex < totalRows; rowIndex++ {
		// Calculate actual B value (reverse order: start from top = 256, go down to 1)
		b := 256 - scale - (rowIndex * scale)

		// Row labels for y-axis
		if rowIndex == 0 {
			content.WriteString("256│")
		} else if rowIndex == totalRows-1 {
			content.WriteString("1 │ ")
		} else {
			content.WriteString("  │ ")
		}

		for a := 0; a < 256; a += scale {
			// Sum traffic in this 8x8 block for better representation
			var blockTraffic uint32
			for aa := a; aa < a+scale && aa < 256; aa++ {
				for bb := b; bb < b+scale && bb < 256; bb++ {
					blockTraffic += v.trafficData[aa][bb]
				}
			}

			// Check if this block contains or is part of a clustered range (optimized)
			rangeMarker := v.getRangeMarkerOptimized(a, b, scale)

			if blockTraffic == 0 {
				if rangeMarker != "" {
					// Red dot on black background for no traffic, size based on coverage
					dotChar := strings.TrimSpace(rangeMarker) // Extract just the dot character
					content.WriteString(fmt.Sprintf("[black]█[red]%s[black]█[white]", dotChar))
				} else {
					// Black for no traffic - use triple width (3 characters)
					content.WriteString("[black]███[white]")
				}
			} else {
				// Calculate intensity based on block traffic relative to max block
				intensity := float64(blockTraffic) / float64(maxBlockTraffic)
				color, char := v.getTrafficColorAndChar(intensity)

				if rangeMarker != "" {
					// Red dot overlaid on traffic color, preserving background
					dotChar := strings.TrimSpace(rangeMarker) // Extract just the dot character
					content.WriteString(fmt.Sprintf("[%s]%s[red]%s[%s]%s[white]", color, char, dotChar, color, char))
				} else {
					// Normal traffic color
					content.WriteString(fmt.Sprintf("[%s]%s%s%s[white]", color, char, char, char))
				}
			}
		}

		// Right side labels
		if rowIndex == 0 {
			content.WriteString("│256\n")
		} else if rowIndex == totalRows-1 {
			content.WriteString(" │1\n")
		} else {
			content.WriteString(" │\n")
		}
	}

	// Add axis label
	content.WriteString("B\n")

	// Footer with color legend showing 10% intervals
	content.WriteString("\n[dim]Traffic Intensity (10% steps):[white]\n")
	content.WriteString("[black]███[white]=0% ")
	content.WriteString("[#202020]███[white]=0-10% ")
	content.WriteString("[#303030]███[white]=10-20% ")
	content.WriteString("[#404040]███[white]=20-30% ")
	content.WriteString("[#505050]███[white]=30-40%\n")
	content.WriteString("[#606060]███[white]=40-50% ")
	content.WriteString("[#808080]███[white]=50-60% ")
	content.WriteString("[#A0A0A0]███[white]=60-70% ")
	content.WriteString("[#C0C0C0]███[white]=70-80% ")
	content.WriteString("[#E0E0E0]███[white]=80-90% ")
	content.WriteString("[white]███[white]=90-100%\n")
	content.WriteString("\n[dim]Axes: A=First octet (horizontal), B=Second octet (vertical)[white]\n")
	content.WriteString("[dim]Range Markers: [red]●[white]=full coverage, [red]•[white]=partial, [red]·[white]=minimal[white]\n")

	// Show current cluster set ranges
	if v.totalClusterSets > 0 && v.currentClusterSet < v.totalClusterSets {
		clusterSet := v.getCurrentClusterSet()
		if clusterSet != nil && len(clusterSet.MergedRanges) > 0 {
			content.WriteString(fmt.Sprintf("\n[yellow]Cluster Set %d Detected Ranges:[white]\n", v.currentClusterSet+1))

			// Calculate total for this cluster set
			var totalRequests uint32
			for _, cidr := range clusterSet.MergedRanges {
				totalRequests += cidr.Requests
			}

			// Get unique IPs count depending on mode
			var uniqueIPs int
			if v.app.cfg != nil && len(v.app.jsonResult.Tries) > 0 && v.app.currentTrie < len(v.app.jsonResult.Tries) {
				// Multi-trie mode - use current trie's unique IPs
				uniqueIPs = v.app.jsonResult.Tries[v.app.currentTrie].Stats.UniqueIPs
			} else {
				// Legacy mode
				uniqueIPs = v.app.jsonResult.General.UniqueIPs
			}

			var totalPercentage float64
			if uniqueIPs > 0 {
				totalPercentage = float64(totalRequests) / float64(uniqueIPs) * 100
			}

			for _, cidr := range clusterSet.MergedRanges {
				content.WriteString(fmt.Sprintf("  • [red]%s[white]: %s requests (%.2f%%)\n",
					cidr.CIDR, formatNumber(int(cidr.Requests)), cidr.Percentage))
			}
			content.WriteString(fmt.Sprintf("[yellow]Total: %s requests (%.2f%%)[white]\n",
				formatNumber(int(totalRequests)), totalPercentage))
		} else {
			content.WriteString(fmt.Sprintf("\n[dim]Cluster Set %d: No ranges detected[white]\n", v.currentClusterSet+1))
		}
	}
}

// getRangeMarkerOptimized uses cache for fast marker lookup
func (v *VisualizationView) getRangeMarkerOptimized(a, b, scale int) string {
	if v.totalClusterSets == 0 || v.currentClusterSet >= v.totalClusterSets {
		return ""
	}

	// Get current cluster set
	clusterSet := v.getCurrentClusterSet()
	if clusterSet == nil {
		return ""
	}

	// Try to use cached visual block if cache is available
	if v.cache != nil {
		blockKey := BlockKey{A: a, B: b, Scale: scale}
		if visualBlock := v.cache.GetVisualBlock(clusterSet, blockKey); visualBlock != nil {
			return visualBlock.Marker
		}
	}

	// Fallback to computation
	return v.getRangeMarker(a, b, scale)
}

// getRangeMarker determines what marker to show for clustered ranges (legacy)
func (v *VisualizationView) getRangeMarker(a, b, scale int) string {
	if v.totalClusterSets == 0 || v.currentClusterSet >= v.totalClusterSets {
		return ""
	}

	// Get current cluster set
	clusterSet := v.getCurrentClusterSet()
	if clusterSet == nil {
		return ""
	}

	for _, cidrRange := range clusterSet.MergedRanges {
		_, ipNet, err := net.ParseCIDR(cidrRange.CIDR)
		if err != nil {
			continue
		}

		// Check if this block overlaps with the CIDR range
		marker := v.getBlockMarker(a, b, scale, ipNet)
		if marker != "" {
			return marker
		}
	}

	return ""
}

// getBlockMarker determines the marker for a block based on CIDR coverage
func (v *VisualizationView) getBlockMarker(blockA, blockB, scale int, ipNet *net.IPNet) string {
	// Check if the CIDR range has any overlap with this block's IP space
	blockOverlaps := v.cidrOverlapsBlock(blockA, blockB, scale, ipNet)

	if !blockOverlaps {
		return ""
	}

	// Calculate coverage percentage of this block by the CIDR range
	coverage := v.calculateBlockCoverage(blockA, blockB, scale, ipNet)

	// Return different dot sizes based on coverage
	return v.getDotSize(coverage)
}

// helper funcs
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// calculateBlockCoverage returns the max of the A-axis and B-axis overlap fraction
func (v *VisualizationView) calculateBlockCoverage(blockA, blockB, scale int, ipNet *net.IPNet) float64 {
	// 1) compute network start & broadcast IPs
	netIP := ipNet.IP.To4()
	mask := ipNet.Mask
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = netIP[i] | ^mask[i]
	}

	// 2) extract the 1st & 2nd-octet intervals of the CIDR
	netStartA, netStartB := int(netIP[0]), int(netIP[1])
	netEndA, netEndB := int(broadcast[0]), int(broadcast[1])

	// 3) block’s octet interval
	blockEndA := blockA + scale - 1
	blockEndB := blockB + scale - 1

	// 4) compute 1-D overlap lengths
	overlapALen := max(0, min(blockEndA, netEndA)-max(blockA, netStartA)+1)
	overlapBLen := max(0, min(blockEndB, netEndB)-max(blockB, netStartB)+1)

	// 5) fractional coverage on each axis
	covA := float64(overlapALen) / float64(scale)
	covB := float64(overlapBLen) / float64(scale)

	// 6) use the bigger one for your dot size
	return math.Max(covA, covB)
}

// cidrOverlapsBlock checks if a CIDR range overlaps with a visualization block
func (v *VisualizationView) cidrOverlapsBlock(blockA, blockB, scale int, ipNet *net.IPNet) bool {
	// blockA/B are actual octet starts
	octetStartA := blockA
	octetEndA := blockA + scale - 1
	octetStartB := blockB
	octetEndB := blockB + scale - 1

	// Check if any of the block's /16 positions lie within the CIDR
	for a := octetStartA; a <= octetEndA; a++ {
		for b := octetStartB; b <= octetEndB; b++ {
			if ipNet.Contains(net.IPv4(byte(a), byte(b), 0, 0)) {
				return true
			}
		}
	}

	// Also check if the CIDR's own base IP falls inside the block
	if cidrIP := ipNet.IP.To4(); cidrIP != nil {
		ca, cb := int(cidrIP[0]), int(cidrIP[1])
		if ca >= octetStartA && ca <= octetEndA && cb >= octetStartB && cb <= octetEndB {
			return true
		}
	}

	return false
}

// getDotSize returns appropriate dot based on coverage percentage
func (v *VisualizationView) getDotSize(coverage float64) string {
	switch {
	case coverage >= 0.8: // 80%+ coverage (51+ out of 64 /16 networks)
		return " ● " // Full coverage: large dot
	case coverage >= 0.2: // 20%+ coverage (13+ out of 64 /16 networks)
		return " • " // Partial coverage: medium dot
	case coverage > 0.0: // Any coverage (1+ out of 64 /16 networks)
		return " · " // Minimal coverage: small dot
	default:
		return "" // No coverage: no dot
	}
}

// getTrafficColorAndChar returns color and character for traffic intensity
// 10-level progression with 10% resolution: 0%, 10%, 20%, ..., 90%, 100%
func (v *VisualizationView) getTrafficColorAndChar(intensity float64) (string, string) {
	switch {
	case intensity >= 0.9:
		return "white", "█" // 90-100%: white
	case intensity >= 0.8:
		return "#E0E0E0", "█" // 80-90%: very light grey
	case intensity >= 0.7:
		return "#C0C0C0", "█" // 70-80%: light grey
	case intensity >= 0.6:
		return "#A0A0A0", "█" // 60-70%: medium-light grey
	case intensity >= 0.5:
		return "#808080", "█" // 50-60%: medium grey
	case intensity >= 0.4:
		return "#606060", "█" // 40-50%: medium-dark grey
	case intensity >= 0.3:
		return "#505050", "█" // 30-40%: dark grey
	case intensity >= 0.2:
		return "#404040", "█" // 20-30%: darker grey
	case intensity >= 0.1:
		return "#303030", "█" // 10-20%: very dark grey
	case intensity > 0:
		return "#202020", "█" // 0-10%: almost black
	default:
		return "black", "█" // 0%: black
	}
}

// NextClusterSet moves to the next cluster set
func (v *VisualizationView) NextClusterSet() {
	if v.totalClusterSets > 0 {
		v.currentClusterSet = (v.currentClusterSet + 1) % v.totalClusterSets
		v.RenderCached()
		// Update status bar to reflect new cluster set
		v.app.updateStatusBar()
	}
}

// PrevClusterSet moves to the previous cluster set
func (v *VisualizationView) PrevClusterSet() {
	if v.totalClusterSets > 0 {
		v.currentClusterSet = (v.currentClusterSet - 1 + v.totalClusterSets) % v.totalClusterSets
		v.RenderCached()
		// Update status bar to reflect new cluster set
		v.app.updateStatusBar()
	}
}

// GetView returns the tview component
func (v *VisualizationView) GetView() *tview.TextView {
	return v.view
}

// IsTrieCached returns true if the given trie index has cached traffic data
func (v *VisualizationView) IsTrieCached(trieIndex int) bool {
	_, exists := v.cachedTrafficData[trieIndex]
	return exists
}

// GetCachedTrieCount returns the number of tries that have been cached
func (v *VisualizationView) GetCachedTrieCount() int {
	return len(v.cachedTrafficData)
}
