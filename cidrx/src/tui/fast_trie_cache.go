package tui

import (
	"sync"
	"time"

	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/output"
)

// FastTrieCache holds ALL trie data in RAM for instant switching
// This eliminates any conversion or processing delays during trie switching
type FastTrieCache struct {
	mu sync.RWMutex

	// Pre-computed data for instant access
	legacyData      map[int]*output.JSONOutput // Converted legacy format per trie
	summaryTexts    map[int]string             // Pre-rendered summary text per trie
	clusterTexts    map[int]string             // Pre-rendered clustering text per trie
	cidrTexts       map[int]string             // Pre-rendered CIDR text per trie
	diagnosticTexts map[int]string             // Pre-rendered diagnostic text per trie

	// Visualization data for instant switching
	trafficMatrixes map[int][256][256]uint32 // Traffic data per trie
	maxTraffics     map[int]uint32           // Max traffic per trie
	vizRenderCache  map[int]map[int]string   // Visualization render cache per trie per cluster set

	// Metadata
	totalTries    int
	cacheComplete bool
	lastUpdated   time.Time

	// Performance metrics
	cacheHits   int64
	cacheMisses int64
}

// NewFastTrieCache creates a new fast trie cache
func NewFastTrieCache() *FastTrieCache {
	return &FastTrieCache{
		legacyData:      make(map[int]*output.JSONOutput),
		summaryTexts:    make(map[int]string),
		clusterTexts:    make(map[int]string),
		cidrTexts:       make(map[int]string),
		diagnosticTexts: make(map[int]string),
		trafficMatrixes: make(map[int][256][256]uint32),
		maxTraffics:     make(map[int]uint32),
		vizRenderCache:  make(map[int]map[int]string),
	}
}

// PreCacheAllTries processes and caches ALL trie data upfront for instant switching
func (ftc *FastTrieCache) PreCacheAllTries(app *App, multiResult *output.JSONOutput, requests []ingestor.Request) {
	if multiResult == nil || len(multiResult.Tries) == 0 {
		return
	}

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.totalTries = len(multiResult.Tries)
	ftc.cacheComplete = false

	// Process each trie and cache everything
	for trieIndex := 0; trieIndex < len(multiResult.Tries); trieIndex++ {
		// 1. Convert to legacy format and cache
		legacyData := app.convertTrieToLegacy(trieIndex)
		if legacyData != nil {
			ftc.legacyData[trieIndex] = legacyData

			// 2. Pre-render all text components
			ftc.preRenderTrieTexts(trieIndex, legacyData, app)

			// 3. Pre-process traffic data for visualization
			ftc.preProcessTrafficData(trieIndex, requests, multiResult.Tries[trieIndex], app)

			// 4. Pre-render visualization for all cluster sets (disabled for now to avoid nil pointer issues)
			// ftc.preRenderVisualization(trieIndex, legacyData, app)
		}
	}

	ftc.cacheComplete = true
	ftc.lastUpdated = time.Now()
}

// PreCacheSingleTrie caches a specific trie with priority
func (ftc *FastTrieCache) PreCacheSingleTrie(app *App, trieIndex int, multiResult *output.JSONOutput, requests []ingestor.Request) bool {
	if multiResult == nil || trieIndex >= len(multiResult.Tries) {
		return false
	}

	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	// Convert to legacy format and cache
	legacyData := app.convertTrieToLegacy(trieIndex)
	if legacyData != nil {
		ftc.legacyData[trieIndex] = legacyData

		// Pre-render all text components
		ftc.preRenderTrieTexts(trieIndex, legacyData, app)

		// Pre-process traffic data for visualization
		ftc.preProcessTrafficData(trieIndex, requests, multiResult.Tries[trieIndex], app)

		return true
	}
	return false
}

// preRenderTrieTexts pre-renders all text components for a trie
func (ftc *FastTrieCache) preRenderTrieTexts(trieIndex int, legacyData *output.JSONOutput, app *App) {
	// Temporarily set the app's jsonResult to render texts
	originalResult := app.jsonResult
	app.jsonResult = legacyData

	// Pre-render summary text
	ftc.summaryTexts[trieIndex] = app.buildSummaryText()

	// Pre-render clustering text
	ftc.clusterTexts[trieIndex] = app.buildClusteringText()

	// Pre-render CIDR analysis text
	ftc.cidrTexts[trieIndex] = app.buildCidrAnalysisText()

	// Pre-render diagnostics text
	ftc.diagnosticTexts[trieIndex] = app.buildDiagnosticsText()

	// Restore original result
	app.jsonResult = originalResult
}

// preProcessTrafficData pre-processes traffic data for visualization
func (ftc *FastTrieCache) preProcessTrafficData(trieIndex int, requests []ingestor.Request, trieResult output.TrieResult, app *App) {
	var trafficMatrix [256][256]uint32
	var maxTraffic uint32

	// Apply trie-specific filters
	filteredRequests := ftc.getTrieSpecificRequests(requests, trieResult, app)

	// Build traffic matrix
	for _, req := range filteredRequests {
		ip := req.IP.To4()
		if ip == nil {
			continue
		}
		a, b := ip[0], ip[1]
		trafficMatrix[a][b]++
		if trafficMatrix[a][b] > maxTraffic {
			maxTraffic = trafficMatrix[a][b]
		}
	}

	ftc.trafficMatrixes[trieIndex] = trafficMatrix
	ftc.maxTraffics[trieIndex] = maxTraffic
}

// getTrieSpecificRequests filters requests for a specific trie
func (ftc *FastTrieCache) getTrieSpecificRequests(requests []ingestor.Request, trieResult output.TrieResult, app *App) []ingestor.Request {
	// If no config or filters, return all requests
	if app.cfg == nil {
		return requests
	}

	// Find the trie config
	trieConfig := app.cfg.StaticTries[trieResult.Name]
	if trieConfig == nil {
		return requests
	}

	// Apply filters
	var filteredRequests []ingestor.Request
	for _, r := range requests {
		// Apply time filtering
		if trieConfig.StartTime != nil && r.Timestamp.Before(*trieConfig.StartTime) {
			continue
		}
		if trieConfig.EndTime != nil && r.Timestamp.After(*trieConfig.EndTime) {
			continue
		}

		// Apply regex filtering (if ShouldIncludeRequest method exists)
		if !trieConfig.ShouldIncludeRequest(r) {
			continue
		}

		filteredRequests = append(filteredRequests, r)
	}

	return filteredRequests
}

// GetLegacyData returns cached legacy data for instant access
func (ftc *FastTrieCache) GetLegacyData(trieIndex int) (*output.JSONOutput, bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	data, exists := ftc.legacyData[trieIndex]
	if exists {
		ftc.cacheHits++
	} else {
		ftc.cacheMisses++
	}
	return data, exists
}

// GetPreRenderedTexts returns all pre-rendered texts for instant display
func (ftc *FastTrieCache) GetPreRenderedTexts(trieIndex int) (summary, clustering, cidr, diagnostics string, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	summary, summaryExists := ftc.summaryTexts[trieIndex]
	clustering, clusteringExists := ftc.clusterTexts[trieIndex]
	cidr, cidrExists := ftc.cidrTexts[trieIndex]
	diagnostics, diagnosticsExists := ftc.diagnosticTexts[trieIndex]

	exists = summaryExists && clusteringExists && cidrExists && diagnosticsExists
	if exists {
		ftc.cacheHits++
	} else {
		ftc.cacheMisses++
	}

	return summary, clustering, cidr, diagnostics, exists
}

// GetTrafficData returns cached traffic data for instant visualization
func (ftc *FastTrieCache) GetTrafficData(trieIndex int) (trafficMatrix [256][256]uint32, maxTraffic uint32, exists bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	trafficMatrix, matrixExists := ftc.trafficMatrixes[trieIndex]
	maxTraffic, maxExists := ftc.maxTraffics[trieIndex]

	exists = matrixExists && maxExists
	if exists {
		ftc.cacheHits++
	} else {
		ftc.cacheMisses++
	}

	return trafficMatrix, maxTraffic, exists
}

// GetVisualizationRender returns pre-rendered visualization text
func (ftc *FastTrieCache) GetVisualizationRender(trieIndex, clusterSetIndex int) (string, bool) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	if trieCache, trieExists := ftc.vizRenderCache[trieIndex]; trieExists {
		if renderText, renderExists := trieCache[clusterSetIndex]; renderExists {
			ftc.cacheHits++
			return renderText, true
		}
	}

	ftc.cacheMisses++
	return "", false
}

// IsCacheComplete returns true if all tries have been cached
func (ftc *FastTrieCache) IsCacheComplete() bool {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()
	return ftc.cacheComplete
}

// GetCacheStats returns cache performance statistics
func (ftc *FastTrieCache) GetCacheStats() (totalTries int, cacheComplete bool, hits, misses int64, hitRatio float64) {
	ftc.mu.RLock()
	defer ftc.mu.RUnlock()

	totalTries = ftc.totalTries
	cacheComplete = ftc.cacheComplete
	hits = ftc.cacheHits
	misses = ftc.cacheMisses

	if hits+misses > 0 {
		hitRatio = float64(hits) / float64(hits+misses) * 100
	}

	return
}

// Clear clears all cached data
func (ftc *FastTrieCache) Clear() {
	ftc.mu.Lock()
	defer ftc.mu.Unlock()

	ftc.legacyData = make(map[int]*output.JSONOutput)
	ftc.summaryTexts = make(map[int]string)
	ftc.clusterTexts = make(map[int]string)
	ftc.cidrTexts = make(map[int]string)
	ftc.diagnosticTexts = make(map[int]string)
	ftc.trafficMatrixes = make(map[int][256][256]uint32)
	ftc.maxTraffics = make(map[int]uint32)
	ftc.vizRenderCache = make(map[int]map[int]string)

	ftc.totalTries = 0
	ftc.cacheComplete = false
	ftc.cacheHits = 0
	ftc.cacheMisses = 0
}
