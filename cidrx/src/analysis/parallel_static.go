package analysis

import (
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/logparser"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/trie"
)

// ParallelStaticFromConfig runs static analysis with parallel trie building
func ParallelStaticFromConfig(cfg *config.Config) (*output.JSONOutput, error) {
	result, _, err := ParallelStaticFromConfigWithRequests(cfg)
	return result, err
}

// ParallelStaticFromConfigWithRequests runs parallel static analysis
func ParallelStaticFromConfigWithRequests(cfg *config.Config) (*output.JSONOutput, []ingestor.Request, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	// Validate config (same as original)
	if cfg == nil {
		jsonOutput.AddError("config_error", "configuration is nil", 1)
		return jsonOutput, nil, fmt.Errorf("configuration is nil")
	}

	if cfg.Static == nil {
		jsonOutput.AddError("config_error", "static configuration section is missing", 1)
		return jsonOutput, nil, fmt.Errorf("static configuration section is missing")
	}

	if len(cfg.StaticTries) == 0 {
		jsonOutput.AddWarning("config_warning", "no static tries configured, analysis may have limited results", 1)
	}

	// Parse requests once
	logFormat := cfg.Static.LogFormat
	if logFormat == "" {
		logFormat = "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\""
	}

	// Create parser
	parser, err := logparser.NewParallelParser(logFormat)
	if err != nil {
		jsonOutput.AddError("parser_init", fmt.Sprintf("failed to create parallel parser: %v", err), 1)
		return jsonOutput, nil, err
	}

	parseStart := time.Now()
	requests, err := parser.ParseFileParallelChunked(cfg.Static.LogFile)
	parseDuration := time.Since(parseStart)
	if err != nil {
		jsonOutput.AddError("parse_file", fmt.Sprintf("failed to parse log file %s: %v", cfg.Static.LogFile, err), 1)
		return jsonOutput, nil, err
	}

	// Set general information
	jsonOutput.General.LogFile = cfg.Static.LogFile
	jsonOutput.General.TotalRequests = len(requests)
	jsonOutput.General.Parsing.DurationMS = parseDuration.Milliseconds()
	jsonOutput.General.Parsing.RatePerSecond = int64(float64(len(requests)) / parseDuration.Seconds())
	jsonOutput.General.Parsing.Format = logFormat

	if len(requests) == 0 {
		jsonOutput.AddWarning("empty_logfile", "No requests found in logfile", 1)
		return jsonOutput, requests, nil
	}

	// Load global User-Agent whitelist/blacklist patterns
	globalUserAgentWhitelistIPSet := make(map[string]bool)
	globalUserAgentBlacklistIPSet := make(map[string]bool)

	// Process tries in parallel
	var trieWG sync.WaitGroup
	var triesMutex sync.Mutex
	trieResults := make([]output.TrieResult, 0, len(cfg.StaticTries))

	// Channel for coordinating trie work
	type trieWork struct {
		name   string
		config *config.TrieConfig
	}

	trieWorkChan := make(chan trieWork, len(cfg.StaticTries))

	// Start trie workers (parallel trie building)
	numTrieWorkers := runtime.NumCPU()
	if len(cfg.StaticTries) < numTrieWorkers {
		numTrieWorkers = len(cfg.StaticTries)
	}

	for i := 0; i < numTrieWorkers; i++ {
		trieWG.Add(1)
		go func() {
			defer trieWG.Done()

			for work := range trieWorkChan {
				result := processTrieParallel(work.name, work.config, requests, cfg, jsonOutput)

				// Thread-safe append to results
				triesMutex.Lock()
				trieResults = append(trieResults, result)
				triesMutex.Unlock()
			}
		}()
	}

	// Send work to trie workers
	for trieName, trieConfig := range cfg.StaticTries {
		trieWorkChan <- trieWork{name: trieName, config: trieConfig}
	}
	close(trieWorkChan)

	// Wait for all tries to complete
	trieWG.Wait()

	// Sort results by name for consistency with sequential version
	sort.Slice(trieResults, func(i, j int) bool {
		return trieResults[i].Name < trieResults[j].Name
	})

	// Add results to output
	jsonOutput.Tries = trieResults

	// Load and store global whitelist/blacklist IPs
	if err := loadGlobalUserAgentLists(cfg, jsonOutput, globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet); err != nil {
		jsonOutput.AddWarning("useragent_lists_load", fmt.Sprintf("failed to load User-Agent lists: %v", err), 1)
	}

	// Jail processing (same as original)
	if err := processJailActions(cfg, jsonOutput, globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet); err != nil {
		jsonOutput.AddWarning("jail_processing", fmt.Sprintf("Jail processing failed: %v", err), 1)
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, requests, nil
}

// processTrieParallel processes a single trie with parallel insertion
func processTrieParallel(trieName string, trieConfig *config.TrieConfig, requests []ingestor.Request,
	cfg *config.Config, jsonOutput *output.JSONOutput) output.TrieResult {

	insertStart := time.Now()

	trieResult := output.TrieResult{
		Name:       trieName,
		Parameters: output.TrieParameters{},
		Stats:      output.TrieStats{},
		Data:       []output.ClusterResult{},
	}

	if trieConfig == nil {
		jsonOutput.AddWarning("config_warning", fmt.Sprintf("trie configuration '%s' is nil, skipping", trieName), 1)
		return trieResult
	}

	// Warn if time parsing failed
	if trieConfig.StartTimeRaw != "" && trieConfig.StartTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse startTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.StartTimeRaw), 1)
	}
	if trieConfig.EndTimeRaw != "" && trieConfig.EndTime == nil {
		jsonOutput.AddWarning("invalid_time_format",
			fmt.Sprintf("Trie '%s': Failed to parse endTime '%s' - expected RFC3339 format (e.g., 2025-01-01T00:00:00Z)",
				trieName, trieConfig.EndTimeRaw), 1)
	}

	// Warn if endTime is before startTime (invalid time range)
	if trieConfig.StartTime != nil && trieConfig.EndTime != nil && trieConfig.EndTime.Before(*trieConfig.StartTime) {
		jsonOutput.AddWarning("invalid_time_range",
			fmt.Sprintf("Trie '%s': endTime (%s) is before startTime (%s) - no requests can match this range",
				trieName, trieConfig.EndTime.Format(time.RFC3339), trieConfig.StartTime.Format(time.RFC3339)), 1)
	}

	// Set CidrRanges after null check
	trieResult.Parameters.CidrRanges = trieConfig.CidrRanges

	// Create parallel trie
	trieInstance := trie.NewParallelTrie()

	// Apply filtering and collect IPs for parallel insertion
	var startTime, endTime time.Time
	if trieConfig.StartTime != nil {
		startTime = *trieConfig.StartTime
	}
	if trieConfig.EndTime != nil {
		endTime = *trieConfig.EndTime
	}

	// Add regex filters to parameters if they exist
	if trieConfig.UserAgentRegex != "" {
		trieResult.Parameters.UserAgentRegex = &trieConfig.UserAgentRegex
	}
	if trieConfig.EndpointRegex != "" {
		trieResult.Parameters.EndpointRegex = &trieConfig.EndpointRegex
	}

	// Add time range to parameters if set
	if !startTime.IsZero() || !endTime.IsZero() {
		trieResult.Parameters.TimeRange = &output.TimeRange{
			Start: startTime,
			End:   endTime,
		}
	}

	// Add UseForJail configuration if set
	if len(trieConfig.UseForJail) > 0 {
		trieResult.Parameters.UseForJail = trieConfig.UseForJail
	}

	// Create User-Agent matcher
	userAgentMatcher, err := cfg.CreateUserAgentMatcher()
	if err != nil {
		jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("failed to create User-Agent matcher: %v", err), 1)
		userAgentMatcher = nil
	}

	// Filter requests and collect IPs for batch insertion
	var filteredRequests []ingestor.Request
	var ipsToInsert []net.IP

	// User-Agent tracking
	userAgentWhitelistIPs := make([]string, 0)
	userAgentBlacklistIPs := make([]string, 0)
	userAgentWhitelistIPSet := make(map[string]bool)
	userAgentBlacklistIPSet := make(map[string]bool)

	// Check if we have any filters that require per-request processing
	// Only consider User-Agent matcher a filter if it actually has patterns
	hasUserAgentFilters := userAgentMatcher != nil && userAgentMatcher.Count() > 0
	hasFilters := hasUserAgentFilters ||
		trieConfig.UserAgentRegex != "" ||
		trieConfig.EndpointRegex != "" ||
		!startTime.IsZero() ||
		!endTime.IsZero()

	// Track invalid IPs for warning
	var invalidIPCount int

	// Fast path for unfiltered data: use sorted insertion optimization
	if !hasFilters {
		// Convert all IPs to uint32 for sorting and counting, filtering out invalid IPs
		ipUints := make([]uint32, 0, len(requests))
		for _, r := range requests {
			// Skip nil IPs (failed to parse)
			if r.IP == nil {
				invalidIPCount++
				continue
			}
			ipUint := iputils.IPToUint32(r.IP)
			// Skip 0.0.0.0 (invalid or failed conversion)
			if ipUint == 0 {
				invalidIPCount++
				continue
			}
			ipUints = append(ipUints, ipUint)
			filteredRequests = append(filteredRequests, r)
		}

		// Sort for optimal cache locality and count identical IPs
		sort.Slice(ipUints, func(i, j int) bool {
			return ipUints[i] < ipUints[j]
		})

		// Use optimized sorted insertion
		trieInstance.BatchInsertSortedUint32(ipUints)
	} else {
		// Adaptive filtering: use concurrent processing only when complex patterns justify overhead
		usesConcurrency := len(requests) > 50000 && hasFilters

		if usesConcurrency {
			// Concurrent filtering for large datasets with complex patterns
			err = processRequestsConcurrentlyParallel(
				requests, trieConfig, startTime, endTime,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&userAgentWhitelistIPs, &userAgentBlacklistIPs,
				&filteredRequests, &ipsToInsert, &invalidIPCount)
			if err != nil {
				jsonOutput.AddError("concurrent_filtering", fmt.Sprintf("failed to process requests concurrently: %v", err), 1)
			}
		} else {
			// Sequential filtering for simple cases (faster for small datasets)
			processRequestsSequentiallyParallel(
				requests, trieConfig, startTime, endTime,
				userAgentMatcher,
				userAgentWhitelistIPSet, userAgentBlacklistIPSet,
				&userAgentWhitelistIPs, &userAgentBlacklistIPs,
				&filteredRequests, &ipsToInsert, &invalidIPCount)
		}

		// Parallel batch insertion of all IPs (only for filtered data)
		if len(ipsToInsert) > 0 {
			trieInstance.BatchParallelInsert(ipsToInsert, runtime.NumCPU())
		}
	}

	insertDuration := time.Since(insertStart)

	// Add warning if invalid IPs were skipped
	if invalidIPCount > 0 {
		percentage := float64(invalidIPCount) / float64(len(requests)) * 100
		jsonOutput.AddWarning("invalid_ips_skipped",
			fmt.Sprintf("%d requests (%.1f%%) had invalid/missing IPs (nil or 0.0.0.0) and were skipped - check log format", invalidIPCount, percentage), 1)
	}

	// Set trie stats
	trieResult.Stats = output.TrieStats{
		TotalRequestsAfterFiltering: len(filteredRequests),
		UniqueIPs:                   int(trieInstance.ParallelCountAll()),
		SkippedInvalidIPs:           invalidIPCount,
		InsertTimeMS:                insertDuration.Milliseconds(),
	}

	// Warn if time filter resulted in zero requests (non-overlapping time range)
	if len(filteredRequests) == 0 && (!startTime.IsZero() || !endTime.IsZero()) {
		var timeRangeStr string
		if !startTime.IsZero() && !endTime.IsZero() {
			timeRangeStr = fmt.Sprintf("%s to %s", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
		} else if !startTime.IsZero() {
			timeRangeStr = fmt.Sprintf("after %s", startTime.Format(time.RFC3339))
		} else {
			timeRangeStr = fmt.Sprintf("before %s", endTime.Format(time.RFC3339))
		}
		jsonOutput.AddWarning("time_filter_no_results",
			fmt.Sprintf("Trie '%s': Time filter (%s) resulted in 0 requests - the time range may not overlap with log data",
				trieName, timeRangeStr), 1)
	}

	// CIDR range analysis (same as original but with parallel trie)
	if len(trieConfig.CidrRanges) > 0 {
		for _, cidrRange := range trieConfig.CidrRanges {
			count, err := trieInstance.ParallelCountInRange(cidrRange)
			if err != nil {
				jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range '%s': %v", cidrRange, err), 1)
				continue
			}

			var percentage float64
			if trieInstance.ParallelCountAll() > 0 {
				percentage = float64(count) / float64(trieInstance.ParallelCountAll()) * 100
			}
			trieResult.Stats.CIDRAnalysis = append(trieResult.Stats.CIDRAnalysis, output.CIDRRange{
				CIDR:       cidrRange,
				Requests:   count,
				Percentage: percentage,
			})
		}
	}

	// Clustering (same as original but with parallel trie)
	processClustering(trieConfig, trieInstance.Trie, jsonOutput, &trieResult)

	// Store User-Agent results in additional info if needed
	// Note: These would be stored elsewhere in the JSON output structure

	return trieResult
}

// Helper functions (copied from original with minor modifications for parallel trie)
func loadGlobalUserAgentLists(cfg *config.Config, jsonOutput *output.JSONOutput,
	globalWhitelistIPSet, globalBlacklistIPSet map[string]bool) error {
	// Process jail with whitelist/blacklist if configured
	if cfg.Global != nil && cfg.Global.JailFile != "" && cfg.Global.BanFile != "" {
		// Always process jail to generate ban file from existing jail + new detections
		err := ProcessJailWithWhitelist(cfg, jsonOutput)
		if err != nil {
			jsonOutput.AddError("jail_processing", fmt.Sprintf("failed to process jail with whitelist/blacklist: %v", err), 1)
		}
	}
	return nil
}

func processJailActions(cfg *config.Config, jsonOutput *output.JSONOutput,
	globalWhitelistIPSet, globalBlacklistIPSet map[string]bool) error {
	// This function is now handled in loadGlobalUserAgentLists to maintain compatibility
	return nil
}

// processRequestsConcurrentlyParallel implements high-performance concurrent filtering
func processRequestsConcurrentlyParallel(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	filteredRequests *[]ingestor.Request,
	ipsToInsert *[]net.IP,
	invalidIPCount *int) error {

	// Determine optimal worker count for filtering
	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8 // Cap at 8 to reduce contention and mutex overhead
	}
	if len(requests) < 50000 {
		numWorkers = 4 // Use fewer workers for smaller datasets
	}

	// Pre-allocate result slice with estimated capacity
	resultCapacity := len(requests) / 2 // Estimate 50% will pass filtering
	if resultCapacity < 1000 {
		resultCapacity = 1000
	}

	// Channels for work distribution - smaller buffers reduce memory overhead
	requestChan := make(chan parallelRequestChunk, numWorkers)
	resultChan := make(chan parallelFilterResult, numWorkers*4)

	// Worker synchronization
	var wg sync.WaitGroup

	// Start filter workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parallelFilterWorker(requestChan, resultChan, trieConfig, startTime, endTime,
				userAgentMatcher)
		}()
	}

	// Start result collector
	var collectorWG sync.WaitGroup

	// Collect User-Agent whitelist/blacklist results
	var whitelistMutex, blacklistMutex sync.Mutex

	// Track invalid IPs in collector
	var localInvalidCount int

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for result := range resultChan {
			if result.shouldInclude {
				// Skip nil IPs (failed to parse)
				if result.request.IP == nil {
					localInvalidCount++
					continue
				}
				// Skip 0.0.0.0 (invalid or failed conversion)
				if iputils.IPToUint32(result.request.IP) == 0 {
					localInvalidCount++
					continue
				}
				*filteredRequests = append(*filteredRequests, result.request)
				*ipsToInsert = append(*ipsToInsert, result.request.IP)
			}

			// Collect User-Agent whitelist IPs (only if IP is valid)
			if result.isWhitelistedUA && result.request.IP != nil {
				whitelistMutex.Lock()
				ipStr := result.request.IP.String()
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
				}
				whitelistMutex.Unlock()
			}

			// Collect User-Agent blacklist IPs (only if IP is valid)
			if result.isBlacklistedUA && result.request.IP != nil {
				blacklistMutex.Lock()
				ipStr := result.request.IP.String()
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
				}
				blacklistMutex.Unlock()
			}
		}
		// Update the shared invalid count
		*invalidIPCount += localInvalidCount
	}()

	// Distribute work in larger chunks to reduce overhead
	chunkSize := len(requests) / (numWorkers * 2) // 2 chunks per worker for better efficiency
	if chunkSize < 5000 {
		chunkSize = 5000 // Larger minimum chunk size
	}
	if chunkSize > 50000 {
		chunkSize = 50000 // Larger maximum chunk size
	}

	for i := 0; i < len(requests); i += chunkSize {
		end := i + chunkSize
		if end > len(requests) {
			end = len(requests)
		}

		requestChan <- parallelRequestChunk{
			requests: requests[i:end],
			start:    i,
			end:      end,
		}
	}
	close(requestChan)

	// Wait for all workers to complete
	wg.Wait()
	close(resultChan)

	// Wait for result collection to complete
	collectorWG.Wait()

	return nil
}

// processRequestsSequentiallyParallel provides optimized sequential processing for simple filtering cases
func processRequestsSequentiallyParallel(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	filteredRequests *[]ingestor.Request,
	ipsToInsert *[]net.IP,
	invalidIPCount *int) {

	// Single pass through requests with optimized filtering
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

		// Skip nil IPs (failed to parse)
		if r.IP == nil {
			*invalidIPCount++
			continue
		}

		// Skip 0.0.0.0 (invalid or failed conversion)
		if iputils.IPToUint32(r.IP) == 0 {
			*invalidIPCount++
			continue
		}

		// Only convert IP to string if we need it for User-Agent pattern processing
		var ipStr string
		var ipStrComputed bool
		isWhitelistedUA := false
		isBlacklistedUA := false

		// Check User-Agent patterns using ultra-fast exact matching
		if userAgentMatcher != nil {
			uaResult := userAgentMatcher.CheckUserAgent(r.UserAgent)
			isWhitelistedUA = (uaResult == cidr.UserAgentWhitelist)
			isBlacklistedUA = (uaResult == cidr.UserAgentBlacklist)

			if isWhitelistedUA {
				if !ipStrComputed {
					ipStr = r.IP.String()
					ipStrComputed = true
				}
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
				}
			}

			if isBlacklistedUA {
				if !ipStrComputed {
					ipStr = r.IP.String()
					ipStrComputed = true
				}
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
				}
			}
		}

		// Include in trie if not whitelisted by User-Agent
		if !isWhitelistedUA {
			*filteredRequests = append(*filteredRequests, r)
			*ipsToInsert = append(*ipsToInsert, r.IP)
		}
	}
}

func processClustering(trieConfig *config.TrieConfig, trieInstance *trie.Trie,
	jsonOutput *output.JSONOutput, trieResult *output.TrieResult) {
	// Implementation same as original
	if len(trieConfig.ClusterArgSets) == 0 {
		return
	}

	for _, argSet := range trieConfig.ClusterArgSets {
		if argSet.MinDepth > argSet.MaxDepth {
			jsonOutput.AddError("invalid_depth_params",
				fmt.Sprintf("minDepth (%d) must be <= maxDepth (%d)", argSet.MinDepth, argSet.MaxDepth), 1)
			continue
		}

		clusterStart := time.Now()
		cidrs := trieInstance.CollectCIDRs(argSet.MinClusterSize, argSet.MinDepth, argSet.MaxDepth, argSet.MeanSubnetDifference)
		clusterDuration := time.Since(clusterStart)

		clusterResult := output.ClusterResult{
			Parameters: output.ClusterParameters{
				MinClusterSize:       argSet.MinClusterSize,
				MinDepth:             argSet.MinDepth,
				MaxDepth:             argSet.MaxDepth,
				MeanSubnetDifference: argSet.MeanSubnetDifference,
			},
			ExecutionTimeUS: clusterDuration.Microseconds(),
			DetectedRanges:  []output.CIDRRange{},
			MergedRanges:    []output.CIDRRange{},
		}

		// Parse CIDRs once for reuse across operations
		var cidrIPNets []*net.IPNet
		totalUniqueIPs := float64(trieInstance.CountAll())

		for _, cidrStr := range cidrs {
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				jsonOutput.AddWarning("cidr_parse_error",
					fmt.Sprintf("error parsing CIDR %s: %v", cidrStr, err), 1)
				continue
			}
			cidrIPNets = append(cidrIPNets, ipNet)

			// Use IPNet-native count function for speed
			count := trieInstance.CountInRangeIPNet(ipNet)
			var percentage float64
			if totalUniqueIPs > 0 {
				percentage = float64(count) / totalUniqueIPs * 100
			}

			clusterResult.DetectedRanges = append(clusterResult.DetectedRanges, output.CIDRRange{
				CIDR:       cidrStr,
				Requests:   count,
				Percentage: percentage,
			})
		}

		// Use IPNet-native merge function to avoid re-parsing
		mergedIPNets := cidr.MergeIPNets(cidrIPNets)
		for _, mergedIPNet := range mergedIPNets {
			count := trieInstance.CountInRangeIPNet(mergedIPNet)
			var percentage float64
			if totalUniqueIPs > 0 {
				percentage = float64(count) / totalUniqueIPs * 100
			}

			clusterResult.MergedRanges = append(clusterResult.MergedRanges, output.CIDRRange{
				CIDR:       mergedIPNet.String(),
				Requests:   count,
				Percentage: percentage,
			})
		}

		trieResult.Data = append(trieResult.Data, clusterResult)
	}
}

// parallelRequestChunk represents a chunk of requests for parallel processing
type parallelRequestChunk struct {
	requests []ingestor.Request
	start    int
	end      int
}

// parallelFilterResult represents the result of filtering a single request
type parallelFilterResult struct {
	request         ingestor.Request
	shouldInclude   bool
	isWhitelistedUA bool
	isBlacklistedUA bool
}

// parallelFilterWorker processes request chunks concurrently
func parallelFilterWorker(
	requestChan <-chan parallelRequestChunk,
	resultChan chan<- parallelFilterResult,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher) {

	for chunk := range requestChan {
		for _, r := range chunk.requests {
			result := parallelFilterResult{
				request: r,
			}

			// Apply time filtering
			if !startTime.IsZero() && r.Timestamp.Before(startTime) {
				resultChan <- result
				continue
			}
			if !endTime.IsZero() && r.Timestamp.After(endTime) {
				resultChan <- result
				continue
			}

			// Apply regex filtering (this is expensive and benefits from concurrency)
			if !trieConfig.ShouldIncludeRequest(r) {
				resultChan <- result
				continue
			}

			// Check User-Agent patterns using ultra-fast exact matching
			if userAgentMatcher != nil {
				uaResult := userAgentMatcher.CheckUserAgent(r.UserAgent)
				result.isWhitelistedUA = (uaResult == cidr.UserAgentWhitelist)
				result.isBlacklistedUA = (uaResult == cidr.UserAgentBlacklist)
			}

			// Include in results if not whitelisted by User-Agent
			if !result.isWhitelistedUA {
				result.shouldInclude = true
			}

			resultChan <- result
		}
	}
}
