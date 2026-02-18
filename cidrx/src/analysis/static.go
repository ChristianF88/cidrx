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
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/logparser"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/pools"
	"github.com/ChristianF88/cidrx/trie"
)

// StaticFromConfig runs static analysis and returns the result
func StaticFromConfig(cfg *config.Config) (*output.JSONOutput, error) {
	result, _, err := StaticFromConfigWithRequests(cfg)
	return result, err
}

// StaticFromConfigWithRequests runs static analysis and returns both the result and parsed requests
func StaticFromConfigWithRequests(cfg *config.Config) (*output.JSONOutput, []ingestor.Request, error) {
	analysisStart := time.Now()
	jsonOutput := output.NewJSONOutput("static", analysisStart)

	// Validate config
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

	// Use the log format from config
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

	// Check if any trie config requires string fields (URI/UserAgent) or non-IP fields
	// If none do, skip allocations for dramatically fewer allocs per line
	needsStringFields := false
	needsNonIPFields := false
	userAgentMatcherForCheck, _ := cfg.CreateUserAgentMatcher()
	hasGlobalUAFilters := userAgentMatcherForCheck != nil && userAgentMatcherForCheck.Count() > 0
	for _, tc := range cfg.StaticTries {
		if tc == nil {
			continue
		}
		if hasGlobalUAFilters || tc.UserAgentRegex != "" || tc.EndpointRegex != "" {
			needsStringFields = true
			needsNonIPFields = true
		}
		if tc.StartTime != nil || tc.EndTime != nil {
			needsNonIPFields = true
		}
	}
	parser.SkipStringFields = !needsStringFields
	parser.SkipNonIPFields = !needsNonIPFields

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

	// Get sorted trie names for deterministic ordering
	var trieNames []string
	for trieName := range cfg.StaticTries {
		trieNames = append(trieNames, trieName)
	}
	sort.Strings(trieNames)

	// Accumulate User-Agent derived IPs across all tries
	globalUserAgentWhitelistIPSet := make(map[string]bool)
	globalUserAgentBlacklistIPSet := make(map[string]bool)

	// Process each trie configuration in sorted order
	for _, trieName := range trieNames {
		trieConfig := cfg.StaticTries[trieName]
		// Skip if trieConfig is nil
		if trieConfig == nil {
			jsonOutput.AddWarning("config_warning", fmt.Sprintf("trie configuration '%s' is nil, skipping", trieName), 1)
			continue
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

		// Create a new trie for this configuration
		trieInstance := trie.NewTrie()

		// Apply filtering and time range - use pooled slice
		filteredRequests := pools.Pools.GetRequestSlice()
		defer pools.Pools.ReturnRequestSlice(filteredRequests)
		var startTime, endTime time.Time

		if trieConfig.StartTime != nil {
			startTime = *trieConfig.StartTime
		}
		if trieConfig.EndTime != nil {
			endTime = *trieConfig.EndTime
		}

		// Create fast User-Agent exact matcher once per trie
		userAgentMatcher, err := cfg.CreateUserAgentMatcher()
		if err != nil {
			jsonOutput.AddError("useragent_matcher_create", fmt.Sprintf("failed to create User-Agent matcher: %v", err), 1)
			userAgentMatcher = nil // Continue without User-Agent filtering
		}

		// Extract IPs from User-Agent whitelist/blacklist for this trie's filtered requests - use pooled slices
		userAgentWhitelistIPs := pools.Pools.GetStringSlice()
		defer pools.Pools.ReturnStringSlice(userAgentWhitelistIPs)
		userAgentBlacklistIPs := pools.Pools.GetStringSlice()
		defer pools.Pools.ReturnStringSlice(userAgentBlacklistIPs)

		// Set up trie result
		trieResult := output.TrieResult{
			Name: trieName,
			Parameters: output.TrieParameters{
				CidrRanges: trieConfig.CidrRanges,
			},
			Data: []output.ClusterResult{},
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

		// Start timing for filtering and insertion
		insertStart := time.Now()

		// Concurrent filtering for maximum performance - use pooled maps
		userAgentWhitelistIPSet := pools.Pools.GetStringMap()
		defer pools.Pools.ReturnStringMap(userAgentWhitelistIPSet)
		userAgentBlacklistIPSet := pools.Pools.GetStringMap()
		defer pools.Pools.ReturnStringMap(userAgentBlacklistIPSet)

		// Check if we have any filters that require per-request processing
		// Only consider User-Agent matcher a filter if it actually has patterns
		hasUserAgentFilters := userAgentMatcher != nil && userAgentMatcher.Count() > 0
		hasFilters := hasUserAgentFilters ||
			trieConfig.UserAgentRegex != "" ||
			trieConfig.EndpointRegex != "" ||
			!startTime.IsZero() ||
			!endTime.IsZero()

		// Fast path for unfiltered data: use sorted insertion optimization
		if !hasFilters {
			// No filtering needed: all requests pass through
			filteredRequests = requests

			// Use IPUint32 directly — no conversion needed (parsed directly to uint32)
			ipUints := make([]uint32, len(requests))
			for i := range requests {
				ipUints[i] = requests[i].IPUint32
			}

			// Radix sort: O(n) vs sort.Slice O(n log n) — 10-15x faster for large arrays
			iputils.RadixSortUint32(ipUints)

			// Use optimized sorted insertion
			trieInstance.BatchInsertSortedUint32(ipUints)
		} else {
			// Adaptive filtering: use concurrent processing only when complex patterns justify overhead
			usesConcurrency := len(requests) > 50000 && hasFilters

			if usesConcurrency {
				// Concurrent filtering for large datasets with complex patterns
				err = processRequestsConcurrently(
					requests, trieConfig, startTime, endTime,
					userAgentMatcher,
					userAgentWhitelistIPSet, userAgentBlacklistIPSet,
					&userAgentWhitelistIPs, &userAgentBlacklistIPs,
					globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet,
					trieInstance, &filteredRequests)
				if err != nil {
					jsonOutput.AddError("concurrent_filtering", fmt.Sprintf("failed to process requests concurrently: %v", err), 1)
				}
			} else {
				// Sequential filtering for simple cases (faster for small datasets)
				processRequestsSequentially(
					requests, trieConfig, startTime, endTime,
					userAgentMatcher,
					userAgentWhitelistIPSet, userAgentBlacklistIPSet,
					&userAgentWhitelistIPs, &userAgentBlacklistIPs,
					globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet,
					trieInstance, &filteredRequests)
			}
		}

		insertDuration := time.Since(insertStart)

		// Set trie stats
		trieResult.Stats = output.TrieStats{
			TotalRequestsAfterFiltering: len(filteredRequests),
			UniqueIPs:                   int(trieInstance.CountAll()),
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

		// Check CIDR ranges if provided
		if len(trieConfig.CidrRanges) > 0 {
			for _, cidrRange := range trieConfig.CidrRanges {
				count, err := trieInstance.CountInRange(cidrRange)
				if err != nil {
					jsonOutput.AddWarning("invalid_cidr", fmt.Sprintf("Invalid CIDR range '%s': %v", cidrRange, err), 1)
					continue
				}

				var percentage float64
				if trieInstance.CountAll() > 0 {
					percentage = float64(count) / float64(trieInstance.CountAll()) * 100
				}
				trieResult.Stats.CIDRAnalysis = append(trieResult.Stats.CIDRAnalysis, output.CIDRRange{
					CIDR:       cidrRange,
					Requests:   count,
					Percentage: percentage,
				})
			}
		}

		// Process clustering for this trie
		if len(trieConfig.ClusterArgSets) > 0 {
			for i, argSet := range trieConfig.ClusterArgSets {
				// Validate depth parameters
				if argSet.MinDepth > argSet.MaxDepth {
					jsonOutput.AddError("invalid_depth_params", fmt.Sprintf("minDepth (%d) must be less than or equal to maxDepth (%d) in cluster arg set %d", argSet.MinDepth, argSet.MaxDepth, i), 1)
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

				// Parse CIDRs once for reuse across operations - use pooled slice
				cidrIPNets := pools.Pools.GetIPNetSlice()
				defer pools.Pools.ReturnIPNetSlice(cidrIPNets)
				totalUniqueIPs := float64(trieInstance.CountAll())

				for _, cidrStr := range cidrs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						jsonOutput.AddWarning("cidr_parse_error", fmt.Sprintf("error parsing CIDR %s: %v", cidrStr, err), 1)
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

		// Add this trie result to the output
		jsonOutput.Tries = append(jsonOutput.Tries, trieResult)
	}

	// Calculate total clusters across all tries
	totalClusters := 0
	for _, trieResult := range jsonOutput.Tries {
		totalClusters += len(trieResult.Data)
	}
	jsonOutput.Clustering.Metadata.TotalClusters = totalClusters

	// Convert global User-Agent IP sets to slices
	for ip := range globalUserAgentWhitelistIPSet {
		jsonOutput.UserAgentWhitelistIPs = append(jsonOutput.UserAgentWhitelistIPs, ip)
	}
	for ip := range globalUserAgentBlacklistIPSet {
		jsonOutput.UserAgentBlacklistIPs = append(jsonOutput.UserAgentBlacklistIPs, ip)
	}

	// Process jail with whitelist/blacklist if configured
	if cfg.Global != nil && cfg.Global.JailFile != "" && cfg.Global.BanFile != "" {
		// Always process jail to generate ban file from existing jail + new detections
		err := ProcessJailWithWhitelist(cfg, jsonOutput)
		if err != nil {
			jsonOutput.AddError("jail_processing", fmt.Sprintf("failed to process jail with whitelist/blacklist: %v", err), 1)
		}
	}

	jsonOutput.UpdateDuration(analysisStart)
	return jsonOutput, requests, nil
}

// ProcessJailWithWhitelist processes all clustering results and applies whitelist/blacklist filtering
func ProcessJailWithWhitelist(cfg *config.Config, jsonOutput *output.JSONOutput) error {
	if cfg.Global == nil {
		return fmt.Errorf("global configuration is required for jail processing")
	}

	// Load whitelist and blacklist
	whitelistCIDRs, err := cfg.LoadWhitelistCIDRs()
	if err != nil {
		jsonOutput.AddError("whitelist_load", fmt.Sprintf("failed to load whitelist: %v", err), 1)
		return err
	}
	blacklistCIDRs, err := cfg.LoadBlacklistCIDRs()
	if err != nil {
		jsonOutput.AddError("blacklist_load", fmt.Sprintf("failed to load blacklist: %v", err), 1)
		return err
	}

	// Collect all CIDRs from all tries that are marked for jail - use pooled slice
	allJailCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(allJailCIDRs)
	for _, trieResult := range jsonOutput.Tries {
		for i, clusterResult := range trieResult.Data {
			// Check if this cluster set should be used for jail
			if len(trieResult.Parameters.UseForJail) > i && trieResult.Parameters.UseForJail[i] {
				// Add all merged ranges from this cluster result
				for _, mergedRange := range clusterResult.MergedRanges {
					allJailCIDRs = append(allJailCIDRs, mergedRange.CIDR)
				}
			}
		}
	}

	// Apply whitelist filtering - remove whitelisted CIDRs AND User-Agent whitelisted IPs BEFORE adding to jail
	filteredJailCIDRs := cidr.RemoveWhitelisted(allJailCIDRs, whitelistCIDRs)

	// Also remove IPs that were whitelisted by User-Agent
	if len(jsonOutput.UserAgentWhitelistIPs) > 0 {
		// Convert User-Agent whitelist IPs to /32 CIDRs for consistent processing - use pooled slice
		userAgentWhitelistCIDRs := pools.Pools.GetStringSlice()
		defer pools.Pools.ReturnStringSlice(userAgentWhitelistCIDRs)
		for _, ip := range jsonOutput.UserAgentWhitelistIPs {
			userAgentWhitelistCIDRs = append(userAgentWhitelistCIDRs, ip+"/32")
		}
		filteredJailCIDRs = cidr.RemoveWhitelisted(filteredJailCIDRs, userAgentWhitelistCIDRs)
	}

	// Log whitelist filtering results
	if len(whitelistCIDRs) > 0 {
		removedCount := len(allJailCIDRs) - len(filteredJailCIDRs)
		jsonOutput.AddWarning("whitelist_applied", fmt.Sprintf("Whitelist filtering prevented %d CIDRs from being added to jail", removedCount), 0)
	}

	// Load existing jail (always load to generate ban file)
	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		jsonOutput.AddError("jail_load", fmt.Sprintf("failed to load jail: %v", err), 1)
		return err
	}

	// Add User-Agent blacklisted IPs to jail (convert to /32 CIDRs) - use pooled slice
	userAgentBlacklistCIDRs := pools.Pools.GetStringSlice()
	defer pools.Pools.ReturnStringSlice(userAgentBlacklistCIDRs)
	if len(jsonOutput.UserAgentBlacklistIPs) > 0 {
		for _, ip := range jsonOutput.UserAgentBlacklistIPs {
			userAgentBlacklistCIDRs = append(userAgentBlacklistCIDRs, ip+"/32")
		}
		filteredJailCIDRs = append(filteredJailCIDRs, userAgentBlacklistCIDRs...)
	}

	// Update jail with filtered CIDRs (non-whitelisted ones + blacklisted User-Agent IPs)
	if len(filteredJailCIDRs) > 0 {
		if err := jailInstance.Update(filteredJailCIDRs); err != nil {
			jsonOutput.AddWarning("jail_update", fmt.Sprintf("some CIDRs failed during jail update: %v", err), 1)
		}

		// Write updated jail back to file
		err = jail.JailToFile(jailInstance, cfg.GetJailFile())
		if err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("failed to save jail: %v", err), 1)
			return err
		}
	}

	// Always generate ban file from jail (even if no new CIDRs were added)
	// Apply whitelist filtering to active bans before writing ban file
	activeBans := jailInstance.ListActiveBans()
	filteredActiveBans := cidr.RemoveWhitelisted(activeBans, whitelistCIDRs)

	// Write ban file with blacklist
	err = jail.WriteBanFileWithBlacklist(cfg.GetBanFile(), filteredActiveBans, blacklistCIDRs)
	if err != nil {
		jsonOutput.AddError("banfile_write", fmt.Sprintf("failed to write ban file: %v", err), 1)
		return err
	}

	// Log blacklist results
	if len(blacklistCIDRs) > 0 {
		jsonOutput.AddWarning("blacklist_applied", fmt.Sprintf("Added %d manual blacklist entries to ban file", len(blacklistCIDRs)), 0)
	}

	return nil
}

// processRequestsConcurrently implements high-performance concurrent filtering and trie building
func processRequestsConcurrently(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet map[string]bool,
	trieInstance *trie.Trie,
	filteredRequests *[]ingestor.Request) error {

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
	requestChan := make(chan requestChunk, numWorkers)
	resultChan := make(chan filterResult, numWorkers*4)

	// Worker synchronization
	var wg sync.WaitGroup

	// Start filter workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			filterWorker(requestChan, resultChan, trieConfig, startTime, endTime,
				userAgentMatcher)
		}()
	}

	// Start result collector
	var collectorWG sync.WaitGroup

	// Collect User-Agent whitelist/blacklist results
	var whitelistMutex, blacklistMutex sync.Mutex

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		var ipUintsToInsert []uint32
		for result := range resultChan {
			if result.shouldInclude {
				*filteredRequests = append(*filteredRequests, result.request)
				ipUintsToInsert = append(ipUintsToInsert, result.request.IPUint32)
			}

			// Collect User-Agent whitelist IPs
			if result.isWhitelistedUA {
				whitelistMutex.Lock()
				ipStr := ingestor.Uint32ToIPString(result.request.IPUint32)
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
					globalUserAgentWhitelistIPSet[ipStr] = true
				}
				whitelistMutex.Unlock()
			}

			// Collect User-Agent blacklist IPs
			if result.isBlacklistedUA {
				blacklistMutex.Lock()
				ipStr := ingestor.Uint32ToIPString(result.request.IPUint32)
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
					globalUserAgentBlacklistIPSet[ipStr] = true
				}
				blacklistMutex.Unlock()
			}
		}

		// Batch insert all collected IPs using sorted insertion
		if len(ipUintsToInsert) > 0 {
			// Radix sort: O(n) vs sort.Slice O(n log n) — 10-15x faster for large arrays
			iputils.RadixSortUint32(ipUintsToInsert)

			// Use optimized sorted insertion
			trieInstance.BatchInsertSortedUint32(ipUintsToInsert)
		}
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

		requestChan <- requestChunk{
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

// processRequestsSequentially provides optimized sequential processing for simple filtering cases.
// Collects filtered IPs, then radix-sorts and batch-inserts for the same speed as the unfiltered fast path.
func processRequestsSequentially(
	requests []ingestor.Request,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher,
	userAgentWhitelistIPSet, userAgentBlacklistIPSet map[string]bool,
	userAgentWhitelistIPs, userAgentBlacklistIPs *[]string,
	globalUserAgentWhitelistIPSet, globalUserAgentBlacklistIPSet map[string]bool,
	trieInstance *trie.Trie,
	filteredRequests *[]ingestor.Request) {

	// Collect filtered IPs for deferred batch insert
	ipUints := make([]uint32, 0, len(requests)/2)

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
					ipStr = ingestor.Uint32ToIPString(r.IPUint32)
					ipStrComputed = true
				}
				if !userAgentWhitelistIPSet[ipStr] {
					userAgentWhitelistIPSet[ipStr] = true
					*userAgentWhitelistIPs = append(*userAgentWhitelistIPs, ipStr)
					globalUserAgentWhitelistIPSet[ipStr] = true
				}
			}

			if isBlacklistedUA {
				if !ipStrComputed {
					ipStr = ingestor.Uint32ToIPString(r.IPUint32)
					ipStrComputed = true
				}
				if !userAgentBlacklistIPSet[ipStr] {
					userAgentBlacklistIPSet[ipStr] = true
					*userAgentBlacklistIPs = append(*userAgentBlacklistIPs, ipStr)
					globalUserAgentBlacklistIPSet[ipStr] = true
				}
			}
		}

		// Collect for batch insert if not whitelisted by User-Agent
		if !isWhitelistedUA {
			*filteredRequests = append(*filteredRequests, r)
			ipUints = append(ipUints, r.IPUint32)
		}
	}

	// Radix sort + batch sorted insert — same optimization as unfiltered fast path
	if len(ipUints) > 0 {
		iputils.RadixSortUint32(ipUints)
		trieInstance.BatchInsertSortedUint32(ipUints)
	}
}
