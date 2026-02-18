package cli

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ChristianF88/cidrx/analysis"
	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
	"github.com/ChristianF88/cidrx/jail"
	"github.com/ChristianF88/cidrx/output"
	"github.com/ChristianF88/cidrx/sliding"
	"github.com/ChristianF88/cidrx/tui"
)

// ============================================================================
// CONFIGURATION STRUCTS
// ============================================================================

// Note: Using config.LiveConfig instead of defining our own

// OutputConfig contains output formatting options
type OutputConfig struct {
	Compact bool
	Plain   bool
	TUI     bool
}

// ============================================================================
// MAIN ENTRY POINTS - These are the only functions that should be called externally
// ============================================================================

// Static is the unified static analysis function - handles all static analysis cases
func Static(logFile, logFormat string, startTime, endTime time.Time, useragentRegex, endpointRegex string,
	clusterArgSets []string, rangesCidr []string, plotPath string, compact, plain, tui bool) {

	// Create config.Config directly from CLI parameters - no intermediate structs
	cfg, err := createConfigFromCLI(logFile, logFormat, startTime, endTime, useragentRegex, endpointRegex, clusterArgSets, rangesCidr, plotPath)
	if err != nil {
		fmt.Printf(`{"error": "%v"}`, err)
		return
	}

	outputConfig := OutputConfig{
		Compact: compact,
		Plain:   plain,
		TUI:     tui,
	}

	// Use the same execution path regardless of input source
	executeStaticAnalysis(cfg, outputConfig)
}

// StaticFromConfig runs static analysis from config file
func StaticFromConfig(cfg *config.Config, compact, plain, tui bool) {
	outputConfig := OutputConfig{
		Compact: compact,
		Plain:   plain,
		TUI:     tui,
	}

	// Use the same execution path regardless of input source
	executeStaticAnalysis(cfg, outputConfig)
}

// Live runs live mode analysis
func Live(port, jailFile, banFile string, slidingWindowMaxTime time.Duration, slidingWindowMaxSize int, sleepBetweenIterations int) {
	// Create config.Config directly from CLI parameters
	cfg, err := createLiveConfigFromCLI(port, jailFile, banFile, slidingWindowMaxTime, slidingWindowMaxSize, sleepBetweenIterations)
	if err != nil {
		fmt.Printf(`{"error": "%v"}`, err)
		return
	}

	executeLiveAnalysis(cfg)
}

// ============================================================================
// CORE EXECUTION LOGIC - Single unified execution path
// ============================================================================

// executeStaticAnalysis handles all static analysis - CLI or config file, doesn't matter
func executeStaticAnalysis(cfg *config.Config, outputConfig OutputConfig) {
	// Route to TUI if requested
	if outputConfig.TUI {
		executeTUI(cfg)
		return
	}

	// Execute the actual analysis
	result, requests, err := analysis.ParallelStaticFromConfigWithRequests(cfg)
	if err != nil {
		outputResult(result, outputConfig) // Output with errors
		return
	}

	// Generate heatmap if plotPath is provided - reuse parsed requests
	if cfg.Static.PlotPath != "" && requests != nil {
		plotStart := time.Now()
		output.PlotHeatmap(requests, cfg.Static.PlotPath)
		plotDuration := time.Since(plotStart)
		result.AddWarning("info", fmt.Sprintf("Heatmap generated in %v at %s", plotDuration, cfg.Static.PlotPath), 0)
	}

	outputResult(result, outputConfig)
}

// executeTUI runs TUI mode - works for both CLI and config file inputs
func executeTUI(cfg *config.Config) {
	app := tui.NewAppFromConfig(cfg, "")

	// Run the complete analysis first (like non-TUI mode), then pass results to TUI
	go func() {
		// Do the same complete analysis as non-TUI mode
		multiTrieResult, requests, err := analysis.ParallelStaticFromConfigWithRequests(cfg)
		if err != nil {
			// Show error in TUI instead of silent failure
			app.ShowError(fmt.Sprintf("Analysis failed: %v", err))
			return
		}

		// Verify we got results
		if multiTrieResult == nil {
			app.ShowError("Analysis completed but returned no results")
			return
		}

		// Set the complete analysis results first
		app.SetAnalysisResults(multiTrieResult)

		// Then set raw requests for visualization
		if requests != nil {
			app.SetRequestData(requests)
		}
	}()

	if err := app.Run(); err != nil {
		fmt.Printf("TUI error: %v\n", err)
	}
}

// ============================================================================
// HELPER FUNCTIONS - Conversion and utility functions
// ============================================================================

// createConfigFromCLI creates a config.Config directly from CLI parameters for static mode
// This eliminates the need for intermediate structs like StaticAnalysisConfig
func createConfigFromCLI(logFile, logFormat string, startTime, endTime time.Time, useragentRegex, endpointRegex string,
	clusterArgSets []string, rangesCidr []string, plotPath string) (*config.Config, error) {

	// Create a config structure from CLI arguments - same structure as config file
	cfg := &config.Config{
		Static: &config.StaticConfig{
			LogFile:   logFile,
			LogFormat: logFormat,
			PlotPath:  plotPath,
		},
		StaticTries: make(map[string]*config.TrieConfig),
	}

	// Create a single trie config from CLI arguments
	trieConfig := &config.TrieConfig{
		UserAgentRegex: useragentRegex,
		EndpointRegex:  endpointRegex,
		CidrRanges:     rangesCidr,
	}

	// Set time range if provided
	if !startTime.IsZero() {
		trieConfig.StartTime = &startTime
	}
	if !endTime.IsZero() {
		trieConfig.EndTime = &endTime
	}

	// Parse cluster arg sets using shared logic
	clusterArgSetsResult, useForJail, err := parseClusterArguments(clusterArgSets)
	if err != nil {
		return nil, err
	}

	// Convert [][]float64 to []ClusterArgSet
	for _, argSet := range clusterArgSetsResult {
		if len(argSet) >= 4 {
			trieConfig.ClusterArgSets = append(trieConfig.ClusterArgSets, config.ClusterArgSet{
				MinClusterSize:       uint32(argSet[0]),
				MinDepth:             uint32(argSet[1]),
				MaxDepth:             uint32(argSet[2]),
				MeanSubnetDifference: argSet[3],
			})
		}
	}
	trieConfig.UseForJail = useForJail

	cfg.StaticTries["cli_trie"] = trieConfig
	return cfg, nil
}

// createLiveConfigFromCLI creates a config.Config directly from CLI parameters for live mode
func createLiveConfigFromCLI(port, jailFile, banFile string, slidingWindowMaxTime time.Duration, slidingWindowMaxSize int, sleepBetweenIterations int) (*config.Config, error) {
	// Create a config structure from CLI arguments - same structure as config file
	cfg := &config.Config{
		Global: &config.GlobalConfig{
			JailFile: jailFile,
			BanFile:  banFile,
		},
		Live: &config.LiveConfig{
			Port: port,
		},
		LiveTries: make(map[string]*config.SlidingTrieConfig),
	}

	// Create a default sliding window config from CLI parameters
	cfg.LiveTries["cli_default"] = &config.SlidingTrieConfig{
		SlidingWindowMaxTime:   slidingWindowMaxTime,
		SlidingWindowMaxSize:   slidingWindowMaxSize,
		SleepBetweenIterations: sleepBetweenIterations,
		ClusterArgSets: []config.ClusterArgSet{
			{
				MinClusterSize:       1000,
				MinDepth:             30,
				MaxDepth:             32,
				MeanSubnetDifference: 0.2,
			},
		},
		UseForJail: []bool{true},
	}

	return cfg, nil
}

// parseClusterArguments parses cluster argument sets and returns the parsed cluster configuration
func parseClusterArguments(clusterArgSets []string) ([][]float64, []bool, error) {
	var clusterArgSetsResult [][]float64
	var useForJailResult []bool

	if len(clusterArgSets) == 0 {
		return clusterArgSetsResult, useForJailResult, nil
	}

	for i := 0; i < len(clusterArgSets); i += 4 {
		if i+3 >= len(clusterArgSets) {
			return nil, nil, fmt.Errorf("invalid cluster argument sets: each set should contain 4 values")
		}

		minClusterSize, err := strconv.ParseFloat(clusterArgSets[i], 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid minClusterSize: %w", err)
		}

		minDepth, err := strconv.ParseFloat(clusterArgSets[i+1], 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid minDepth: %w", err)
		}

		maxDepth, err := strconv.ParseFloat(clusterArgSets[i+2], 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid maxDepth: %w", err)
		}

		meanSubnetDifference, err := strconv.ParseFloat(clusterArgSets[i+3], 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid meanSubnetDifference: %w", err)
		}

		// Validate depth parameters
		if minDepth > maxDepth {
			return nil, nil, fmt.Errorf("minDepth (%.0f) must be less than or equal to maxDepth (%.0f)", minDepth, maxDepth)
		}

		argSet := []float64{minClusterSize, minDepth, maxDepth, meanSubnetDifference}
		clusterArgSetsResult = append(clusterArgSetsResult, argSet)
		useForJailResult = append(useForJailResult, false) // CLI mode sets all to false
	}

	return clusterArgSetsResult, useForJailResult, nil
}

// ============================================================================
// LIVE MODE IMPLEMENTATION
// ============================================================================

// LiveFromConfig runs live mode from config file
func LiveFromConfig(cfg *config.Config) {
	executeLiveAnalysis(cfg)
}

// slidingWindowInstance holds a sliding window and its associated configuration
type slidingWindowInstance struct {
	name   string
	window *sliding.SlidingWindow
	config *config.SlidingTrieConfig
}

// executeLiveAnalysis runs live mode analysis - works for both CLI and config file inputs
func executeLiveAnalysis(cfg *config.Config) {
	if len(cfg.LiveTries) == 0 {
		log.Fatalf("No LiveTries configurations found")
	}

	// Create sliding window instances - one per LiveTries entry
	var windows []slidingWindowInstance
	for name, slidingConfig := range cfg.LiveTries {
		window := sliding.NewSlidingWindowTrie(
			slidingConfig.SlidingWindowMaxTime,
			slidingConfig.SlidingWindowMaxSize,
		)
		windows = append(windows, slidingWindowInstance{
			name:   name,
			window: window,
			config: slidingConfig,
		})
	}

	ingestor, err := ingestor.NewTCPIngestor(
		":"+cfg.Live.Port,
		5*time.Second, // read timeout: avoid client disconnects
	)

	if err != nil {
		log.Fatalf("Error creating ingestor: %v", err)
	}

	jailInstance, err := jail.FileToJail(cfg.GetJailFile())
	if err != nil {
		log.Fatalf("Error reading jail file: %v\n", err)
	}

	// Output initial connection status as JSON
	initOutput := output.NewJSONOutput("live", time.Now())
	initOutput.AddWarning("info", "Waiting for Filebeat to connect...", 0)
	outputJSON(initOutput)

	if err := ingestor.Accept(); err != nil {
		log.Fatalf("Error accepting connection: %v", err)
	}

	// Connection established
	connectedOutput := output.NewJSONOutput("live", time.Now())
	connectedOutput.AddWarning("info", "Filebeat connected", 0)
	outputJSON(connectedOutput)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		shutdownOutput := output.NewJSONOutput("live", time.Now())
		shutdownOutput.AddWarning("info", "Received shutdown signal...", 0)
		outputJSON(shutdownOutput)
		ingestor.Close()
	}()

	// Calculate maximum sleep time across all windows
	maxSleepTime := 0
	for _, winInst := range windows {
		if winInst.config.SleepBetweenIterations > maxSleepTime {
			maxSleepTime = winInst.config.SleepBetweenIterations
		}
	}

	for {
		loopStart := time.Now()
		jsonOutput := output.NewJSONOutput("live", loopStart)

		batch, err := ingestor.ReadBatch()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			jsonOutput.AddError("read_batch", fmt.Sprintf("read error: %v", err), 1)
			outputJSON(jsonOutput)
			break
		}

		if len(batch) == 0 {
			if ingestor.IsClosed() {
				jsonOutput.AddWarning("info", "Ingestor closed. Exiting loop.", 0)
				outputJSON(jsonOutput)
				break
			}
			continue
		}

		// Collect all CIDRs to ban from all sliding windows
		var allMergedCIDRs []*net.IPNet
		var allDetectedCIDRs []output.LiveCIDR
		totalClusterDuration := int64(0)
		totalWindowSize := 0

		// Process each sliding window
		for _, winInst := range windows {
			// Filter batch based on this window's regex filters
			timedIps := make([]sliding.TimedIp, 0, len(batch))
			for _, msg := range batch {
				if msg.Timestamp.IsZero() || msg.IPUint32 == 0 {
					continue
				}

				// Apply regex filtering based on window config
				if !winInst.config.ShouldIncludeRequest(msg) {
					continue
				}

				timedIps = append(timedIps, sliding.TimedIp{
					Ip:               msg.GetIPNet(),
					Time:             msg.Timestamp,
					EndpointAllowed:  true,
					UserAgentAllowed: true,
				})
			}

			// Update this specific window
			winInst.window.Update(timedIps)
			totalWindowSize += len(winInst.window.IpQueue)

			// Run clustering for each ClusterArgSet on this window
			for i, argSet := range winInst.config.ClusterArgSets {
				useForJail := false
				if i < len(winInst.config.UseForJail) {
					useForJail = winInst.config.UseForJail[i]
				}

				clusterStart := time.Now()
				cidrs := winInst.window.Trie.CollectCIDRs(
					argSet.MinClusterSize,
					argSet.MinDepth,
					argSet.MaxDepth,
					argSet.MeanSubnetDifference,
				)
				clusterDuration := time.Since(clusterStart)
				totalClusterDuration += clusterDuration.Microseconds()

				// Parse CIDRs once for reuse across operations
				var cidrIPNets []*net.IPNet

				for _, cidrStr := range cidrs {
					_, ipNet, err := net.ParseCIDR(cidrStr)
					if err != nil {
						jsonOutput.AddWarning("cidr_parse_error", fmt.Sprintf("error parsing CIDR %s: %v", cidrStr, err), 1)
						continue
					}
					cidrIPNets = append(cidrIPNets, ipNet)

					// Use IPNet-native count function for speed
					count := winInst.window.Trie.CountInRangeIPNet(ipNet)
					allDetectedCIDRs = append(allDetectedCIDRs, output.LiveCIDR{
						CIDR:  cidrStr,
						Count: count,
					})
				}

				// Only add to jail if useForJail is true
				if useForJail {
					allMergedCIDRs = append(allMergedCIDRs, cidrIPNets...)
				}
			}
		}

		// Merge all CIDRs collected across configurations
		mergedIPNets := cidr.MergeIPNets(allMergedCIDRs)

		// Convert back to strings for display and jail operations
		var mergedCIDRs []string
		for _, ipNet := range mergedIPNets {
			mergedCIDRs = append(mergedCIDRs, ipNet.String())
		}

		if err := jailInstance.Update(mergedCIDRs); err != nil {
			jsonOutput.AddWarning("jail_update", fmt.Sprintf("some CIDRs failed during jail update: %v", err), 1)
		}
		if err := jail.JailToFile(jailInstance, cfg.GetJailFile()); err != nil {
			jsonOutput.AddError("jail_save", fmt.Sprintf("failed to save jail: %v", err), 1)
		}
		if err := jail.WriteBanFile(cfg.GetBanFile(), jailInstance.ListActiveBans()); err != nil {
			jsonOutput.AddError("banfile_write", fmt.Sprintf("failed to write ban file: %v", err), 1)
		}

		loopEnd := time.Since(loopStart)

		// Set live stats
		jsonOutput.LiveStats = &output.LiveStats{
			WindowSize:      totalWindowSize,
			ProcessedBatch:  len(batch),
			LoopDuration:    loopEnd.Milliseconds(),
			ClusterDuration: totalClusterDuration / 1000, // Convert to milliseconds
			ActiveBans:      jailInstance.ListActiveBans(),
			DetectedCIDRs:   allDetectedCIDRs,
			MergedCIDRs:     mergedCIDRs,
		}

		jsonOutput.UpdateDuration(loopStart)
		outputJSON(jsonOutput)

		// Sleep using maximum sleep time across all windows
		time.Sleep(time.Duration(maxSleepTime) * time.Second)
	}
}

// ============================================================================
// OUTPUT FUNCTIONS - Unified output handling
// ============================================================================

// outputJSON outputs in default JSON format (non-compact, non-plain)
func outputJSON(jsonOutput *output.JSONOutput) {
	outputResult(jsonOutput, OutputConfig{Compact: false, Plain: false})
}

// outputResult is the unified output function that handles all output formats
func outputResult(jsonOutput *output.JSONOutput, outputConfig OutputConfig) {
	if outputConfig.Plain {
		outputPlain(jsonOutput)
		return
	}

	var jsonBytes []byte
	var err error

	if outputConfig.Compact {
		jsonBytes, err = jsonOutput.ToCompactJSON()
	} else {
		jsonBytes, err = jsonOutput.ToJSON()
	}

	if err != nil {
		fmt.Printf(`{"error": "failed to marshal JSON output: %v"}`, err)
		return
	}
	fmt.Println(string(jsonBytes))
}

// outputPlain formats the JSON output as human-readable plain text
func outputPlain(jsonOutput *output.JSONOutput) {
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                               cidrx Analysis Results\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n\n")

	// General Information
	fmt.Printf("📊 ANALYSIS OVERVIEW\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Log File:        %s\n", jsonOutput.General.LogFile)
	fmt.Printf("Analysis Type:   %s\n", jsonOutput.Metadata.AnalysisType)
	fmt.Printf("Generated:       %s\n", jsonOutput.Metadata.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Duration:        %d ms\n", jsonOutput.Metadata.DurationMS)
	fmt.Printf("\n")

	// Parsing Performance
	fmt.Printf("⚡ PARSING PERFORMANCE\n")
	fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("Total Requests:  %s\n", formatNumber(jsonOutput.General.TotalRequests))
	fmt.Printf("Parse Time:      %d ms\n", jsonOutput.General.Parsing.DurationMS)
	fmt.Printf("Parse Rate:      %s requests/sec\n", formatNumber(int(jsonOutput.General.Parsing.RatePerSecond)))
	fmt.Printf("Log Format:      %s\n", jsonOutput.General.Parsing.Format)
	fmt.Printf("\n")

	// Process each trie
	for i, trieResult := range jsonOutput.Tries {
		fmt.Printf("🎯 TRIE: %s\n", trieResult.Name)
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		// Trie Statistics
		fmt.Printf("Requests After Filtering: %s\n", formatNumber(trieResult.Stats.TotalRequestsAfterFiltering))
		fmt.Printf("Unique IPs:              %s\n", formatNumber(trieResult.Stats.UniqueIPs))
		fmt.Printf("Trie Build Time:         %d ms\n", trieResult.Stats.InsertTimeMS)

		// Active Filters
		fmt.Printf("Active Filters:          ")
		filters := getActiveFiltersPlain(trieResult.Parameters)
		if len(filters) > 0 {
			fmt.Printf("%s\n", strings.Join(filters, ", "))
		} else {
			fmt.Printf("None\n")
		}
		fmt.Printf("\n")

		// CIDR Range Analysis
		if len(trieResult.Stats.CIDRAnalysis) > 0 {
			fmt.Printf("📍 CIDR RANGE ANALYSIS\n")
			fmt.Printf("...............................................................................  \n")
			for _, cidr := range trieResult.Stats.CIDRAnalysis {
				fmt.Printf("  %-20s  %10s requests  (%6.2f%%)\n",
					cidr.CIDR, formatNumber(int(cidr.Requests)), cidr.Percentage)
			}
			fmt.Printf("\n")
		}

		// Clustering Results
		if len(trieResult.Data) > 0 {
			fmt.Printf("🔍 CLUSTERING RESULTS (%d sets)\n", len(trieResult.Data))
			fmt.Printf("...............................................................................  \n")

			for j, cluster := range trieResult.Data {
				fmt.Printf("  Set %d: min_size=%d, depth=%d-%d, threshold=%.2f\n",
					j+1, cluster.Parameters.MinClusterSize, cluster.Parameters.MinDepth,
					cluster.Parameters.MaxDepth, cluster.Parameters.MeanSubnetDifference)
				fmt.Printf("  Execution Time: %d μs\n", cluster.ExecutionTimeUS)

				if len(cluster.MergedRanges) > 0 {
					fmt.Printf("  Detected Threat Ranges:\n")
					var totalThreats uint32
					for _, threat := range cluster.MergedRanges {
						fmt.Printf("    %-20s  %10s requests  (%6.2f%%)\n",
							threat.CIDR, formatNumber(int(threat.Requests)), threat.Percentage)
						totalThreats += threat.Requests
					}
					totalPercentage := float64(totalThreats) / float64(trieResult.Stats.UniqueIPs) * 100
					fmt.Printf("    %-20s  %10s requests  (%6.2f%%) [TOTAL]\n",
						"───────────────────", formatNumber(int(totalThreats)), totalPercentage)
				} else {
					fmt.Printf("  No significant threat ranges detected\n")
				}
				fmt.Printf("\n")
			}
		}

		// Add separator between tries
		if i < len(jsonOutput.Tries)-1 {
			fmt.Printf("===============================================================================\n\n")
		}
	}

	// Warnings and Errors
	if len(jsonOutput.Warnings) > 0 || len(jsonOutput.Errors) > 0 {
		fmt.Printf("⚠️  DIAGNOSTICS\n")
		fmt.Printf("────────────────────────────────────────────────────────────────────────────────\n")

		if len(jsonOutput.Warnings) > 0 {
			fmt.Printf("Warnings:\n")
			for _, warning := range jsonOutput.Warnings {
				if warning.Type != "info" { // Skip info messages in plain output
					fmt.Printf("  • %s\n", warning.Message)
				}
			}
		}

		if len(jsonOutput.Errors) > 0 {
			fmt.Printf("Errors:\n")
			for _, err := range jsonOutput.Errors {
				fmt.Printf("  • %s\n", err.Message)
			}
		}

		if len(jsonOutput.Warnings) == 0 && len(jsonOutput.Errors) == 0 {
			fmt.Printf("✅ No issues detected\n")
		}
		fmt.Printf("\n")
	}

	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
}

// getActiveFiltersPlain returns a list of active filter descriptions for plain output
func getActiveFiltersPlain(params output.TrieParameters) []string {
	var filters []string

	if params.UserAgentRegex != nil && *params.UserAgentRegex != "" {
		filters = append(filters, fmt.Sprintf("User-Agent: %s", *params.UserAgentRegex))
	}

	if params.EndpointRegex != nil && *params.EndpointRegex != "" {
		filters = append(filters, fmt.Sprintf("Endpoint: %s", *params.EndpointRegex))
	}

	if params.TimeRange != nil {
		if !params.TimeRange.Start.IsZero() || !params.TimeRange.End.IsZero() {
			timeFilter := "Time: "
			if !params.TimeRange.Start.IsZero() {
				timeFilter += params.TimeRange.Start.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			timeFilter += " → "
			if !params.TimeRange.End.IsZero() {
				timeFilter += params.TimeRange.End.Format("2006-01-02 15:04")
			} else {
				timeFilter += "∞"
			}
			filters = append(filters, timeFilter)
		}
	}

	return filters
}

// formatNumber adds thousand separators to numbers
func formatNumber(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}
