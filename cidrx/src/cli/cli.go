package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/version"
	cli "github.com/urfave/cli/v2"
)

// parseDate attempts to parse the build date
func parseDate(d string) time.Time {
	t, err := time.Parse(time.RFC3339, d)
	if err != nil {
		return time.Now()
	}
	return t
}

// Shared flag definitions to eliminate duplication
var (
	// Configuration flags
	configFlag = &cli.StringFlag{
		Name:  "config",
		Usage: "Path to configuration file (mutually exclusive with other flags)",
	}

	// Filtering flags
	useragentRegexFlag = &cli.StringFlag{
		Name:  "useragentRegex",
		Usage: "Filter requests by user agent regex pattern (e.g., '.*bot.*')",
	}
	endpointRegexFlag = &cli.StringFlag{
		Name:  "endpointRegex",
		Usage: "Filter requests by endpoint regex pattern (e.g., '/api/.*')",
	}
	rangesCidrFlag = &cli.StringSliceFlag{
		Name:  "rangesCidr",
		Usage: "Provide one or more CIDR ranges to check how many requests are in these range(s).",
	}

	// Output flags
	plotPathFlag = &cli.StringFlag{
		Name:  "plotPath",
		Usage: "Path where to save the heatmap file (e.g., '/path/to/heatmap.html'). If not provided, no plot will be generated.",
	}
	compactFlag = &cli.BoolFlag{
		Name:  "compact",
		Usage: "Output compact JSON (no pretty printing)",
		Value: false,
	}
	plainFlag = &cli.BoolFlag{
		Name:  "plain",
		Usage: "Output plain text format for easy readability",
		Value: false,
	}

	// Jail and ban management flags
	jailFileFlag = &cli.StringFlag{
		Name:  "jailFile",
		Usage: "Path to jail file for ban persistence (e.g., '/tmp/jail.json')",
	}
	banFileFlag = &cli.StringFlag{
		Name:  "banFile",
		Usage: "Path to ban file output (e.g., '/tmp/ban.txt')",
	}

	// Whitelist and blacklist flags
	whitelistFlag = &cli.StringFlag{
		Name:  "whitelist",
		Usage: "Path to IP/CIDR whitelist file (IPs that are never banned)",
	}
	blacklistFlag = &cli.StringFlag{
		Name:  "blacklist",
		Usage: "Path to IP/CIDR blacklist file (IPs that are always banned)",
	}
	userAgentWhitelistFlag = &cli.StringFlag{
		Name:  "userAgentWhitelist",
		Usage: "Path to User-Agent whitelist file (User-Agent patterns that whitelist IPs)",
	}
	userAgentBlacklistFlag = &cli.StringFlag{
		Name:  "userAgentBlacklist",
		Usage: "Path to User-Agent blacklist file (User-Agent patterns that blacklist IPs)",
	}

	// Live-specific flags
	portFlag = &cli.IntFlag{
		Name:  "port",
		Usage: "Port to listen on",
	}
	slidingWindowMaxTimeFlag = &cli.DurationFlag{
		Name:  "slidingWindowMaxTime",
		Usage: "Maximum time duration for sliding window",
		Value: 2 * time.Hour,
	}
	slidingWindowMaxSizeFlag = &cli.IntFlag{
		Name:  "slidingWindowMaxSize",
		Usage: "Maximum number of requests in sliding window",
		Value: 100000,
	}
	sleepBetweenIterationsFlag = &cli.IntFlag{
		Name:  "sleepBetweenIterations",
		Usage: "Sleep duration between iterations in seconds",
		Value: 10,
	}
	clusterArgSetFlag = &cli.StringSliceFlag{
		Name:  "clusterArgSet",
		Usage: "Cluster argument sets (multiple can be passed): minClusterSize,minDepth,maxDepth,meanSubnetDifference",
	}

	// Static-specific flags
	logfileFlag = &cli.StringFlag{
		Name:  "logfile",
		Usage: "Path to the log file",
	}
	logFormatFlag = &cli.StringFlag{
		Name:  "logFormat",
		Usage: "Log format string (e.g., '%h %^ %^ [%t] \"r\" %s %b %^ \"%u\"')",
		Value: "%^ %^ %^ [%t] \"%r\" %s %b %^ \"%u\" \"%h\"",
	}
	startTimeFlag = &cli.StringFlag{
		Name:  "startTime",
		Usage: "Start time (formats: YYYY-MM-DD, YYYY-MM-DD HH, or YYYY-MM-DD HH:MM)",
	}
	endTimeFlag = &cli.StringFlag{
		Name:  "endTime",
		Usage: "End time (formats: YYYY-MM-DD, YYYY-MM-DD HH, or YYYY-MM-DD HH:MM)",
	}
	clusterArgSetsFlag = &cli.StringSliceFlag{
		Name:  "clusterArgSets",
		Usage: "Cluster argument sets: minClusterSize,minDepth,maxDepth,meanSubnetDifference;...",
	}
	tuiFlag = &cli.BoolFlag{
		Name:  "tui",
		Usage: "Launch TUI (Terminal User Interface) mode",
		Value: false,
	}
)

// Shared validation functions
func validateConfigModeFlags(c *cli.Context, allowedFlags []string) error {
	// Create a map for quick lookup of allowed flags
	allowed := make(map[string]bool)
	for _, flag := range allowedFlags {
		allowed[flag] = true
	}

	// Check all possible flags
	flagsToCheck := []string{
		"port", "jailFile", "banFile", "slidingWindowMaxTime", "slidingWindowMaxSize",
		"sleepBetweenIterations", "clusterArgSet", "useragentRegex", "endpointRegex",
		"rangesCidr", "plotPath", "whitelist", "blacklist", "userAgentWhitelist",
		"userAgentBlacklist", "logfile", "logFormat", "startTime", "endTime",
		"clusterArgSets", "tui", "compact", "plain",
	}

	for _, flag := range flagsToCheck {
		if c.IsSet(flag) && !allowed[flag] {
			return fmt.Errorf("when using --config, only %v flags are allowed", allowedFlags)
		}
	}
	return nil
}

func validateRegexPatterns(c *cli.Context) error {
	if useragentRegex := c.String("useragentRegex"); useragentRegex != "" {
		if _, err := regexp.Compile(useragentRegex); err != nil {
			return fmt.Errorf("invalid useragentRegex pattern: %w", err)
		}
	}

	if endpointRegex := c.String("endpointRegex"); endpointRegex != "" {
		if _, err := regexp.Compile(endpointRegex); err != nil {
			return fmt.Errorf("invalid endpointRegex pattern: %w", err)
		}
	}

	return nil
}

func validateCIDRRanges(c *cli.Context) error {
	if rangesCidr := c.StringSlice("rangesCidr"); len(rangesCidr) > 0 {
		for _, cidr := range rangesCidr {
			if !iputils.IsValidCidrOrIP(cidr) {
				return fmt.Errorf("invalid CIDR range: %s", cidr)
			}
		}
	}
	return nil
}

func validatePlotPath(plotPath string) error {
	if plotPath != "" {
		plotDir := filepath.Dir(plotPath)
		if plotDir == "." {
			plotDir, _ = os.Getwd()
		}
		if _, err := os.Stat(plotDir); os.IsNotExist(err) {
			return fmt.Errorf("plot directory does not exist: %s", plotDir)
		}
	}
	return nil
}

func validateLogFileExists(logfilePath string) error {
	if _, err := os.Stat(logfilePath); os.IsNotExist(err) {
		return fmt.Errorf("logfile does not exist: %s", logfilePath)
	}
	return nil
}

func parseFlexibleTime(input string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04", // full datetime
		"2006-01-02 15",    // date + hour
		"2006-01-02",       // just date
	}

	for _, layout := range formats {
		if t, err := time.Parse(layout, input); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s", input)
}

func parseClusterArgSets(clusterArgSets []string) ([]string, error) {
	if len(clusterArgSets)%4 != 0 {
		return nil, fmt.Errorf("invalid cluster argument sets. Each set should contain 4 comma-separated values: minClusterSize,minDepth,maxDepth,meanSubnetDifference")
	}
	return clusterArgSets, nil
}

// Command handler functions to reduce deep nesting

// handleLiveCommand processes the live command with proper separation of concerns
func handleLiveCommand(c *cli.Context) error {
	configPath := c.String("config")
	if configPath != "" {
		return handleLiveConfigMode(c, configPath)
	}
	return handleLiveFlagsMode(c)
}

// handleLiveConfigMode handles live command when using config file
func handleLiveConfigMode(c *cli.Context, configPath string) error {
	// Validate only allowed flags in config mode
	if err := validateConfigModeFlags(c, []string{"compact", "plain"}); err != nil {
		return err
	}

	// Load and validate config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate live mode configuration
	if err := cfg.ValidateLive(); err != nil {
		return fmt.Errorf("invalid live configuration: %w", err)
	}

	fmt.Println("Running in live mode from config file:")
	LiveFromConfig(cfg)
	return nil
}

// handleLiveFlagsMode handles live command when using CLI flags only
func handleLiveFlagsMode(c *cli.Context) error {
	// Validate required flags
	if !c.IsSet("port") || !c.IsSet("jailFile") || !c.IsSet("banFile") {
		return fmt.Errorf("port, jailFile, and banFile are required when not using --config")
	}

	// Check for advanced features that require config mode
	if c.IsSet("useragentRegex") || c.IsSet("endpointRegex") || c.IsSet("rangesCidr") || c.IsSet("plotPath") {
		return fmt.Errorf("advanced features (useragentRegex, endpointRegex, rangesCidr, plotPath) require --config mode. Please use a configuration file")
	}

	fmt.Println("Running in live mode with CLI flags:")
	Live(
		c.String("port"),
		c.String("jailFile"),
		c.String("banFile"),
		c.Duration("slidingWindowMaxTime"),
		c.Int("slidingWindowMaxSize"),
		c.Int("sleepBetweenIterations"),
	)
	return nil
}

// handleStaticCommand processes the static command with proper separation of concerns
func handleStaticCommand(c *cli.Context) error {
	configPath := c.String("config")
	if configPath != "" {
		return handleStaticConfigMode(c, configPath)
	}
	return handleStaticFlagsMode(c)
}

// handleStaticConfigMode handles static command when using config file
func handleStaticConfigMode(c *cli.Context, configPath string) error {
	// Validate only allowed flags in config mode
	if err := validateConfigModeFlags(c, []string{"tui", "compact", "plain"}); err != nil {
		return err
	}

	// Load and validate config
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Static == nil {
		return fmt.Errorf("static configuration section missing in config file")
	}

	// Validate logfile exists
	if err := validateLogFileExists(cfg.Static.LogFile); err != nil {
		return err
	}

	// Validate plot path if provided
	if err := validatePlotPath(cfg.Static.PlotPath); err != nil {
		return err
	}

	// Use unified static interface
	StaticFromConfig(cfg, c.Bool("compact"), c.Bool("plain"), c.Bool("tui"))
	return nil
}

// handleStaticFlagsMode handles static command when using CLI flags only
func handleStaticFlagsMode(c *cli.Context) error {
	// Validate required flags
	if !c.IsSet("logfile") {
		return fmt.Errorf("logfile is required when not using --config")
	}

	// Validate logfile exists
	if err := validateLogFileExists(c.String("logfile")); err != nil {
		return err
	}

	// Parse time arguments
	var st, et time.Time
	var err error

	if start := c.String("startTime"); start != "" {
		if st, err = parseFlexibleTime(start); err != nil {
			return fmt.Errorf("error parsing start time: %w", err)
		}
		fmt.Printf("Start Time: %s\n", st)
	}

	if end := c.String("endTime"); end != "" {
		if et, err = parseFlexibleTime(end); err != nil {
			return fmt.Errorf("error parsing end time: %w", err)
		}
		fmt.Printf("End Time: %s\n", et)
	}

	// Parse and validate cluster arguments
	clusterArgSets, err := parseClusterArgSets(c.StringSlice("clusterArgSets"))
	if err != nil {
		return err
	}

	// Validate patterns and ranges
	if err := validateRegexPatterns(c); err != nil {
		return err
	}

	if err := validateCIDRRanges(c); err != nil {
		return err
	}

	if err := validatePlotPath(c.String("plotPath")); err != nil {
		return err
	}

	// Use unified static interface
	Static(
		c.String("logfile"),
		c.String("logFormat"),
		st,
		et,
		c.String("useragentRegex"),
		c.String("endpointRegex"),
		clusterArgSets,
		c.StringSlice("rangesCidr"),
		c.String("plotPath"),
		c.Bool("compact"),
		c.Bool("plain"),
		c.Bool("tui"),
	)
	return nil
}

var App = &cli.App{
	Name:     "cidrx",
	Usage:    "Cluster IPs either in live mode or from static logs",
	Version:  version.Version,
	Compiled: parseDate(version.Date),
	Commands: []*cli.Command{
		{
			Name:  "live",
			Usage: "Run clustering on live incoming data",
			Flags: []cli.Flag{
				// Configuration
				configFlag,
				// Live-specific flags
				portFlag,
				slidingWindowMaxTimeFlag,
				slidingWindowMaxSizeFlag,
				sleepBetweenIterationsFlag,
				clusterArgSetFlag,
				// Filtering flags
				useragentRegexFlag,
				endpointRegexFlag,
				rangesCidrFlag,
				// Output flags
				plotPathFlag,
				compactFlag,
				plainFlag,
				// Jail and ban management
				jailFileFlag,
				banFileFlag,
				// Whitelist and blacklist
				whitelistFlag,
				blacklistFlag,
				userAgentWhitelistFlag,
				userAgentBlacklistFlag,
			},
			Action: handleLiveCommand,
		},
		{
			Name:  "static",
			Usage: "Run clustering from a log file",
			Flags: []cli.Flag{
				// Configuration
				configFlag,
				// Static-specific flags
				logfileFlag,
				logFormatFlag,
				startTimeFlag,
				endTimeFlag,
				clusterArgSetsFlag,
				tuiFlag,
				// Filtering flags
				useragentRegexFlag,
				endpointRegexFlag,
				rangesCidrFlag,
				// Output flags
				plotPathFlag,
				compactFlag,
				plainFlag,
				// Jail and ban management
				jailFileFlag,
				banFileFlag,
				// Whitelist and blacklist
				whitelistFlag,
				blacklistFlag,
				userAgentWhitelistFlag,
				userAgentBlacklistFlag,
			},
			Action: handleStaticCommand,
		},
	},
}
