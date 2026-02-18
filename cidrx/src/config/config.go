package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ChristianF88/cidrx/ingestor"
)

var HomeDir string = os.Getenv("HOME")
var JailFile string = filepath.Join(HomeDir, "jail.json")
var BanFile string = filepath.Join(HomeDir, "banFile.txt")

type GlobalConfig struct {
	LogFile            string `toml:"logFile"`
	JailFile           string `toml:"jailFile"`
	BanFile            string `toml:"banFile"`
	Whitelist          string `toml:"whitelist"`
	Blacklist          string `toml:"blacklist"`
	UserAgentWhitelist string `toml:"userAgentWhitelist"`
	UserAgentBlacklist string `toml:"userAgentBlacklist"`
}

// ClusterArgSet represents a single set of clustering parameters with proper types
type ClusterArgSet struct {
	MinClusterSize       uint32
	MinDepth             uint32
	MaxDepth             uint32
	MeanSubnetDifference float64
}

type TrieConfig struct {
	UserAgentRegex string     `toml:"useragentRegex"`
	EndpointRegex  string     `toml:"endpointRegex"`
	StartTime      *time.Time `toml:"startTime"`
	EndTime        *time.Time `toml:"endTime"`
	CIDRRanges     []string   `toml:"cidrRanges"`
	ClusterArgSets []ClusterArgSet
	UseForJail     []bool `toml:"useForJail"`

	// Raw values for validation reporting when parsing fails
	StartTimeRaw string `toml:"-"`
	EndTimeRaw   string `toml:"-"`

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp
}

type SlidingTrieConfig struct {
	UserAgentRegex         string        `toml:"useragentRegex"`
	EndpointRegex          string        `toml:"endpointRegex"`
	SlidingWindowMaxTime   time.Duration `toml:"slidingWindowMaxTime"`
	SlidingWindowMaxSize   int           `toml:"slidingWindowMaxSize"`
	SleepBetweenIterations int           `toml:"sleepBetweenIterations"`
	ClusterArgSets         []ClusterArgSet
	UseForJail             []bool `toml:"useForJail"`

	// Compiled regex patterns for fast filtering
	userAgentRegexCompiled *regexp.Regexp
	endpointRegexCompiled  *regexp.Regexp
}

type StaticConfig struct {
	LogFile   string `toml:"logFile"`
	LogFormat string `toml:"logFormat"`
	PlotPath  string `toml:"plotPath"`
}

type LiveConfig struct {
	Port string `toml:"port"`
}

type Config struct {
	Global      *GlobalConfig                 `toml:"global"`
	Static      *StaticConfig                 `toml:"static"`
	Live        *LiveConfig                   `toml:"live"`
	StaticTries map[string]*TrieConfig        `toml:",remain"`
	LiveTries   map[string]*SlidingTrieConfig `toml:",remain"`
}

func LoadConfig(configPath string) (*Config, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var rawConfig map[string]any
	if _, err := toml.Decode(string(configData), &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	config := &Config{
		StaticTries: make(map[string]*TrieConfig),
		LiveTries:   make(map[string]*SlidingTrieConfig),
	}

	for key, value := range rawConfig {
		switch key {
		case "global":
			if globalMap, ok := value.(map[string]any); ok {
				config.Global = parseGlobalConfig(globalMap)
			}
		case "static":
			if staticMap, ok := value.(map[string]any); ok {
				config.Static = parseStaticConfig(staticMap)
				// Parse static tries from nested config
				for subKey, subValue := range staticMap {
					// Skip static configuration fields and only process trie configurations
					if subKey != "logFormat" && subKey != "logFile" && subKey != "plotPath" {
						if trieMap, ok := subValue.(map[string]any); ok {
							trieConfig, err := parseTrieConfig(trieMap)
							if err != nil {
								return nil, fmt.Errorf("parsing trie config %q: %w", subKey, err)
							}
							if trieConfig != nil {
								config.StaticTries[subKey] = trieConfig
							}
						}
					}
				}
			}
		case "live":
			if liveMap, ok := value.(map[string]any); ok {
				config.Live = parseLiveConfig(liveMap)
				// Parse live tries from nested config
				for subKey, subValue := range liveMap {
					// Skip live configuration fields and only process trie configurations
					if subKey != "port" && subKey != "slidingWindowMaxTime" && subKey != "slidingWindowMaxSize" && subKey != "sleepBetweenIterations" {
						if trieMap, ok := subValue.(map[string]any); ok {
							trieConfig, err := parseSlidingTrieConfig(trieMap)
							if err != nil {
								return nil, fmt.Errorf("parsing sliding trie config %q: %w", subKey, err)
							}
							if trieConfig != nil {
								config.LiveTries[subKey] = trieConfig
							}
						}
					}
				}
			}
		}
	}

	if config.Global == nil {
		config.Global = &GlobalConfig{}
	}
	if config.Static == nil {
		config.Static = &StaticConfig{}
	}
	if config.Live == nil {
		config.Live = &LiveConfig{}
	}

	return config, nil
}

func parseGlobalConfig(m map[string]any) *GlobalConfig {
	config := &GlobalConfig{}
	if v, ok := m["logFile"].(string); ok {
		config.LogFile = v
	}
	if v, ok := m["jailFile"].(string); ok {
		config.JailFile = v
	}
	if v, ok := m["banFile"].(string); ok {
		config.BanFile = v
	}
	if v, ok := m["whitelist"].(string); ok {
		config.Whitelist = v
	}
	if v, ok := m["blacklist"].(string); ok {
		config.Blacklist = v
	}
	if v, ok := m["userAgentWhitelist"].(string); ok {
		config.UserAgentWhitelist = v
	}
	if v, ok := m["userAgentBlacklist"].(string); ok {
		config.UserAgentBlacklist = v
	}
	return config
}

func parseStaticConfig(m map[string]any) *StaticConfig {
	config := &StaticConfig{}
	if v, ok := m["logFile"].(string); ok {
		config.LogFile = v
	}
	if v, ok := m["logFormat"].(string); ok {
		config.LogFormat = v
	}
	if v, ok := m["plotPath"].(string); ok {
		config.PlotPath = v
	}
	return config
}

func parseLiveConfig(m map[string]any) *LiveConfig {
	config := &LiveConfig{}
	if v, ok := m["port"].(string); ok {
		config.Port = v
	}
	return config
}

func parseTrieConfig(m map[string]any) (*TrieConfig, error) {
	config := &TrieConfig{}
	if v, ok := m["useragentRegex"].(string); ok {
		config.UserAgentRegex = v
		if v != "" {
			compiled, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid useragentRegex %q: %w", v, err)
			}
			config.userAgentRegexCompiled = compiled
		}
	}
	if v, ok := m["endpointRegex"].(string); ok {
		config.EndpointRegex = v
		if v != "" {
			compiled, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid endpointRegex %q: %w", v, err)
			}
			config.endpointRegexCompiled = compiled
		}
	}
	if v, ok := m["startTime"].(string); ok {
		if v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				config.StartTime = &t
			} else {
				config.StartTimeRaw = v // Store for warning
			}
		}
	}
	if v, ok := m["endTime"].(string); ok {
		if v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				config.EndTime = &t
			} else {
				config.EndTimeRaw = v // Store for warning
			}
		}
	}
	if v, ok := m["cidrRanges"].([]any); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				config.CIDRRanges = append(config.CIDRRanges, str)
			}
		}
	}
	if v, ok := m["clusterArgSets"].([]any); ok {
		for _, item := range v {
			if arr, ok := item.([]any); ok {
				var argSet []float64
				for _, val := range arr {
					if f, ok := val.(float64); ok {
						argSet = append(argSet, f)
					} else if i, ok := val.(int64); ok {
						argSet = append(argSet, float64(i))
					}
				}
				// Convert to ClusterArgSet with proper types
				if len(argSet) >= 4 {
					minDepth := uint32(argSet[1])
					maxDepth := uint32(argSet[2])
					// Validate depth parameters
					if minDepth > maxDepth {
						// Skip invalid cluster arg sets
						continue
					}
					config.ClusterArgSets = append(config.ClusterArgSets, ClusterArgSet{
						MinClusterSize:       uint32(argSet[0]),
						MinDepth:             minDepth,
						MaxDepth:             maxDepth,
						MeanSubnetDifference: argSet[3],
					})
				}
			}
		}
	}
	if v, ok := m["useForJail"].([]any); ok {
		for _, item := range v {
			if b, ok := item.(bool); ok {
				config.UseForJail = append(config.UseForJail, b)
			}
		}
	}
	return config, nil
}

func parseSlidingTrieConfig(m map[string]any) (*SlidingTrieConfig, error) {
	config := &SlidingTrieConfig{}
	if v, ok := m["useragentRegex"].(string); ok {
		config.UserAgentRegex = v
		if v != "" {
			compiled, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid useragentRegex %q: %w", v, err)
			}
			config.userAgentRegexCompiled = compiled
		}
	}
	if v, ok := m["endpointRegex"].(string); ok {
		config.EndpointRegex = v
		if v != "" {
			compiled, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("invalid endpointRegex %q: %w", v, err)
			}
			config.endpointRegexCompiled = compiled
		}
	}
	if v, ok := m["slidingWindowMaxTime"].(string); ok {
		duration, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid slidingWindowMaxTime %q: %w", v, err)
		}
		config.SlidingWindowMaxTime = duration
	}
	if v, ok := m["slidingWindowMaxSize"].(int64); ok {
		config.SlidingWindowMaxSize = int(v)
	}
	if v, ok := m["sleepBetweenIterations"].(int64); ok {
		config.SleepBetweenIterations = int(v)
	}
	if v, ok := m["clusterArgSets"].([]any); ok {
		for _, item := range v {
			if arr, ok := item.([]any); ok {
				var argSet []float64
				for _, val := range arr {
					if f, ok := val.(float64); ok {
						argSet = append(argSet, f)
					} else if i, ok := val.(int64); ok {
						argSet = append(argSet, float64(i))
					}
				}
				// Convert to ClusterArgSet with proper types
				if len(argSet) >= 4 {
					minDepth := uint32(argSet[1])
					maxDepth := uint32(argSet[2])
					// Validate depth parameters
					if minDepth > maxDepth {
						// Skip invalid cluster arg sets
						continue
					}
					config.ClusterArgSets = append(config.ClusterArgSets, ClusterArgSet{
						MinClusterSize:       uint32(argSet[0]),
						MinDepth:             minDepth,
						MaxDepth:             maxDepth,
						MeanSubnetDifference: argSet[3],
					})
				}
			}
		}
	}
	if v, ok := m["useForJail"].([]any); ok {
		for _, item := range v {
			if b, ok := item.(bool); ok {
				config.UseForJail = append(config.UseForJail, b)
			}
		}
	}
	return config, nil
}

func (c *Config) GetJailFile() string {
	if c.Global != nil && c.Global.JailFile != "" {
		return c.Global.JailFile
	}
	return JailFile
}

func (c *Config) GetBanFile() string {
	if c.Global != nil && c.Global.BanFile != "" {
		return c.Global.BanFile
	}
	return BanFile
}

func (c *Config) ValidateStatic() error {
	if c.Static == nil {
		return fmt.Errorf("static configuration section is required")
	}

	if c.Static.LogFile == "" {
		return fmt.Errorf("logFile is required in static configuration")
	}

	if c.Static.LogFormat == "" {
		return fmt.Errorf("logFormat is required in static configuration")
	}

	// Check if logfile exists
	if _, err := os.Stat(c.Static.LogFile); os.IsNotExist(err) {
		return fmt.Errorf("logfile does not exist: %s", c.Static.LogFile)
	}

	// Validate required global fields for static mode
	if c.Global == nil {
		return fmt.Errorf("global configuration section is required for static mode")
	}

	if c.Global.JailFile == "" {
		return fmt.Errorf("jailFile is required in global configuration for static mode")
	}

	if c.Global.BanFile == "" {
		return fmt.Errorf("banFile is required in global configuration for static mode")
	}

	// PlotPath is optional - no validation needed if empty

	return nil
}

func (c *Config) ValidateLive() error {
	if c.Live == nil {
		return fmt.Errorf("live configuration section is required")
	}

	if c.Live.Port == "" {
		return fmt.Errorf("port is required in live configuration")
	}

	// Validate required global fields for live mode
	if c.Global == nil {
		return fmt.Errorf("global configuration section is required for live mode")
	}

	if c.Global.JailFile == "" {
		return fmt.Errorf("jailFile is required in global configuration for live mode")
	}

	if c.Global.BanFile == "" {
		return fmt.Errorf("banFile is required in global configuration for live mode")
	}

	// Validate that at least one LiveTries configuration exists
	if len(c.LiveTries) == 0 {
		return fmt.Errorf("at least one sliding window configuration is required in live mode (e.g., [live.window_name])")
	}

	return nil
}

// ShouldIncludeRequest checks if a request should be included based on regex filters
func (tc *TrieConfig) ShouldIncludeRequest(req ingestor.Request) bool {
	// Apply useragent regex filter (short-circuit on empty UserAgent)
	if tc.userAgentRegexCompiled != nil {
		if req.UserAgent == "" || !tc.userAgentRegexCompiled.MatchString(req.UserAgent) {
			return false
		}
	}

	// Apply endpoint regex filter (short-circuit on empty URI)
	if tc.endpointRegexCompiled != nil {
		if req.URI == "" || !tc.endpointRegexCompiled.MatchString(req.URI) {
			return false
		}
	}

	return true
}

// ShouldIncludeRequest checks if a request should be included based on regex filters
func (stc *SlidingTrieConfig) ShouldIncludeRequest(req ingestor.Request) bool {
	// Apply useragent regex filter
	if stc.userAgentRegexCompiled != nil && !stc.userAgentRegexCompiled.MatchString(req.UserAgent) {
		return false
	}

	// Apply endpoint regex filter
	if stc.endpointRegexCompiled != nil && !stc.endpointRegexCompiled.MatchString(req.URI) {
		return false
	}

	return true
}

// LoadWhitelistCIDRs loads CIDR ranges from whitelist file
func (c *Config) LoadWhitelistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Whitelist == "" {
		return nil, nil
	}

	return loadCIDRFile(c.Global.Whitelist)
}

// LoadBlacklistCIDRs loads CIDR ranges from blacklist file
func (c *Config) LoadBlacklistCIDRs() ([]string, error) {
	if c.Global == nil || c.Global.Blacklist == "" {
		return nil, nil
	}

	return loadCIDRFile(c.Global.Blacklist)
}

// LoadUserAgentWhitelistPatterns loads User-Agent patterns from whitelist file
func (c *Config) LoadUserAgentWhitelistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentWhitelist == "" {
		return nil, nil
	}
	return loadPatternFile(c.Global.UserAgentWhitelist)
}

// LoadUserAgentBlacklistPatterns loads User-Agent patterns from blacklist file
func (c *Config) LoadUserAgentBlacklistPatterns() ([]string, error) {
	if c.Global == nil || c.Global.UserAgentBlacklist == "" {
		return nil, nil
	}
	return loadPatternFile(c.Global.UserAgentBlacklist)
}

// loadPatternFile loads patterns from a file (for User-Agent whitelist/blacklist)
func loadPatternFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		patterns = append(patterns, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return patterns, nil
}

// loadCIDRFile loads and validates CIDR ranges from a file
func loadCIDRFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	var cidrs []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate CIDR format
		if _, _, err := net.ParseCIDR(line); err != nil {
			return nil, fmt.Errorf("invalid CIDR format at line %d in %s: %s", lineNum, filename, line)
		}

		cidrs = append(cidrs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filename, err)
	}

	return cidrs, nil
}
