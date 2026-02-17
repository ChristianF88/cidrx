package analysis

import (
	"time"

	"github.com/ChristianF88/cidrx/cidr"
	"github.com/ChristianF88/cidrx/config"
	"github.com/ChristianF88/cidrx/ingestor"
)

// requestChunk represents a chunk of requests for parallel processing
type requestChunk struct {
	requests []ingestor.Request
	start    int
	end      int
}

// filterResult represents the result of filtering a single request
type filterResult struct {
	request         ingestor.Request
	shouldInclude   bool
	isWhitelistedUA bool
	isBlacklistedUA bool
}

// filterWorker processes request chunks concurrently
func filterWorker(
	requestChan <-chan requestChunk,
	resultChan chan<- filterResult,
	trieConfig *config.TrieConfig,
	startTime, endTime time.Time,
	userAgentMatcher *cidr.UserAgentMatcher) {

	for chunk := range requestChan {
		for _, r := range chunk.requests {
			result := filterResult{
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
