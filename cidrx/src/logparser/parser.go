package logparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ChristianF88/cidrx/ingestor"
)

// FieldExtractor represents a compiled field extraction operation
type FieldExtractor struct {
	FieldType int  // 0=IP, 1=timestamp, 2=method, 3=URI, 4=status, 5=bytes, 6=user-agent, 7=referer, -1=skip
	Delimiter byte // delimiter to find (space, quote, bracket)
	Quoted    bool // whether field is in quotes
	Brackets  bool // whether field is in brackets
}

// CompiledFormat represents a pre-compiled log format for ultra-fast parsing
type CompiledFormat struct {
	extractors []FieldExtractor
	pattern    string
}

// Parser provides high-performance log parsing with adaptive I/O strategies
// Combines parallel processing, object pooling, and ultra-fast field extraction
type Parser struct {
	format           string
	compiled         *CompiledFormat
	workers          int
	pool             *sync.Pool // Object pool for Request structs
	SkipStringFields bool       // When true, skip URI and UserAgent string allocations
	SkipNonIPFields  bool       // When true, skip all non-IP field extraction (timestamp, method, status, bytes, strings)
}

// ParallelParser is an alias for Parser (backward compatibility)
type ParallelParser = Parser

// NewParser creates a high-performance log parser (recommended constructor)
func NewParser(format string) (*Parser, error) {
	// Optimize worker count for maximum parsing throughput
	workerCount := runtime.NumCPU()
	// For log parsing, fewer workers often perform better due to memory bandwidth
	if workerCount > 8 {
		workerCount = 8 // Cap at 8 workers for optimal performance
	}

	p := &Parser{
		format:  format,
		workers: workerCount,
		pool: &sync.Pool{
			New: func() interface{} {
				return &ingestor.Request{}
			},
		},
	}

	// Compile format string into optimized extractors
	compiled, err := compileFormat(format)
	if err != nil {
		return nil, err
	}
	p.compiled = compiled

	return p, nil
}

// NewParallelParser creates a parser (backward compatibility - use NewParser instead)
func NewParallelParser(format string) (*ParallelParser, error) {
	parser, err := NewParser(format)
	return (*ParallelParser)(parser), err
}

// ParseFile parses a log file using adaptive I/O strategy (primary interface)
// Automatically chooses between streaming I/O (small files) and chunked I/O (large files)
// This is the recommended method for all file parsing operations.
func (pp *ParallelParser) ParseFile(filename string) ([]ingestor.Request, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size to decide on optimal parsing strategy
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()

	// For files smaller than 500MB, use streaming I/O (better performance)
	const largeFileThreshold = 500 * 1024 * 1024 // 500MB
	if fileSize < largeFileThreshold {
		return pp.parseFileWithStreamingIO(filename)
	}

	// For large files, use chunked concurrent I/O
	return pp.parseFileWithConcurrentIO(file, fileSize)
}

// parseBatchSize is the number of lines per batch sent through channels.
// Batching amortizes channel lock/unlock overhead: 1M lines = ~1K channel ops instead of 1M.
const parseBatchSize = 1024

// parseFileWithStreamingIO uses streaming I/O with batched parallel parsing workers (internal method)
func (pp *ParallelParser) parseFileWithStreamingIO(filename string) ([]ingestor.Request, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size for pre-allocation estimate
	stat, _ := file.Stat()
	estimatedLines := int(stat.Size() / 200) // ~200 bytes per log line estimate
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	// Batched channels — each send/receive moves parseBatchSize items at once,
	// reducing channel operations from O(lines) to O(lines/batchSize).
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan []ingestor.Request, pp.workers*2)

	var wg sync.WaitGroup

	// Capture skip flags for use in worker goroutines
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields

	// Start parser workers — each worker reuses a single Request for parsing
	for i := 0; i < pp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &ingestor.Request{}
			for batch := range linesChan {
				resBatch := make([]ingestor.Request, 0, len(batch))
				for _, line := range batch {
					*req = ingestor.Request{}
					if err := pp.compiled.parseLineReuseOpt(line, req, skipStrings, skipNonIP); err == nil {
						resBatch = append(resBatch, *req)
					}
				}
				if len(resBatch) > 0 {
					resultsChan <- resBatch
				}
			}
		}()
	}

	// Start result collector with pre-allocated slice
	results := make([]ingestor.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)

	go func() {
		defer collectorWG.Done()
		for batch := range resultsChan {
			results = append(results, batch...)
		}
	}()

	// I/O reader — accumulate lines into batches before sending
	// Uses a slab allocator: one contiguous []byte per batch instead of one per line.
	// Reduces allocations from O(lines) to O(lines/batchSize).
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 256*1024), 2*1024*1024) // 256KB initial, 2MB max

	const slabSize = 256 * 1024 // 256KB slab per batch (~250 bytes/line * 1024 lines)
	batch := make([][]byte, 0, parseBatchSize)
	slab := make([]byte, 0, slabSize)
	for scanner.Scan() {
		scanBytes := scanner.Bytes()
		lineLen := len(scanBytes)

		// If this line won't fit in the current slab, allocate a new one
		if len(slab)+lineLen > cap(slab) {
			newCap := slabSize
			if lineLen > newCap {
				newCap = lineLen // handle lines larger than slab
			}
			slab = make([]byte, 0, newCap)
		}

		// Sub-allocate from slab: append line bytes, then slice out the line
		start := len(slab)
		slab = append(slab, scanBytes...)
		batch = append(batch, slab[start:start+lineLen])

		if len(batch) >= parseBatchSize {
			linesChan <- batch
			batch = make([][]byte, 0, parseBatchSize)
			slab = make([]byte, 0, slabSize)
		}
	}
	// Send remaining lines
	if len(batch) > 0 {
		linesChan <- batch
	}

	// Shutdown pipeline
	close(linesChan)   // Signal workers to stop
	wg.Wait()          // Wait for all workers to finish
	close(resultsChan) // Signal collector to stop
	collectorWG.Wait() // Wait for collector to finish

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// ParseFileChunked (deprecated: use ParseFile instead)
// Backward compatibility alias - delegates to ParseFile for consistent behavior
func (pp *ParallelParser) ParseFileChunked(filename string) ([]ingestor.Request, error) {
	return pp.ParseFile(filename)
}

// ParseFileParallelChunked (deprecated: use ParseFile instead)
// Backward compatibility alias - delegates to ParseFile for consistent behavior
func (pp *ParallelParser) ParseFileParallelChunked(filename string) ([]ingestor.Request, error) {
	return pp.ParseFile(filename)
}

// ParseFileParallel (deprecated: use ParseFile instead)
// Backward compatibility alias - delegates to parseFileWithStreamingIO
func (pp *ParallelParser) ParseFileParallel(filename string) ([]ingestor.Request, error) {
	return pp.parseFileWithStreamingIO(filename)
}

// parseFileWithConcurrentIO implements concurrent chunked file reading.
// Uses ReadAt for thread-safe parallel reads, batched channels matching the
// streaming path, and per-worker Request reuse (no sync.Pool needed).
func (pp *ParallelParser) parseFileWithConcurrentIO(file *os.File, fileSize int64) ([]ingestor.Request, error) {
	const chunkSize = 64 * 1024 * 1024 // 64MB chunks for optimal I/O
	numChunks := int(fileSize / chunkSize)
	if fileSize%chunkSize != 0 {
		numChunks++
	}

	// Limit concurrent chunk readers
	maxConcurrentChunks := runtime.NumCPU()
	if maxConcurrentChunks > 8 {
		maxConcurrentChunks = 8
	}

	// Estimate total lines for pre-allocation
	estimatedLines := int(fileSize / 150)
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	// Batched channels — same pattern as streaming path
	chunkJobs := make(chan chunkJob, numChunks)
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan []ingestor.Request, pp.workers*2)

	var wg sync.WaitGroup

	// Start chunk readers — use ReadAt (pread64) for thread-safe parallel reads
	// on the same file descriptor. No file handle pool needed.
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range chunkJobs {
				pp.readChunkBatched(file, job, fileSize, linesChan)
			}
		}()
	}

	// Start parser workers — per-worker Request reuse (matches streaming path)
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields
	var parserWG sync.WaitGroup
	for i := 0; i < pp.workers; i++ {
		parserWG.Add(1)
		go func() {
			defer parserWG.Done()
			req := &ingestor.Request{}
			for batch := range linesChan {
				resBatch := make([]ingestor.Request, 0, len(batch))
				for _, line := range batch {
					*req = ingestor.Request{}
					if err := pp.compiled.parseLineReuseOpt(line, req, skipStrings, skipNonIP); err == nil {
						resBatch = append(resBatch, *req)
					}
				}
				if len(resBatch) > 0 {
					resultsChan <- resBatch
				}
			}
		}()
	}

	// Start result collector with pre-allocated slice
	results := make([]ingestor.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for batch := range resultsChan {
			results = append(results, batch...)
		}
	}()

	// Enqueue chunk jobs
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}
		chunkJobs <- chunkJob{start: start, end: end, index: i}
	}
	close(chunkJobs)

	// Shutdown pipeline
	wg.Wait()
	close(linesChan)
	parserWG.Wait()
	close(resultsChan)
	collectorWG.Wait()

	return results, nil
}

// chunkJob represents a file chunk to be read
type chunkJob struct {
	start int64
	end   int64
	index int
}

// readChunkBatched reads a file chunk using ReadAt and sends batched line slices.
// Uses a slab allocator for line data, matching the streaming path's approach.
func (pp *ParallelParser) readChunkBatched(file *os.File, job chunkJob, fileSize int64, linesChan chan<- [][]byte) {
	chunkLen := job.end - job.start
	if chunkLen <= 0 {
		return
	}

	// Read the chunk with overlap for line boundary handling
	overlap := int64(8192)
	readEnd := job.end + overlap
	if readEnd > fileSize {
		readEnd = fileSize
	}
	readSize := readEnd - job.start

	buffer := make([]byte, readSize)
	n, err := file.ReadAt(buffer, job.start)
	if err != nil && err != io.EOF {
		return
	}
	buffer = buffer[:n]

	// For non-first chunks, skip the first (likely partial) line
	start := 0
	if job.index > 0 {
		idx := bytes.IndexByte(buffer, '\n')
		if idx < 0 {
			return
		}
		start = idx + 1
	}

	// Extract lines into batches using slab allocator
	const slabSize = 256 * 1024
	batch := make([][]byte, 0, parseBatchSize)
	slab := make([]byte, 0, slabSize)
	bytesProcessed := 0

	for i := start; i < len(buffer); i++ {
		if buffer[i] == '\n' {
			lineData := buffer[start:i]
			start = i + 1

			// Stop if we've gone past this chunk's boundary
			if job.start+int64(bytesProcessed) >= job.end {
				break
			}
			bytesProcessed = i + 1

			if len(lineData) == 0 {
				continue
			}

			// Sub-allocate from slab
			lineLen := len(lineData)
			if len(slab)+lineLen > cap(slab) {
				newCap := slabSize
				if lineLen > newCap {
					newCap = lineLen
				}
				slab = make([]byte, 0, newCap)
			}
			slabStart := len(slab)
			slab = append(slab, lineData...)
			batch = append(batch, slab[slabStart:slabStart+lineLen])

			if len(batch) >= parseBatchSize {
				linesChan <- batch
				batch = make([][]byte, 0, parseBatchSize)
				slab = make([]byte, 0, slabSize)
			}
		}
	}

	// Handle the last line if it doesn't end with newline and we're at EOF
	if start < len(buffer) && readEnd == fileSize {
		lineData := buffer[start:]
		if len(lineData) > 0 {
			lineLen := len(lineData)
			if len(slab)+lineLen > cap(slab) {
				slab = make([]byte, 0, lineLen)
			}
			slabStart := len(slab)
			slab = append(slab, lineData...)
			batch = append(batch, slab[slabStart:slabStart+lineLen])
		}
	}

	// Send remaining lines
	if len(batch) > 0 {
		linesChan <- batch
	}
}

// ParseLine for single line parsing
func (pp *ParallelParser) ParseLine(line []byte) (*ingestor.Request, error) {
	return pp.compiled.parseLineWithPool(line, pp.pool)
}

// ParseLineReuse for zero-allocation parsing with request reuse
func (pp *ParallelParser) ParseLineReuse(line []byte, req *ingestor.Request) error {
	return pp.compiled.parseLineReuseOpt(line, req, pp.SkipStringFields, pp.SkipNonIPFields)
}

// validateFormat ensures format string doesn't have duplicate non-skippable fields
func validateFormat(format string) error {
	fieldCounts := make(map[byte]int)

	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			field := format[i+1]

			// Skip validation for skip field (%^)
			if field == '^' {
				continue
			}

			// Count occurrences of each field type
			fieldCounts[field]++

			// Validate supported field types and check for duplicates
			switch field {
			case 'h': // IP - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate IP field (%%h) found in format string - only one IP field is allowed")
				}
			case 't': // Timestamp - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate timestamp field (%%t) found in format string - only one timestamp field is allowed")
				}
			case 'r': // Request - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate request field (%%r) found in format string - only one request field is allowed")
				}
			case 'm': // Method - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate method field (%%m) found in format string - only one method field is allowed")
				}
			case 's': // Status - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate status field (%%s) found in format string - only one status field is allowed")
				}
			case 'b': // Bytes - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate bytes field (%%b) found in format string - only one bytes field is allowed")
				}
			case 'U': // URI standalone - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate URI field (%%U) found in format string - only one URI field is allowed")
				}
			case 'u': // User agent - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate user agent field (%%u) found in format string - only one user agent field is allowed")
				}
			default:
				return fmt.Errorf("unsupported format code %%%c - supported codes are: %%h (IP), %%t (timestamp), %%r (request), %%m (method), %%s (status), %%b (bytes), %%U (URI), %%u (user-agent), %%^ (skip)", field)
			}
		}
	}

	// Ensure at least one IP field is present
	if fieldCounts['h'] == 0 {
		return fmt.Errorf("no IP field (%%h) found in format string - at least one IP field is required")
	}

	return nil
}

// compileFormat converts a format string into optimized field extractors
//
// Supported format codes:
//
//	%h - IP address (required) - maps to Request.IP
//	%t - Timestamp in brackets [DD/MMM/YYYY:HH:mm:ss +zone] - maps to Request.Timestamp
//	%r - Request line "METHOD URI HTTP/VERSION" - extracts Method and URI (ignores HTTP version)
//	%m - HTTP method standalone - maps to Request.Method
//	%U - URI standalone - maps to Request.URI
//	%s - Status code - maps to Request.Status
//	%b - Response bytes - maps to Request.Bytes
//	%u - User-Agent - maps to Request.UserAgent
//	%^ - Skip this field (ignore)
//
// Notes:
//   - %r extracts both Method and URI from quoted request line, HTTP version is ignored
//   - Fields in quotes ("") or brackets ([]) are automatically detected
//   - Delimiter-aware parsing respects comma, space, and other separators
//   - At least one %h (IP) field is required
func compileFormat(format string) (*CompiledFormat, error) {
	// Validate format first
	if err := validateFormat(format); err != nil {
		return nil, err
	}

	var extractors []FieldExtractor

	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			extractor := FieldExtractor{}

			// Determine field type
			switch format[i+1] {
			case 'h':
				extractor.FieldType = 0 // IP
			case 't':
				extractor.FieldType = 1 // Timestamp
				extractor.Brackets = true
			case 'm':
				extractor.FieldType = 2 // Method
			case 'r':
				extractor.FieldType = 3 // URI (request)
			case 's':
				extractor.FieldType = 4 // Status
			case 'b':
				extractor.FieldType = 5 // Bytes
			case 'U':
				extractor.FieldType = 7 // URI (standalone)
			case 'u':
				extractor.FieldType = 6 // User agent
				extractor.Quoted = true
			case '^':
				extractor.FieldType = -1 // Skip
			default:
				continue
			}

			// Determine delimiter and quoted status by looking ahead
			if i+2 < len(format) {
				nextChar := format[i+2]
				extractor.Delimiter = nextChar
				if nextChar == '"' {
					extractor.Quoted = true
				}
			} else {
				extractor.Delimiter = ' ' // default
			}

			extractors = append(extractors, extractor)
			i++ // Skip format character
		}
	}

	return &CompiledFormat{
		extractors: extractors,
		pattern:    format,
	}, nil
}

// parseLineWithPool uses object pool to reduce allocations
func (cf *CompiledFormat) parseLineWithPool(line []byte, pool *sync.Pool) (*ingestor.Request, error) {
	return cf.parseLineWithPoolOpt(line, pool, false, false)
}

// parseLineWithPoolOpt uses object pool with optional string field skipping
func (cf *CompiledFormat) parseLineWithPoolOpt(line []byte, pool *sync.Pool, skipStrings, skipNonIP bool) (*ingestor.Request, error) {
	req := pool.Get().(*ingestor.Request)
	// Reset the request to zero state
	*req = ingestor.Request{}
	err := cf.parseLineReuseOpt(line, req, skipStrings, skipNonIP)
	if err != nil {
		// Return request to pool on parse error to prevent memory leak
		pool.Put(req)
		return nil, err
	}
	return req, nil
}

// parseLineReuseOpt parses a log line with optional string field skipping
func (cf *CompiledFormat) parseLineReuseOpt(line []byte, req *ingestor.Request, skipStrings, skipNonIP bool) error {
	// Use compiled format extractors for optimized parsing
	if len(cf.extractors) > 0 {
		return cf.parseUsingCompiledFormatOpt(line, req, skipStrings, skipNonIP)
	}

	// If no extractors configured, skip parsing
	return nil
}

// parseUsingCompiledFormatOpt applies extractors with optional string field skipping
// When skipNonIP is true, only the IP field is extracted (all others are skipped but positions still advance)
func (cf *CompiledFormat) parseUsingCompiledFormatOpt(line []byte, req *ingestor.Request, skipStrings, skipNonIP bool) error {
	pos := 0

	for _, extractor := range cf.extractors {
		if pos >= len(line) {
			break
		}

		// Skip whitespace
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}

		start := pos

		// Handle quoted/bracketed fields
		// bytes.IndexByte uses SIMD (SSE2/AVX2) on amd64 for 8-16x faster scanning
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++ // skip opening quote
			start = pos
			if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			// Don't skip closing quote yet - we'll handle it after field extraction
		} else if extractor.Brackets && pos < len(line) && line[pos] == '[' {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			// Don't skip closing bracket yet
		} else {
			// Regular field - scan until delimiter or space
			delimiter := extractor.Delimiter
			if delimiter == 0 {
				delimiter = ' ' // default to space
			}
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
		}

		// Extract and parse field if not skipped
		if extractor.FieldType >= 0 && start < pos {
			// IP is always extracted; other fields are skipped when skipNonIP is true
			if extractor.FieldType == 0 {
				req.IPUint32 = parseIPv4ToUint32(line, start, pos)
			} else if !skipNonIP {
				fieldData := line[start:pos]

				switch extractor.FieldType {
				case 1: // Timestamp
					req.Timestamp = parseTimestampUltraFast(line, start)
				case 2: // Method (standalone)
					req.Method = parseMethodUltraFast(line, start, pos)
				case 3: // Request line (%r) - extracts METHOD and URI, ignores HTTP version
					if extractor.Quoted {
						// Parse "METHOD URI HTTP/VERSION" format efficiently
						methodEnd := start
						for methodEnd < pos && line[methodEnd] != ' ' {
							methodEnd++
						}

						// Extract method if not already set and method field exists
						if methodEnd > start && req.Method == 0 {
							req.Method = parseMethodUltraFast(line, start, methodEnd)
						}

						// Extract URI only if strings are needed
						if !skipStrings {
							// Skip spaces after method
							uriStart := methodEnd
							for uriStart < pos && line[uriStart] == ' ' {
								uriStart++
							}

							// Find end of URI (next space before HTTP version)
							uriEnd := uriStart
							for uriEnd < pos && line[uriEnd] != ' ' {
								uriEnd++
							}

							// Extract URI
							if uriEnd > uriStart {
								req.URI = bytesToString(line[uriStart:uriEnd])
							}
						}
						// HTTP version is intentionally ignored as Request struct has no field for it
					} else if !skipStrings {
						// If not quoted, treat entire field as URI
						req.URI = bytesToString(fieldData)
					}
				case 4: // Status
					if pos-start >= 3 {
						_ = line[start+2] // BCE hint: eliminate 3 individual bounds checks below
						req.Status = uint16(line[start]&0x0F)*100 + uint16(line[start+1]&0x0F)*10 + uint16(line[start+2]&0x0F)
					}
				case 5: // Bytes
					if len(fieldData) > 0 && fieldData[0] != '-' {
						req.Bytes = parseBytesUltraFast(line, start, pos)
					}
				case 6: // User agent
					if !skipStrings {
						req.UserAgent = bytesToString(fieldData)
					}
				case 7: // URI (standalone)
					if !skipStrings {
						req.URI = bytesToString(fieldData)
					}
				}
			}
		}

		// Advance past closing quotes/brackets/delimiters
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++
		} else if extractor.Brackets && pos < len(line) && line[pos] == ']' {
			pos++
		} else if pos < len(line) && line[pos] == extractor.Delimiter {
			pos++ // Skip the delimiter
		}
	}

	return nil
}

// bytesToString converts byte slice to string without copying.
// Safe when the backing byte slice is not mutated after this call (e.g., lineCopy
// allocated per-line in parseFileWithStreamingIO is never reused).
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// parseIPv4ToUint32 extracts IPv4 address directly as uint32 — zero allocation
//
// Performance optimizations:
//   - Single-pass parsing with dot counting
//   - Bit masking for digit extraction: (b & 0x0F) converts ASCII digit to int
//   - Returns uint32 directly — NO net.IP heap allocation
//   - Bounds checking for IPv4 format (7-15 characters)
//
// Input: line[start:end] should contain IPv4 like "192.168.1.1"
// Returns: uint32 IP or 0 if invalid format
func parseIPv4ToUint32(line []byte, start, end int) uint32 {
	if end-start < 7 || end-start > 15 {
		return 0
	}
	// BCE hint: prove line[end-1] is in bounds, eliminating per-iteration bounds check
	if end > len(line) {
		return 0
	}

	// Count dots and parse in one pass with bit masking
	dots := 0
	partIdx := 0
	current := 0
	var result uint32

	for i := start; i < end; i++ {
		b := line[i]
		if b == '.' {
			if current > 255 || partIdx >= 3 {
				return 0
			}
			result |= uint32(current) << (24 - 8*partIdx)
			partIdx++
			current = 0
			dots++
		} else if b >= '0' && b <= '9' {
			current = current*10 + int(b&0x0F)
		} else {
			return 0
		}
	}

	if dots != 3 || current > 255 || partIdx != 3 {
		return 0
	}
	result |= uint32(current)

	return result
}

// parseTimestampUltraFast extracts timestamp from Apache Common Log format with maximum performance
//
// Expected format: "[06/Jul/2025:19:57:26 +0000]" (26 characters)
//
// Performance optimizations:
//   - Direct byte-to-int conversion using bit masking: (b & 0x0F)
//   - 3-byte month lookup using bitwise operations for ultra-fast comparison
//   - Hardcoded month codes eliminate string comparisons
//   - Single bounds check, then direct array access for all fields
//
// Month encoding: ASCII bytes packed into uint32 for fast switch lookup
// Example: "Jul" = 0x4A756C = uint32('J')<<16 | uint32('u')<<8 | uint32('l')
func parseTimestampUltraFast(line []byte, start int) time.Time {
	if start+25 >= len(line) {
		return time.Time{}
	}

	// BCE hint: prove all accesses up to line[start+19] are in bounds,
	// eliminating 14 individual bounds checks in the code below.
	_ = line[start+19]

	// Parse "06/Jul/2025:19:57:26 +0000" directly from line buffer
	// Use bit operations for faster digit parsing
	day := int(line[start]&0x0F)*10 + int(line[start+1]&0x0F)

	// Ultra-fast month lookup using 3-byte comparison
	var month time.Month
	m1, m2, m3 := line[start+3], line[start+4], line[start+5]
	monthCode := uint32(m1)<<16 | uint32(m2)<<8 | uint32(m3)
	switch monthCode {
	case 0x4A616E: // "Jan"
		month = 1
	case 0x466562: // "Feb"
		month = 2
	case 0x4D6172: // "Mar"
		month = 3
	case 0x417072: // "Apr"
		month = 4
	case 0x4D6179: // "May"
		month = 5
	case 0x4A756E: // "Jun"
		month = 6
	case 0x4A756C: // "Jul"
		month = 7
	case 0x417567: // "Aug"
		month = 8
	case 0x536570: // "Sep"
		month = 9
	case 0x4F6374: // "Oct"
		month = 10
	case 0x4E6F76: // "Nov"
		month = 11
	case 0x446563: // "Dec"
		month = 12
	default:
		return time.Time{}
	}

	// Use bit masking for faster digit extraction
	year := int(line[start+7]&0x0F)*1000 + int(line[start+8]&0x0F)*100 + int(line[start+9]&0x0F)*10 + int(line[start+10]&0x0F)
	hour := int(line[start+12]&0x0F)*10 + int(line[start+13]&0x0F)
	minute := int(line[start+15]&0x0F)*10 + int(line[start+16]&0x0F)
	second := int(line[start+18]&0x0F)*10 + int(line[start+19]&0x0F)

	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// parseMethodUltraFast extracts HTTP method using first-character optimization
//
// Performance optimizations:
//   - First-byte lookup eliminates string comparisons
//   - Only checks second byte when needed (POST vs PUT disambiguation)
//   - Direct enum return avoids string allocations
//   - Covers all common HTTP methods: GET, POST, PUT, DELETE, HEAD, OPTIONS
//
// Returns: HTTPMethod enum or UNKNOWN for unrecognized methods
func parseMethodUltraFast(line []byte, start, end int) ingestor.HTTPMethod {
	if end <= start {
		return ingestor.UNKNOWN
	}

	// Use first byte for ultra-fast lookup
	switch line[start] {
	case 'G':
		return ingestor.GET
	case 'P':
		if end > start+1 {
			switch line[start+1] {
			case 'O':
				return ingestor.POST
			case 'A':
				return ingestor.PATCH
			}
		}
		return ingestor.PUT
	case 'D':
		return ingestor.DELETE
	case 'H':
		return ingestor.HEAD
	case 'O':
		return ingestor.OPTIONS
	default:
		return ingestor.UNKNOWN
	}
}

// parseBytesUltraFast extracts numeric byte count from log field with loop unrolling
//
// Performance optimizations:
//   - Unrolled loop for numbers ≤8 digits (99.9% of cases)
//   - Bit masking for digit conversion: (digit & 0x0F) faster than (digit - '0')
//   - Early termination on non-digit characters
//   - Handles both small and large numbers efficiently
//
// Typical log byte counts: 0-999999 (6 digits), so unrolled loop is optimal
// Returns: parsed uint32 or 0 for invalid input
func parseBytesUltraFast(line []byte, start, end int) uint32 {
	if start >= end {
		return 0
	}
	// BCE hint: prove line[end-1] is in bounds, eliminating per-iteration bounds check
	if end > len(line) {
		end = len(line)
	}

	result := uint32(0)
	for i := start; i < end; i++ {
		digit := line[i]
		if digit >= '0' && digit <= '9' {
			result = result*10 + uint32(digit&0x0F)
		} else {
			break
		}
	}
	return result
}
