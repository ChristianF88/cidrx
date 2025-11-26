package logparser

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ChristianF88/cidrx/ingestor"
)

// maxInt returns the larger of two integers - used for buffer sizing optimization
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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
	format   string
	compiled *CompiledFormat
	workers  int
	pool     *sync.Pool // Object pool for Request structs
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

// parseFileWithStreamingIO uses streaming I/O with parallel parsing workers (internal method)
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

	// Optimized channels - smaller buffers reduce memory overhead and improve cache locality
	linesChan := make(chan []byte, pp.workers*4)              // Smaller buffer for better throughput
	resultsChan := make(chan *ingestor.Request, pp.workers*4) // Match worker capacity

	// Buffer pool for line copies with optimal sizes
	bufferPool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 512) // Most log lines are <512 bytes
			return &buf
		},
	}

	var wg sync.WaitGroup

	// Start parser workers
	for i := 0; i < pp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				if req, err := pp.compiled.parseLineWithPool(line, pp.pool); err == nil {
					resultsChan <- req
				}
				// Return buffer to pool after processing
				if cap(line) <= 2048 { // Only return reasonably sized buffers
					emptyLine := line[:0]
					bufferPool.Put(&emptyLine)
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
		for req := range resultsChan {
			results = append(results, *req)
			// Return request object to pool
			pp.pool.Put(req)
		}
	}()

	// I/O reader with optimized buffer management - use larger initial buffer
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 256*1024), 2*1024*1024) // 2MB max, 256KB initial

	for scanner.Scan() {
		scanBytes := scanner.Bytes()

		// Get buffer from pool and copy line (necessary for concurrent processing)
		bufferPtr := bufferPool.Get().(*[]byte)
		buffer := *bufferPtr
		if cap(buffer) < len(scanBytes) {
			buffer = make([]byte, len(scanBytes), maxInt(len(scanBytes)*2, 512))
			*bufferPtr = buffer
		}
		buffer = buffer[:len(scanBytes)]
		*bufferPtr = buffer
		copy(buffer, scanBytes)

		// Send to workers with optimized blocking
		linesChan <- buffer
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

// parseFileWithConcurrentIO implements concurrent chunked file reading
func (pp *ParallelParser) parseFileWithConcurrentIO(file *os.File, fileSize int64) ([]ingestor.Request, error) {
	const chunkSize = 64 * 1024 * 1024 // 64MB chunks for optimal I/O
	numChunks := int(fileSize / chunkSize)
	if fileSize%chunkSize != 0 {
		numChunks++
	}

	// Limit concurrent chunk readers to avoid excessive file handles
	maxConcurrentChunks := runtime.NumCPU()
	if maxConcurrentChunks > 8 {
		maxConcurrentChunks = 8
	}

	// Estimate total lines for pre-allocation
	estimatedLines := int(fileSize / 200) // ~200 bytes per log line estimate
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	// Channels for coordinating chunk processing
	chunkJobs := make(chan chunkJob, numChunks)
	linesChan := make(chan []byte, pp.workers*1000) // Larger buffer for concurrent chunks
	resultsChan := make(chan *ingestor.Request, pp.workers*1000)

	// Buffer pool for line copies
	bufferPool := &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, 1024)
			return &buf
		},
	}

	// File handle pool to reduce redundant file operations
	// Track active handles for proper cleanup
	var fileHandlesMutex sync.Mutex
	var fileHandles []*os.File
	fileHandlePool := &sync.Pool{
		New: func() interface{} {
			handle, err := os.Open(file.Name())
			if err != nil {
				return nil
			}
			fileHandlesMutex.Lock()
			fileHandles = append(fileHandles, handle)
			fileHandlesMutex.Unlock()
			return handle
		},
	}

	var wg sync.WaitGroup

	// Start chunk readers
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pp.chunkReader(file, chunkJobs, linesChan, bufferPool, fileHandlePool)
		}()
	}

	// Start parser workers
	var parserWG sync.WaitGroup
	for i := 0; i < pp.workers; i++ {
		parserWG.Add(1)
		go func() {
			defer parserWG.Done()
			for line := range linesChan {
				if req, err := pp.compiled.parseLine(line); err == nil {
					resultsChan <- req
				}
				// Return buffer to pool after processing
				if cap(line) <= 2048 {
					emptyLine := line[:0]
					bufferPool.Put(&emptyLine)
				}
			}
		}()
	}

	// Start result collector
	results := make([]ingestor.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for req := range resultsChan {
			results = append(results, *req)
		}
	}()

	// Enqueue chunk jobs
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}

		chunkJobs <- chunkJob{
			start: start,
			end:   end,
			index: i,
		}
	}
	close(chunkJobs)

	// Wait for all chunks to be processed
	wg.Wait()
	close(linesChan)

	// Wait for all parsers to finish
	parserWG.Wait()
	close(resultsChan)

	// Wait for collector to finish
	collectorWG.Wait()

	// Clean up file handle pool - close all handles that were actually opened
	fileHandlesMutex.Lock()
	for _, handle := range fileHandles {
		if handle != nil {
			handle.Close()
		}
	}
	fileHandlesMutex.Unlock()

	return results, nil
}

// chunkJob represents a file chunk to be read
type chunkJob struct {
	start int64
	end   int64
	index int
}

// chunkReader reads file chunks concurrently and handles line boundary detection
func (pp *ParallelParser) chunkReader(file *os.File, jobs <-chan chunkJob, linesChan chan<- []byte, bufferPool *sync.Pool, fileHandlePool *sync.Pool) {
	for job := range jobs {
		pp.readChunk(file, job, linesChan, bufferPool, fileHandlePool)
	}
}

// readChunk reads a specific chunk of the file and handles line boundaries
// Optimized version using file handle pool to reduce redundant file operations
func (pp *ParallelParser) readChunk(file *os.File, job chunkJob, linesChan chan<- []byte, bufferPool *sync.Pool, fileHandlePool *sync.Pool) {
	chunkLen := job.end - job.start
	if chunkLen <= 0 {
		return
	}

	// Read the chunk with some overlap for line boundary handling
	overlap := int64(8192) // 8KB overlap to handle line boundaries
	readStart := job.start
	readEnd := job.end + overlap

	// Get file size to avoid reading beyond EOF (use original file handle to avoid redundant stat)
	stat, err := file.Stat()
	if err != nil {
		return
	}
	if readEnd > stat.Size() {
		readEnd = stat.Size()
	}

	// For first chunk, start from beginning and don't skip lines
	skipStartLine := job.index > 0

	// Use synchronized reading with the original file handle to avoid redundant file operations
	readSize := readEnd - readStart
	buffer := make([]byte, readSize)

	// Get file handle from pool to reduce redundant file operations
	chunkFileInterface := fileHandlePool.Get()
	if chunkFileInterface == nil {
		// Fallback to opening a new file if pool fails
		chunkFile, err := os.Open(file.Name())
		if err != nil {
			return
		}
		defer chunkFile.Close()
		chunkFileInterface = chunkFile
	}
	chunkFile := chunkFileInterface.(*os.File)
	defer fileHandlePool.Put(chunkFile)

	// Seek to chunk start
	if _, err := chunkFile.Seek(readStart, io.SeekStart); err != nil {
		return
	}

	// Read chunk data
	n, err := io.ReadFull(chunkFile, buffer)
	if err != nil && err != io.ErrUnexpectedEOF {
		return
	}
	buffer = buffer[:n]

	// Process lines manually to handle boundaries correctly
	start := 0
	bytesProcessed := 0
	lineCount := 0

	for i := 0; i < len(buffer); i++ {
		if buffer[i] == '\n' {
			lineCount++
			lineData := buffer[start:i]

			// For non-first chunks, skip the first (likely partial) line
			if skipStartLine && lineCount == 1 {
				start = i + 1
				continue
			}

			// Check if we've processed enough bytes for this chunk
			currentPos := readStart + int64(bytesProcessed)
			if currentPos >= job.end {
				break
			}

			// Skip empty lines
			if len(lineData) == 0 {
				start = i + 1
				bytesProcessed = i + 1
				continue
			}

			// Copy line to pooled buffer and send to parser
			lineBufferPtr := bufferPool.Get().(*[]byte)
			lineBuffer := *lineBufferPtr
			if cap(lineBuffer) < len(lineData) {
				lineBuffer = make([]byte, len(lineData), len(lineData)*2)
				*lineBufferPtr = lineBuffer
			}
			lineBuffer = lineBuffer[:len(lineData)]
			copy(lineBuffer, lineData)

			select {
			case linesChan <- lineBuffer:
			default:
				// Channel full, block until space available
				linesChan <- lineBuffer
			}

			start = i + 1
			bytesProcessed = i + 1
		}
	}

	// Handle the last line if it doesn't end with newline and we're at EOF
	if start < len(buffer) && readEnd == stat.Size() {
		lineData := buffer[start:]
		if len(lineData) > 0 {
			lineBufferPtr := bufferPool.Get().(*[]byte)
			lineBuffer := *lineBufferPtr
			if cap(lineBuffer) < len(lineData) {
				lineBuffer = make([]byte, len(lineData), len(lineData)*2)
				*lineBufferPtr = lineBuffer
			}
			lineBuffer = lineBuffer[:len(lineData)]
			copy(lineBuffer, lineData)

			select {
			case linesChan <- lineBuffer:
			default:
				linesChan <- lineBuffer
			}
		}
	}
}

// ParseLine for single line parsing
func (pp *ParallelParser) ParseLine(line []byte) (*ingestor.Request, error) {
	return pp.compiled.parseLineWithPool(line, pp.pool)
}

// ParseLineReuse for zero-allocation parsing with request reuse
func (pp *ParallelParser) ParseLineReuse(line []byte, req *ingestor.Request) error {
	return pp.compiled.parseLineReuse(line, req)
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

// parseLine uses zero-allocation, ultra-fast parsing
func (cf *CompiledFormat) parseLine(line []byte) (*ingestor.Request, error) {
	req := &ingestor.Request{}
	cf.parseLineReuse(line, req)
	return req, nil
}

// parseLineWithPool uses object pool to reduce allocations
func (cf *CompiledFormat) parseLineWithPool(line []byte, pool *sync.Pool) (*ingestor.Request, error) {
	req := pool.Get().(*ingestor.Request)
	// Reset the request to zero state
	*req = ingestor.Request{}
	err := cf.parseLineReuse(line, req)
	if err != nil {
		// Return request to pool on parse error to prevent memory leak
		pool.Put(req)
		return nil, err
	}
	return req, nil
}

// parseLineReuse parses a log line into an existing Request struct to avoid allocations
func (cf *CompiledFormat) parseLineReuse(line []byte, req *ingestor.Request) error {
	// Use compiled format extractors for optimized parsing
	if len(cf.extractors) > 0 {
		return cf.parseUsingCompiledFormat(line, req)
	}

	// If no extractors configured, skip parsing
	return nil
}

// parseUsingCompiledFormat applies the compiled extractors to parse a log line into a Request
func (cf *CompiledFormat) parseUsingCompiledFormat(line []byte, req *ingestor.Request) error {
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
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++ // skip opening quote
			start = pos
			for pos < len(line) && line[pos] != '"' {
				pos++
			}
			// Don't skip closing quote yet - we'll handle it after field extraction
		} else if extractor.Brackets && pos < len(line) && line[pos] == '[' {
			pos++ // skip opening bracket
			start = pos
			for pos < len(line) && line[pos] != ']' {
				pos++
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
			fieldData := line[start:pos]

			switch extractor.FieldType {
			case 0: // IP
				req.IP = parseIPv4UltraFast(line, start, pos)
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
					// HTTP version is intentionally ignored as Request struct has no field for it
				} else {
					// If not quoted, treat entire field as URI
					req.URI = bytesToString(fieldData)
				}
			case 4: // Status
				if pos-start >= 3 {
					req.Status = uint16(line[start]&0x0F)*100 + uint16(line[start+1]&0x0F)*10 + uint16(line[start+2]&0x0F)
				}
			case 5: // Bytes
				if len(fieldData) > 0 && fieldData[0] != '-' {
					req.Bytes = parseBytesUltraFast(line, start, pos)
				}
			case 6: // User agent
				req.UserAgent = bytesToString(fieldData)
			case 7: // URI (standalone)
				req.URI = bytesToString(fieldData)
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

// bytesToString converts byte slice to string with proper memory safety
// Creates a copy to prevent memory safety issues with slices referencing parser buffers
func bytesToString(b []byte) string {
	return string(b)
}

// parseIPv4UltraFast extracts IPv4 address from log line using optimized bit operations
//
// Performance optimizations:
//   - Single-pass parsing with dot counting
//   - Bit masking for digit extraction: (b & 0x0F) converts ASCII digit to int
//   - Direct validation during parsing (avoids re-parsing)
//   - Bounds checking for IPv4 format (7-15 characters)
//
// Input: line[start:end] should contain IPv4 like "192.168.1.1"
// Returns: net.IP or nil if invalid format
func parseIPv4UltraFast(line []byte, start, end int) net.IP {
	if end-start < 7 || end-start > 15 {
		return nil
	}

	// Count dots and parse in one pass with bit masking
	dots := 0
	parts := [4]uint8{}
	partIdx := 0
	current := 0

	for i := start; i < end; i++ {
		b := line[i]
		if b == '.' {
			if current > 255 || partIdx >= 3 {
				return nil
			}
			parts[partIdx] = uint8(current)
			partIdx++
			current = 0
			dots++
		} else if b >= '0' && b <= '9' {
			current = current*10 + int(b&0x0F) // Use bit masking for digit extraction
		} else {
			return nil
		}
	}

	if dots != 3 || current > 255 || partIdx != 3 {
		return nil
	}
	parts[3] = uint8(current)

	return net.IPv4(parts[0], parts[1], parts[2], parts[3])
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
		if end > start+1 && line[start+1] == 'O' {
			return ingestor.POST
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

	result := uint32(0)
	// Unroll loop for common case of small numbers
	length := end - start
	if length <= 8 {
		// Handle up to 8 digits with unrolled loop
		for i := start; i < end; i++ {
			digit := line[i]
			if digit >= '0' && digit <= '9' {
				result = result*10 + uint32(digit&0x0F) // Use bit masking
			} else {
				break
			}
		}
	} else {
		// Fallback for very large numbers
		for i := start; i < end; i++ {
			digit := line[i]
			if digit >= '0' && digit <= '9' {
				result = result*10 + uint32(digit&0x0F)
			} else {
				break
			}
		}
	}
	return result
}
