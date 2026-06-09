package logparser

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ChristianF88/cidrx/ingestor"
)

// concurrentZeroCopyFormat is the standard Apache combined-style format with the
// IP at the end (matches the real-world example in the repo instructions).
const concurrentZeroCopyFormat = `%^ %^ %^ [%t] "%r" %s %b %^ "%u" "%h"`

// genConcurrentTestLog produces a representative, deterministic Apache-style log
// of n "interesting" lines plus injected edge cases:
//   - valid IPs (varied octet widths so line lengths differ and straddle chunks),
//   - invalid / missing IP lines (kept-but-zero-IP in full mode, counted invalid
//     in IP mode — both paths agree),
//   - quoted UA/URI fields containing spaces.
//
// No '\r' is emitted: the production code does not strip carriage returns, while
// the streaming path (bufio.Scanner) would, so including them would make the two
// paths legitimately differ. We keep inputs to what both paths treat identically.
//
// No blank lines are emitted either: the concurrent reader skips empty lines
// (continue), whereas the streaming reader hands them to the parser which treats
// "" as a (zero-IP) Request. That divergence is a long-standing, pre-existing
// property of the two readers and is orthogonal to the zero-copy change under
// test (both the old slab-copy and the new zero-copy concurrent code skip empty
// lines identically). Real Apache logs contain no blank lines, so excluding them
// keeps the differential comparison faithful to the change being validated.
//
// withTrailingNewline controls whether the file ends in '\n'. The no-trailing
// case specifically exercises readChunkBatched's EOF trailing-line handling.
func genConcurrentTestLog(n int, withTrailingNewline bool) string {
	var b strings.Builder
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0",
		"curl/8.5.0",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"-",
	}
	uris := []string{
		"GET /index.html HTTP/1.1",
		"POST /api/v1/login?next=/dashboard HTTP/1.1",
		"GET /a/very/long/path/segment/that/pads/the/line/out/further HTTP/1.1",
		"HEAD / HTTP/1.0",
	}
	for i := 0; i < n; i++ {
		switch i % 11 {
		case 3:
			// Invalid/missing IP — both paths agree: zero-IP Request in full mode,
			// counted invalid in IP mode.
			b.WriteString(fmt.Sprintf(
				`- - - [10/Oct/2024:13:55:%02d +0000] "%s" 200 1234 "x" "%s" "not-an-ip"`,
				i%60, uris[i%len(uris)], uas[i%len(uas)]))
			b.WriteByte('\n')
		default:
			// Valid line. Vary IP octet widths and byte counts so line lengths
			// differ widely, forcing many lines to straddle small-chunk boundaries.
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+(i%223), (i*7)%256, (i*13)%256, (i*29)%256)
			status := 200 + (i % 5)
			bytesN := (i * 37) % 100000
			b.WriteString(fmt.Sprintf(
				`- - - [10/Oct/2024:13:55:%02d +0000] "%s" %d %d "x" "%s" "%s"`,
				i%60, uris[i%len(uris)], status, bytesN, uas[i%len(uas)], ip))
			b.WriteByte('\n')
		}
	}
	s := b.String()
	if !withTrailingNewline {
		s = strings.TrimRight(s, "\n")
	}
	return s
}

func writeTempLog(t testing.TB, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "concurrent_zerocopy_*.log")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return f.Name()
}

// reqKey is a fully-comparable projection of a Request used to sort and compare
// the multisets produced by the two parsing paths.
type reqKey struct {
	IP        uint32
	Status    uint16
	Method    ingestor.HTTPMethod
	Bytes     uint32
	TimeUnix  int64
	URI       string
	UserAgent string
}

func toReqKey(r ingestor.Request) reqKey {
	return reqKey{
		IP:        r.IPUint32,
		Status:    r.Status,
		Method:    r.Method,
		Bytes:     r.Bytes,
		TimeUnix:  r.Timestamp.UnixNano(),
		URI:       r.URI,
		UserAgent: r.UserAgent,
	}
}

func sortReqKeys(ks []reqKey) {
	sort.Slice(ks, func(i, j int) bool {
		a, b := ks[i], ks[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		if a.Bytes != b.Bytes {
			return a.Bytes < b.Bytes
		}
		if a.TimeUnix != b.TimeUnix {
			return a.TimeUnix < b.TimeUnix
		}
		if a.URI != b.URI {
			return a.URI < b.URI
		}
		if a.UserAgent != b.UserAgent {
			return a.UserAgent < b.UserAgent
		}
		return a.Method < b.Method
	})
}

// parseConcurrentFull drives the concurrent path directly with an overridden
// chunkSize so the >=500MB gate is bypassed and small files produce many chunks.
func parseConcurrentFull(t *testing.T, pp *ParallelParser, path string, chunkSize int64) []ingestor.Request {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	reqs, err := pp.parseFileConcurrentIOChunked(f, st.Size(), chunkSize)
	if err != nil {
		t.Fatalf("parseFileConcurrentIOChunked: %v", err)
	}
	return reqs
}

func parseConcurrentIPs(t *testing.T, pp *ParallelParser, path string, chunkSize int64) ([]uint32, int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	ips, invalid, err := pp.parseFileIPsConcurrentIOChunked(f, st.Size(), chunkSize)
	if err != nil {
		t.Fatalf("parseFileIPsConcurrentIOChunked: %v", err)
	}
	return ips, invalid
}

// TestConcurrentZeroCopy_DiffFullMode asserts that the zero-copy concurrent path
// produces the identical multiset of Requests (every field) as the streaming
// path, across small chunk sizes (forcing many boundary crossings) and both with
// and without a trailing newline.
func TestConcurrentZeroCopy_DiffFullMode(t *testing.T) {
	const nLines = 5000
	// Includes a very small chunk (256B) so nearly every line straddles or aligns
	// to a boundary, plus 1023/4097 (coprime-ish to line lengths) to exercise
	// lines starting exactly at a boundary (the sentinel-byte path).
	chunkSizes := []int64{256, 1023, 4 * 1024, 4097, 64 * 1024}

	for _, trailing := range []bool{true, false} {
		content := genConcurrentTestLog(nLines, trailing)
		path := writeTempLog(t, content)

		pp, err := NewParallelParser(concurrentZeroCopyFormat)
		if err != nil {
			t.Fatalf("NewParallelParser: %v", err)
		}

		streamReqs, err := pp.parseFileWithStreamingIO(path)
		if err != nil {
			t.Fatalf("parseFileWithStreamingIO: %v", err)
		}
		streamKeys := make([]reqKey, len(streamReqs))
		for i, r := range streamReqs {
			streamKeys[i] = toReqKey(r)
		}
		sortReqKeys(streamKeys)

		for _, cs := range chunkSizes {
			concReqs := parseConcurrentFull(t, pp, path, cs)

			if len(concReqs) != len(streamReqs) {
				t.Fatalf("trailing=%v chunk=%d: count mismatch: concurrent=%d streaming=%d (lost/dup line)",
					trailing, cs, len(concReqs), len(streamReqs))
			}

			concKeys := make([]reqKey, len(concReqs))
			for i, r := range concReqs {
				concKeys[i] = toReqKey(r)
			}
			sortReqKeys(concKeys)

			for i := range streamKeys {
				if concKeys[i] != streamKeys[i] {
					t.Fatalf("trailing=%v chunk=%d: field mismatch at sorted index %d:\n concurrent=%+v\n streaming=%+v",
						trailing, cs, i, concKeys[i], streamKeys[i])
				}
			}
		}
	}
}

// TestConcurrentZeroCopy_DiffIPMode asserts the IP-only concurrent path yields
// the identical multiset of IPs and identical invalid count as the streaming
// IP path, across small chunks and trailing-newline variants.
func TestConcurrentZeroCopy_DiffIPMode(t *testing.T) {
	const nLines = 5000
	// Includes a very small chunk (256B) so nearly every line straddles or aligns
	// to a boundary, plus 1023/4097 (coprime-ish to line lengths) to exercise
	// lines starting exactly at a boundary (the sentinel-byte path).
	chunkSizes := []int64{256, 1023, 4 * 1024, 4097, 64 * 1024}

	for _, trailing := range []bool{true, false} {
		content := genConcurrentTestLog(nLines, trailing)
		path := writeTempLog(t, content)

		pp, err := NewParallelParser(concurrentZeroCopyFormat)
		if err != nil {
			t.Fatalf("NewParallelParser: %v", err)
		}
		pp.SkipNonIPFields = true

		streamIPs, streamInvalid, err := pp.parseFileIPsStreamingIO(path)
		if err != nil {
			t.Fatalf("parseFileIPsStreamingIO: %v", err)
		}
		sortedStream := append([]uint32(nil), streamIPs...)
		sort.Slice(sortedStream, func(i, j int) bool { return sortedStream[i] < sortedStream[j] })

		for _, cs := range chunkSizes {
			concIPs, concInvalid := parseConcurrentIPs(t, pp, path, cs)

			if len(concIPs) != len(streamIPs) {
				t.Fatalf("trailing=%v chunk=%d: IP count mismatch: concurrent=%d streaming=%d",
					trailing, cs, len(concIPs), len(streamIPs))
			}
			if concInvalid != streamInvalid {
				t.Fatalf("trailing=%v chunk=%d: invalid count mismatch: concurrent=%d streaming=%d",
					trailing, cs, concInvalid, streamInvalid)
			}

			sortedConc := append([]uint32(nil), concIPs...)
			sort.Slice(sortedConc, func(i, j int) bool { return sortedConc[i] < sortedConc[j] })
			for i := range sortedStream {
				if sortedConc[i] != sortedStream[i] {
					t.Fatalf("trailing=%v chunk=%d: IP multiset mismatch at index %d: concurrent=%d streaming=%d",
						trailing, cs, i, sortedConc[i], sortedStream[i])
				}
			}
		}
	}
}

// BenchmarkConcurrentZeroCopy_Full exercises the zero-copy concurrent full-Request
// path with a small chunk size on a multi-thousand-line file (many chunks,
// boundary crossings). With ReportAllocs the per-line slab copy that used to be
// performed in readChunkBatched is gone: there is now a single allocation per
// chunk (the ReadAt buffer) shared by all of that chunk's line sub-slices, rather
// than an additional full-chunk slab memcpy plus per-batch slab allocations.
func BenchmarkConcurrentZeroCopy_Full(b *testing.B) {
	content := genConcurrentTestLog(50000, true)
	path := writeTempLog(b, content)
	pp, err := NewParallelParser(concurrentZeroCopyFormat)
	if err != nil {
		b.Fatalf("NewParallelParser: %v", err)
	}
	const chunkSize = 64 * 1024

	f, err := os.Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqs, err := pp.parseFileConcurrentIOChunked(f, size, chunkSize)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if len(reqs) == 0 {
			b.Fatal("no requests parsed")
		}
	}
}

// BenchmarkConcurrentZeroCopy_IPOnly exercises the zero-copy concurrent IP-only
// path. Here nothing aliases the line bytes, so each chunk buffer is freed right
// after its lines are parsed; the slab memcpy is likewise eliminated.
func BenchmarkConcurrentZeroCopy_IPOnly(b *testing.B) {
	content := genConcurrentTestLog(50000, true)
	path := writeTempLog(b, content)
	pp, err := NewParallelParser(concurrentZeroCopyFormat)
	if err != nil {
		b.Fatalf("NewParallelParser: %v", err)
	}
	pp.SkipNonIPFields = true
	const chunkSize = 64 * 1024

	f, err := os.Open(path)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ips, _, err := pp.parseFileIPsConcurrentIOChunked(f, size, chunkSize)
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if len(ips) == 0 {
			b.Fatal("no ips parsed")
		}
	}
}
