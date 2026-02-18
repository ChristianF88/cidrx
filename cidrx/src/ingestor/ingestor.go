package ingestor

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	lj "github.com/elastic/go-lumber/lj"
	srv2 "github.com/elastic/go-lumber/server/v2"
)

type HTTPMethod uint8

const (
	GET HTTPMethod = iota
	POST
	PUT
	DELETE
	HEAD
	OPTIONS
	PATCH
	UNKNOWN
)

func ParseMethod(m string) HTTPMethod {
	switch m {
	case "GET":
		return GET
	case "POST":
		return POST
	case "PUT":
		return PUT
	case "DELETE":
		return DELETE
	case "HEAD":
		return HEAD
	case "OPTIONS":
		return OPTIONS
	case "PATCH":
		return PATCH
	default:
		return UNKNOWN
	}
}

type Request struct {
	Timestamp time.Time  // Use native time
	IP        net.IP     // Avoid string parsing multiple times (legacy, may be nil)
	URI       string
	UserAgent string
	IPUint32  uint32     // Primary IP storage - eliminates net.IP allocation in parser
	Method    HTTPMethod
	Status    uint16     // Smaller type for status code
	Bytes     uint32
}

// GetIPNet returns the IP as net.IP, deriving from IPUint32 if IP is nil.
// Use this for non-hot-path code that needs net.IP.
func (r *Request) GetIPNet() net.IP {
	if r.IP != nil {
		return r.IP
	}
	if r.IPUint32 == 0 {
		return nil
	}
	return net.IPv4(byte(r.IPUint32>>24), byte(r.IPUint32>>16), byte(r.IPUint32>>8), byte(r.IPUint32))
}

// --- TCP Ingestor using go-lumber v2 ---

type TCPIngestor struct {
	listener    net.Listener
	readTimeout time.Duration // for server
	events      chan *lj.Batch
	server      *srv2.Server
}

func NewTCPIngestor(addr string, readTimeout time.Duration) (*TCPIngestor, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	return &TCPIngestor{
		listener:    ln,
		readTimeout: readTimeout,
		events:      make(chan *lj.Batch, 1000),
	}, nil
}

// Accept starts the lumberjack v2 Server.
func (ing *TCPIngestor) Accept() error {
	srv, err := srv2.NewWithListener(
		ing.listener,
		srv2.Timeout(ing.readTimeout),
	)
	if err != nil {
		return fmt.Errorf("failed to create lumberjack server: %w", err)
	}
	ing.server = srv

	// Pull batches off ReceiveChan and ack them.
	go func() {
		for batch := range ing.server.ReceiveChan() {
			ing.events <- batch
			batch.ACK()
		}
		close(ing.events)
	}()

	return nil
}

func parseEvent(evt map[string]interface{}, out *Request) error {
	msg, ok := evt["message"].(string)
	if !ok {
		return errors.New("missing message field")
	}

	// 1. Extract IP
	spaceIdx := strings.IndexByte(msg, ' ')
	if spaceIdx == -1 {
		return errors.New("invalid log format: no IP")
	}
	ip := net.ParseIP(msg[:spaceIdx])
	if ip == nil {
		return errors.New("invalid IP")
	}
	out.IP = ip

	// 2. Extract timestamp
	start := strings.IndexByte(msg, '[')
	end := strings.IndexByte(msg, ']')
	if start < 0 || end <= start {
		return errors.New("invalid timestamp format")
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", msg[start+1:end])
	if err != nil {
		return err
	}
	out.Timestamp = t

	// 3. Request line (after first quote)
	start = strings.IndexByte(msg[end:], '"')
	if start == -1 {
		return errors.New("missing request start quote")
	}
	start += end + 1
	end = strings.IndexByte(msg[start:], '"')
	if end == -1 {
		return errors.New("missing request end quote")
	}
	end += start
	requestLine := msg[start:end]
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		out.Method = ParseMethod(parts[0])
		out.URI = parts[1]
	}

	// 4. Status and bytes
	fields := strings.Fields(msg[end+2:])
	if len(fields) >= 2 {
		if status, err := strconv.Atoi(fields[0]); err == nil {
			out.Status = uint16(status)
		}
		if bytesSent, err := strconv.Atoi(fields[1]); err == nil {
			out.Bytes = uint32(bytesSent)
		}
	}

	// 5. User-Agent (quoted string after 4th quote)
	q := 0
	start = 0
	for i := 0; i < len(msg); i++ {
		if msg[i] == '"' {
			q++
			if q == 5 {
				start = i + 1
			} else if q == 6 {
				out.UserAgent = msg[start:i]
				break
			}
		}
	}

	return nil
}

func (ing *TCPIngestor) ReadBatch() ([]Request, error) {
	var out []Request

	for {
		select {
		case batch, ok := <-ing.events:
			if !ok {
				return out, nil
			}
			for _, evt := range batch.Events {
				if m, ok := evt.(map[string]interface{}); ok {
					var entry Request
					if err := parseEvent(m, &entry); err == nil {
						out = append(out, entry)
					}
				}
			}
		default:
			// Channel is empty, return what we have
			return out, nil
		}
	}
}

func (ing *TCPIngestor) IsClosed() bool {
	if ing.server == nil {
		return true
	}
	// Check if the server's receive channel is closed by checking events length
	// A zero-length events channel after server init means the goroutine closed it
	select {
	case batch, ok := <-ing.events:
		if !ok {
			return true
		}
		// Put the batch back — avoid losing data
		ing.events <- batch
		return false
	default:
		return false
	}
}

// Close shuts down the server and listener.
func (ing *TCPIngestor) Close() error {
	if ing.server != nil {
		ing.server.Close()
	}
	return ing.listener.Close()
}
