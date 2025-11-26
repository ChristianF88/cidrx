package ingestor

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func parseEventStatic(evt map[string]interface{}, out *Request) error {
	msg, ok := evt["message"].(string)
	if !ok {
		return errors.New("missing message field")
	}

	// Extract timestamp
	start := strings.IndexByte(msg, '[')
	end := strings.IndexByte(msg, ']')
	if start < 0 || end <= start {
		return errors.New("invalid timestamp format")
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", msg[start+1:end])
	if err != nil {
		return fmt.Errorf("timestamp parse error: %w", err)
	}
	out.Timestamp = t.UTC()

	// Extract quoted parts
	quoted := strings.Split(msg, "\"")
	if len(quoted) < 7 {
		return errors.New("malformed log line: not enough quoted parts")
	}

	// Parse request
	requestLine := quoted[1]
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		out.Method = ParseMethod(parts[0])
		out.URI = parts[1]
	} else {
		out.Method = UNKNOWN
	}

	// Status and bytes
	statusAndBytes := strings.TrimSpace(quoted[2])
	fields := strings.Fields(statusAndBytes)
	if len(fields) >= 2 {
		if status, err := strconv.Atoi(fields[0]); err == nil {
			out.Status = uint16(status)
		}
		if bytesSent, err := strconv.Atoi(fields[1]); err == nil {
			out.Bytes = uint32(bytesSent)
		}
	}

	// User agent is quoted[5]
	out.UserAgent = strings.TrimSpace(quoted[5])

	// Final IP is quoted[7]
	ipStr := strings.TrimSpace(quoted[7])
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP at end: %q", ipStr)
	}
	out.IP = ip

	return nil
}

func ParseLogFile(path string) ([]Request, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var requests []Request
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		evt := map[string]interface{}{"message": line}
		var req Request
		if err := parseEventStatic(evt, &req); err != nil {
			// Optionally log or continue
			continue
		}
		requests = append(requests, req)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return requests, nil
}
