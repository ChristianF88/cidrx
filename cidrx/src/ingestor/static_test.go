package ingestor

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestParseEvent_LastIPOnly(t *testing.T) {
	logLine := `198.51.10.21 - - [12/Jun/2025:00:00:00 +0000] "GET /dataset/?_substances_limit=0 HTTP/1.0" 200 24552 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36" "172.59.116.230"`

	evt := map[string]interface{}{"message": logLine}
	var req Request
	err := parseEventStatic(evt, &req)
	if err != nil {
		t.Fatalf("parseEvent failed: %v", err)
	}

	wantIP := net.ParseIP("172.59.116.230")
	if !req.IP.Equal(wantIP) {
		t.Errorf("unexpected IP. got=%s want=%s", req.IP, wantIP)
	}

	wantTime := time.Date(2025, time.June, 12, 0, 0, 0, 0, time.UTC)
	if !req.Timestamp.Equal(wantTime) {
		t.Errorf("unexpected timestamp. got=%v want=%v", req.Timestamp, wantTime)
	}

	if req.Method != ParseMethod("GET") {
		t.Errorf("unexpected method. got=%v want=%v", req.Method, ParseMethod("GET"))
	}

	if req.URI != "/dataset/?_substances_limit=0" {
		t.Errorf("unexpected URI. got=%s want=/dataset/?_substances_limit=0", req.URI)
	}

	if req.Status != 200 {
		t.Errorf("unexpected status. got=%d want=200", req.Status)
	}

	if req.Bytes != 24552 {
		t.Errorf("unexpected bytes. got=%d want=24552", req.Bytes)
	}

	wantUA := `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36`
	if req.UserAgent != wantUA {
		t.Errorf("unexpected UserAgent. got=%s", req.UserAgent)
	}
}

func TestParseLogFile(t *testing.T) {
	logLines := []string{
		`198.51.10.21 - - [12/Jun/2025:00:00:00 +0000] "GET /dataset/?_substances_limit=0 HTTP/1.0" 200 24552 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36" "172.59.116.230"`,
		`198.51.10.21 - - [12/Jun/2025:00:00:00 +0000] "GET /dataset/?_substances_limit=0 HTTP/1.0" 200 84209 "-" "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" "201.151.118.197"`,
		`198.51.10.21 - - [12/Jun/2025:00:00:00 +0000] "GET /dataset/?_substances_limit=0 HTTP/1.0" 302 173473 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.1150.52 Safari/537.36" "23.251.65.196"`,
	}
	tmpFile, err := os.CreateTemp("", "logtest-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, line := range logLines {
		_, _ = tmpFile.WriteString(line + "\n")
	}
	tmpFile.Close()

	requests, err := ParseLogFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseLogFile returned error: %v", err)
	}

	if len(requests) != len(logLines) {
		t.Fatalf("unexpected number of parsed requests: got %d, want %d", len(requests), len(logLines))
	}

	tests := []struct {
		wantIP   string
		wantCode uint16
	}{
		{"172.59.116.230", 200},
		{"201.151.118.197", 200},
		{"23.251.65.196", 302},
	}

	for i, req := range requests {
		wantIP := net.ParseIP(tests[i].wantIP)
		if !req.IP.Equal(wantIP) {
			t.Errorf("request %d: wrong IP. got %s, want %s", i, req.IP, wantIP)
		}
		if req.Status != tests[i].wantCode {
			t.Errorf("request %d: wrong status. got %d, want %d", i, req.Status, tests[i].wantCode)
		}
		if req.Method != ParseMethod("GET") {
			t.Errorf("unexpected method. got=%v want=%v", req.Method, ParseMethod("GET"))
		}
	}
}
