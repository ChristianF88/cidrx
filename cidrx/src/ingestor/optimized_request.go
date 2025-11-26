package ingestor

import (
	"time"
)

// OptimizedRequest uses uint32 for IP addresses to eliminate conversions
// This version keeps everything in numeric format until final output
type OptimizedRequest struct {
	Timestamp time.Time // Use native time
	IP        uint32    // Store IP as uint32 - NO MORE net.IP conversions!
	URI       string
	UserAgent string
	Method    HTTPMethod
	Status    uint16 // Smaller type for status code
	Bytes     uint32
}

// ConvertToOptimized converts a regular Request to OptimizedRequest
func (r *Request) ToOptimized() OptimizedRequest {
	return OptimizedRequest{
		Timestamp: r.Timestamp,
		IP:        IPToUint32Fast(r.IP),
		URI:       r.URI,
		UserAgent: r.UserAgent,
		Method:    r.Method,
		Status:    r.Status,
		Bytes:     r.Bytes,
	}
}

// IPToUint32Fast converts net.IP to uint32 efficiently
func IPToUint32Fast(ip []byte) uint32 {
	if len(ip) == 4 {
		// IPv4 address - direct conversion
		return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	} else if len(ip) == 16 {
		// IPv4-mapped IPv6 address - extract last 4 bytes
		return uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
	}
	return 0
}

// Uint32ToIPString converts uint32 back to IP string for output
func Uint32ToIPString(ip uint32) string {
	// Use a pre-allocated byte buffer for ultra-fast conversion
	var buf [15]byte // Max IPv4 length: "255.255.255.255"

	b1 := byte(ip >> 24)
	b2 := byte(ip >> 16)
	b3 := byte(ip >> 8)
	b4 := byte(ip)

	pos := 0

	// Convert first octet
	if b1 >= 100 {
		buf[pos] = '0' + b1/100
		pos++
		buf[pos] = '0' + (b1%100)/10
		pos++
		buf[pos] = '0' + b1%10
		pos++
	} else if b1 >= 10 {
		buf[pos] = '0' + b1/10
		pos++
		buf[pos] = '0' + b1%10
		pos++
	} else {
		buf[pos] = '0' + b1
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert second octet
	if b2 >= 100 {
		buf[pos] = '0' + b2/100
		pos++
		buf[pos] = '0' + (b2%100)/10
		pos++
		buf[pos] = '0' + b2%10
		pos++
	} else if b2 >= 10 {
		buf[pos] = '0' + b2/10
		pos++
		buf[pos] = '0' + b2%10
		pos++
	} else {
		buf[pos] = '0' + b2
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert third octet
	if b3 >= 100 {
		buf[pos] = '0' + b3/100
		pos++
		buf[pos] = '0' + (b3%100)/10
		pos++
		buf[pos] = '0' + b3%10
		pos++
	} else if b3 >= 10 {
		buf[pos] = '0' + b3/10
		pos++
		buf[pos] = '0' + b3%10
		pos++
	} else {
		buf[pos] = '0' + b3
		pos++
	}
	buf[pos] = '.'
	pos++

	// Convert fourth octet
	if b4 >= 100 {
		buf[pos] = '0' + b4/100
		pos++
		buf[pos] = '0' + (b4%100)/10
		pos++
		buf[pos] = '0' + b4%10
		pos++
	} else if b4 >= 10 {
		buf[pos] = '0' + b4/10
		pos++
		buf[pos] = '0' + b4%10
		pos++
	} else {
		buf[pos] = '0' + b4
		pos++
	}

	return string(buf[:pos])
}
