package sliding

import (
	"net"
	"time"

	"github.com/ChristianF88/cidrx/iputils"
	"github.com/ChristianF88/cidrx/trie"
	"github.com/alphadose/haxmap"
)

// --- Sliding Window Wrapper ---

type TimedIp struct {
	Ip               net.IP
	EndpointAllowed  bool
	UserAgentAllowed bool
	Time             time.Time
}

type IpStat struct {
	Last              time.Time
	DeltaT            []time.Duration
	EndpointsAllowed  []bool
	UserAgentsAllowed []bool
	Count             int
}

type SlidingWindow struct {
	Trie       *trie.Trie
	IpQueue    []TimedIp
	IpStats    *haxmap.Map[uint32, IpStat] // ip represented as uint32 (IPv4)
	timeLimit  time.Duration
	maxEntries int
}

func NewSlidingWindowTrie(window time.Duration, maxEntries int) *SlidingWindow {
	return &SlidingWindow{
		Trie:       trie.NewTrie(),
		IpQueue:    make([]TimedIp, 0),
		IpStats:    haxmap.New[uint32, IpStat](1 << 21), // 256M entries preallocated
		timeLimit:  window,
		maxEntries: maxEntries,
	}
}

func insertIntoHaxmap(m *haxmap.Map[uint32, IpStat], ip net.IP, timedIp TimedIp) {
	var skipDeltaT bool = false
	ipUint32 := iputils.IPToUint32(ip)
	stat, exists := m.Get(ipUint32)
	if !exists {
		stat = IpStat{
			Last:              timedIp.Time,
			DeltaT:            make([]time.Duration, 0),
			EndpointsAllowed:  make([]bool, 0),
			UserAgentsAllowed: make([]bool, 0),
			Count:             0,
		}
		skipDeltaT = true
	}

	if !skipDeltaT {
		stat.DeltaT = append(stat.DeltaT, timedIp.Time.Sub(stat.Last))
	}
	stat.EndpointsAllowed = append(stat.EndpointsAllowed, timedIp.EndpointAllowed)
	stat.UserAgentsAllowed = append(stat.UserAgentsAllowed, timedIp.UserAgentAllowed)
	stat.Last = timedIp.Time
	stat.Count++
	m.Set(ipUint32, stat)
}

func deleteFromHaxmap(m *haxmap.Map[uint32, IpStat], ip net.IP) {
	ipUint32 := iputils.IPToUint32(ip)
	stat, exists := m.Get(ipUint32)
	if !exists {
		return
	}
	stat.Count--
	if stat.Count <= 0 {
		m.Del(ipUint32)
		return
	}
	// Remove the first element from DeltaT
	if len(stat.DeltaT) > 0 {
		stat.DeltaT = stat.DeltaT[1:]
	}
	// Remove the first element from EndpointsAllowed/UserAgentsAllowed
	if len(stat.EndpointsAllowed) > 0 {
		stat.EndpointsAllowed = stat.EndpointsAllowed[1:]
	}
	if len(stat.UserAgentsAllowed) > 0 {
		stat.UserAgentsAllowed = stat.UserAgentsAllowed[1:]
	}
	m.Set(ipUint32, stat)
}

func (s *SlidingWindow) InsertNew(timedIPs []TimedIp) {
	s.IpQueue = append(s.IpQueue, timedIPs...)
	for _, timedIP := range timedIPs {
		s.Trie.Insert(timedIP.Ip)
		insertIntoHaxmap(s.IpStats, timedIP.Ip, timedIP)
	}
}

func (s *SlidingWindow) DropOld() {
	// enforce time limit
	cutoff := time.Now().Add(-s.timeLimit)
	idxTime := 0
	for idxTime < len(s.IpQueue) && s.IpQueue[idxTime].Time.Before(cutoff) {
		s.Trie.Delete(s.IpQueue[idxTime].Ip)
		deleteFromHaxmap(s.IpStats, s.IpQueue[idxTime].Ip)
		idxTime++
	}
	// enforce max entries
	remainingLen := len(s.IpQueue) - idxTime
	if remainingLen > s.maxEntries {
		toDelete := remainingLen - s.maxEntries
		for idxLen := 0; idxLen < toDelete; idxLen++ {
			s.Trie.Delete(s.IpQueue[idxTime+idxLen].Ip)
			deleteFromHaxmap(s.IpStats, s.IpQueue[idxTime+idxLen].Ip)
		}
		idxTime += toDelete
	}

	if idxTime > 0 {
		// Efficient memory-releasing slice copy
		s.IpQueue = append([]TimedIp(nil), s.IpQueue[idxTime:]...)
	}
}

func (s *SlidingWindow) Update(timedIPs []TimedIp) {
	s.InsertNew(timedIPs)
	s.DropOld()
}
