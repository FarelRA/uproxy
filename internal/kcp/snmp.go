// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

// Snmp defines network statistics indicator
type Snmp struct {
	BytesSent           uint64 // bytes sent from upper level
	BytesReceived       uint64 // bytes received to upper level
	MaxConn             uint64 // max number of connections ever reached
	ActiveOpens         uint64 // accumulated active open connections
	PassiveOpens        uint64 // accumulated passive open connections
	CurrEstab           uint64 // current number of established connections
	InErrs              uint64 // UDP read errors reported from net.PacketConn
	KCPInErrors         uint64 // packet iput errors reported from KCP
	InPkts              uint64 // incoming packets count
	OutPkts             uint64 // outgoing packets count
	InSegs              uint64 // incoming KCP segments
	OutSegs             uint64 // outgoing KCP segments
	InBytes             uint64 // UDP bytes received
	OutBytes            uint64 // UDP bytes sent
	RetransSegs         uint64 // accmulated retransmited segments
	FastRetransSegs     uint64 // accmulated fast retransmitted segments
	EarlyRetransSegs    uint64 // accmulated early retransmitted segments
	LostSegs            uint64 // number of segs inferred as lost
	RepeatSegs          uint64 // number of segs duplicated
	RingBufferSndQueue  uint64 // Len of segments in send queue ring buffer
	RingBufferRcvQueue  uint64 // Len of segments in receive queue ring buffer
	RingBufferSndBuffer uint64 // Len of segments in send buffer ring buffer
}

func newSnmp() *Snmp {
	return new(Snmp)
}

// Header returns all field names

// ToSlice returns current snmp info as slice

// Copy make a copy of current snmp snapshot

// Reset values to zero

// DefaultSnmp is the global KCP connection statistics collector
var DefaultSnmp *Snmp

func init() {
	DefaultSnmp = newSnmp()
}
