// The MIT License (MIT)
//
// # Copyright (c) 2015 xtaci
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

// [THE GENERALIZED DATA PIPELINE FOR KCP-GO]
//
// Outgoing Data Pipeline:                        Incoming Data Pipeline:
// Stream          (Input Data)                   Packet Network  (Network Interface Card)
//   |                                               |
//   v                                               v
// KCP Output      (Reliable Transport Layer)     Reader/Listener (Reception Queue)
//   |                                               |
//   v                                               v
// TxQueue         (Transmission Queue)           KCP Input       (Reliable Transport Layer)
//   |                                               |
//   v                                               v
// Packet Network  (Network Transmission)         Stream          (Input Data)

package kcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
)

const (
	// maximum packet size (increased to handle KCP segment batching)
	mtuLimit = 4096

	// accept backlog
	acceptBacklog = 128

	// dev backlog
	devBacklog = 2048

	// max batch size
	maxBatchSize = 64
)

var (
	errInvalidOperation = errors.New("invalid operation")
	errTimeout          = timeoutError{}
	errNotOwner         = errors.New("not the owner of this connection")
	errNoPacketConn     = errors.New("packet connection is nil")
	errNoRemoteAddr     = errors.New("remote address is nil")
)

// timeoutError implements net.Error
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// sendRequest defines a write request before encoding and transmission
type sendRequest struct {
	buffer []byte
}

type (
	// UDPSession defines a KCP session implemented by UDP
	UDPSession struct {
		conn    net.PacketConn // the underlying packet connection
		ownConn bool           // true if we created conn internally, false if provided by caller
		kcp     *KCP           // KCP ARQ protocol
		l       *Listener      // pointing to the Listener object if it's been accepted by a Listener

		// kcp receiving is based on packets
		// recvbuf turns packets into stream
		recvbuf []byte
		bufptr  []byte

		// settings
		remote     atomic.Value // remote peer address
		rd         atomic.Value // read deadline
		wd         atomic.Value // write deadline
		ackNoDelay bool         // send ack immediately for each incoming packet(testing purpose)
		writeDelay bool         // delay kcp.flush() for Write() for bulk transfer

		// notifications
		die          chan struct{} // notify current session has Closed
		dieOnce      sync.Once
		chReadEvent  chan struct{} // notify Read() can be called without blocking
		chWriteEvent chan struct{} // notify Write() can be called without blocking

		// socket error handling
		socketReadError      atomic.Value
		socketWriteError     atomic.Value
		chSocketReadError    chan struct{}
		chSocketWriteError   chan struct{}
		socketReadErrorOnce  sync.Once
		socketWriteErrorOnce sync.Once

		// packets waiting to be sent on wire
		chPostProcessing chan sendRequest

		// platform-dependent optimizations
		platform platform

		// rate limiter (bytes per second)
		rateLimiter atomic.Value

		mu sync.Mutex
	}

	setReadBuffer interface {
		SetReadBuffer(bytes int) error
	}

	setWriteBuffer interface {
		SetWriteBuffer(bytes int) error
	}

	setDSCP interface {
		SetDSCP(int) error
	}
)

// newUDPSession create a new udp session for client or server
func newUDPSession(conv uint32, l *Listener, conn net.PacketConn, ownConn bool, remote net.Addr) *UDPSession {
	sess := new(UDPSession)
	sess.die = make(chan struct{})
	sess.chReadEvent = make(chan struct{}, 1)
	sess.chWriteEvent = make(chan struct{}, 1)
	sess.chSocketReadError = make(chan struct{})
	sess.chSocketWriteError = make(chan struct{})
	sess.chPostProcessing = make(chan sendRequest, devBacklog)
	sess.remote.Store(remote)
	sess.conn = conn
	sess.ownConn = ownConn
	sess.l = l
	sess.recvbuf = make([]byte, mtuLimit)
	sess.initPlatform()

	sess.kcp = NewKCP(conv, func(buf []byte, size int) {
		// A basic check for the minimum packet size
		if size >= IKCP_OVERHEAD {
			// make a copy
			bts := defaultBufferPool.Get()
			copy(bts, buf[:size])

			// delivery to post processing (BLOCKING to ensure NO packet drops)
			// This is critical for uninterruptible proxy - we NEVER drop packets
			select {
			case sess.chPostProcessing <- sendRequest{buffer: bts[:size]}:
			case <-sess.die:
				return
				// NO default case - block until we can send to guarantee delivery
			}
		}
	})

	// Set Default MTU
	if !sess.SetMtu(IKCP_MTU_DEF) {
		panic("Overhead too large")
	}

	// create post-processing goroutine
	go sess.postProcess()

	if sess.l == nil { // it's a client connection
		go sess.readLoop()
		atomic.AddUint64(&DefaultSnmp.ActiveOpens, 1)
	} else {
		atomic.AddUint64(&DefaultSnmp.PassiveOpens, 1)
	}

	// start per-session updater
	SystemTimedSched.Put(sess.update, time.Now())

	currestab := atomic.AddUint64(&DefaultSnmp.CurrEstab, 1)
	maxconn := atomic.LoadUint64(&DefaultSnmp.MaxConn)
	if currestab > maxconn {
		atomic.CompareAndSwapUint64(&DefaultSnmp.MaxConn, maxconn, currestab)
	}

	return sess
}

// Read implements net.Conn
func (s *UDPSession) Read(b []byte) (n int, err error) {
RESET_TIMER:
	var timeout *time.Timer
	// deadline for current reading operation
	var c <-chan time.Time
	if trd, ok := s.rd.Load().(time.Time); ok && !trd.IsZero() {
		timeout = time.NewTimer(time.Until(trd))
		c = timeout.C
		defer timeout.Stop()
	}

	for {
		s.mu.Lock()
		// bufptr points to the current position of recvbuf,
		// if previous 'b' is insufficient to accommodate the data, the
		// remaining data will be stored in bufptr for next read.
		if len(s.bufptr) > 0 {
			n = copy(b, s.bufptr)
			s.bufptr = s.bufptr[n:]
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		if size := s.kcp.PeekSize(); size > 0 { // peek data size from kcp
			// if 'b' is large enough to accommodate the data, read directly
			// from kcp.recv() to 'b', like 'DMA'.
			if len(b) >= size {
				s.kcp.Recv(b)
				s.mu.Unlock()
				atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(size))
				return size, nil
			}

			// otherwise, read to recvbuf first, then copy to 'b'.
			// dynamically adjust the buffer size to the maximum of 'packet size' when necessary.
			if cap(s.recvbuf) < size {
				// usually recvbuf has a size of maximum packet size
				s.recvbuf = make([]byte, size)
			}

			// resize the length of recvbuf to match the data size
			s.recvbuf = s.recvbuf[:size]
			s.kcp.Recv(s.recvbuf)    // read data to recvbuf first
			n = copy(b, s.recvbuf)   // then copy bytes to 'b' as many as possible
			s.bufptr = s.recvbuf[n:] // pointer update

			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesReceived, uint64(n))
			return n, nil
		}

		s.mu.Unlock()

		// if it runs here, that means we have to block the call, and wait until the
		// next data packet arrives.
		select {
		case <-s.chReadEvent:
			if timeout != nil {
				timeout.Stop()
				goto RESET_TIMER
			}
		case <-c:
			return 0, errors.WithStack(errTimeout)
		case <-s.chSocketReadError:
			return 0, s.socketReadError.Load().(error)
		case <-s.die:
			return 0, errors.WithStack(io.ErrClosedPipe)
		}
	}
}

// Write implements net.Conn
func (s *UDPSession) Write(b []byte) (n int, err error) { return s.WriteBuffers([][]byte{b}) }

// WriteBuffers write a vector of byte slices to the underlying connection
func (s *UDPSession) WriteBuffers(v [][]byte) (n int, err error) {
RESET_TIMER:
	var timeout *time.Timer
	var c <-chan time.Time
	if twd, ok := s.wd.Load().(time.Time); ok && !twd.IsZero() {
		timeout = time.NewTimer(time.Until(twd))
		c = timeout.C
		defer timeout.Stop()
	}

	for {
		// check for connection close and socket error
		select {
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.die:
			return 0, errors.WithStack(io.ErrClosedPipe)
		default:
		}

		s.mu.Lock()

		// make sure write do not overflow the max sliding window on both side
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			// transmit all data sequentially, make sure every packet size is within 'mss'
			for _, b := range v {
				n += len(b)
				// handle each slice for packet splitting
				for {
					if len(b) <= int(s.kcp.mss) {
						s.kcp.Send(b)
						break
					} else {
						s.kcp.Send(b[:s.kcp.mss])
						b = b[s.kcp.mss:]
					}
				}
			}

			waitsnd = s.kcp.WaitSnd()
			if waitsnd >= int(s.kcp.snd_wnd) || !s.writeDelay {
				// put the packets on wire immediately if the inflight window is full
				// or if we've specified write no delay(NO merging of outgoing bytes)
				// we don't have to wait until the periodical update() procedure uncorks.
				s.kcp.flush(IKCP_FLUSH_FULL)
			}
			s.mu.Unlock()
			atomic.AddUint64(&DefaultSnmp.BytesSent, uint64(n))
			return n, nil
		}

		s.mu.Unlock()

		// if it runs here, that means we have to block the call, and wait until the
		// transmit buffer to become available again.
		select {
		case <-s.chWriteEvent:
			if timeout != nil {
				timeout.Stop()
				goto RESET_TIMER
			}
		case <-c:
			return 0, errors.WithStack(errTimeout)
		case <-s.chSocketWriteError:
			return 0, s.socketWriteError.Load().(error)
		case <-s.die:
			return 0, errors.WithStack(io.ErrClosedPipe)
		}
	}
}

func (s *UDPSession) isClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

// Close closes the connection.
func (s *UDPSession) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})

	if !once {
		return errors.WithStack(io.ErrClosedPipe)
	}

	atomic.AddUint64(&DefaultSnmp.CurrEstab, ^uint64(0))

	// try best to send all queued messages especially the data in txqueue
	s.mu.Lock()
	s.kcp.flush((IKCP_FLUSH_FULL))
	s.mu.Unlock()

	if s.l != nil { // belongs to listener
		s.l.closeSession(s.kcp.conv)
		return nil
	}

	if s.ownConn { // client socket close
		return s.conn.Close()
	}

	return nil
}

// LocalAddr returns the local network address. The Addr returned is shared by all invocations of LocalAddr, so do not modify it.
func (s *UDPSession) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr returns the remote network address. The Addr returned is shared by all invocations of RemoteAddr, so do not modify it.
func (s *UDPSession) RemoteAddr() net.Addr { return s.remote.Load().(net.Addr) }

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (s *UDPSession) SetDeadline(t time.Time) error {
	s.rd.Store(t)
	s.wd.Store(t)
	s.notifyReadEvent()
	s.notifyWriteEvent()
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (s *UDPSession) SetReadDeadline(t time.Time) error {
	s.rd.Store(t)
	s.notifyReadEvent()
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (s *UDPSession) SetWriteDeadline(t time.Time) error {
	s.wd.Store(t)
	s.notifyWriteEvent()
	return nil
}

// SetWriteDelay delays write for bulk transfer until the next update interval
func (s *UDPSession) SetWriteDelay(delay bool) {
	s.mu.Lock()
	s.writeDelay = delay
	s.mu.Unlock()
}

// SetWindowSize set maximum window size
func (s *UDPSession) SetWindowSize(sndwnd, rcvwnd int) {
	s.mu.Lock()
	s.kcp.WndSize(sndwnd, rcvwnd)
	s.mu.Unlock()
}

// SetMtu sets the maximum transmission unit(not including UDP header)
func (s *UDPSession) SetMtu(mtu int) bool {
	mtu = min(mtuLimit, mtu)

	s.mu.Lock()
	defer s.mu.Unlock()
	ret := s.kcp.SetMtu(mtu) // kcp mtu is not including udp header
	return ret == 0
}

// Deprecated: toggles the stream mode on/off
func (s *UDPSession) SetStreamMode(enable bool) {
	s.mu.Lock()
	if enable {
		s.kcp.stream = 1
	} else {
		s.kcp.stream = 0
	}
	s.mu.Unlock()
}

// SetACKNoDelay changes ack flush option, set true to flush ack immediately,
func (s *UDPSession) SetACKNoDelay(nodelay bool) {
	s.mu.Lock()
	s.ackNoDelay = nodelay
	s.mu.Unlock()
}

// SetNoDelay calls nodelay() of kcp
// https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration
func (s *UDPSession) SetDeadLink(deadlink uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kcp.SetDeadLink(deadlink)
}

func (s *UDPSession) SetNoDelay(nodelay, interval, resend, nc int) {
	s.mu.Lock()
	s.kcp.NoDelay(nodelay, interval, resend, nc)
	s.mu.Unlock()
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
//
// if the underlying connection has implemented `func SetDSCP(int) error`, SetDSCP() will invoke
// this function instead.
//
// It has no effect if it's accepted from Listener.
func (s *UDPSession) SetDSCP(dscp int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l != nil {
		return errInvalidOperation
	}

	// interface enabled
	if ts, ok := s.conn.(setDSCP); ok {
		return ts.SetDSCP(dscp)
	}

	if nc, ok := s.conn.(net.Conn); ok {
		var succeed bool
		if err := ipv4.NewConn(nc).SetTOS(dscp << 2); err == nil {
			succeed = true
		}
		if err := ipv6.NewConn(nc).SetTrafficClass(dscp); err == nil {
			succeed = true
		}

		if succeed {
			return nil
		}
	}
	return errInvalidOperation
}

// SetReadBuffer sets the socket read buffer, no effect if it's accepted from Listener
func (s *UDPSession) SetReadBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setReadBuffer); ok {
			return nc.SetReadBuffer(bytes)
		}
	}
	return errInvalidOperation
}

// SetWriteBuffer sets the socket write buffer, no effect if it's accepted from Listener
func (s *UDPSession) SetWriteBuffer(bytes int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		if nc, ok := s.conn.(setWriteBuffer); ok {
			return nc.SetWriteBuffer(bytes)
		}
	}
	return errInvalidOperation
}

// SetRateLimit sets the rate limit for this session in bytes per second,
// by setting to 0 will disable rate limiting.
func (s *UDPSession) SetRateLimit(bytesPerSecond uint32) {
	var limiter *rate.Limiter
	if bytesPerSecond == 0 {
		limiter = rate.NewLimiter(rate.Inf, maxBatchSize*mtuLimit)
	} else {
		limiter = rate.NewLimiter(rate.Limit(bytesPerSecond), maxBatchSize*mtuLimit)
	}

	s.rateLimiter.Store(limiter)
}

// SetLogger configures the kcp trace logger
func (s *UDPSession) SetLogger(mask KCPLogType, logger logoutput_callback) {
	s.kcp.SetLogger(mask, logger)
}

// Control applys a procedure to the underly socket fd.
// CAUTION: BE VERY CAREFUL TO USE THIS FUNCTION, YOU MAY BREAK THE PROTOCOL.
func (s *UDPSession) Control(f func(conn net.PacketConn) error) error {
	if !s.ownConn {
		return errNotOwner
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return f(s.conn)
}

// a goroutine to handle post processing of kcp and make the critical section smaller
// pipeline for outgoing packets (from ARQ to network)
//
//	KCP output -> TxQueue
func (s *UDPSession) postProcess() {
	txqueue := make([]ipv4.Message, 0, devBacklog)
	chDie := s.die

	ctx := context.Background()
	bytesToSend := 0
	for {
		select {
		case req := <-s.chPostProcessing: // dequeue from post processing
			buf := req.buffer

			// 3. TxQueue
			var msg ipv4.Message
			msg.Addr = s.RemoteAddr()

			// original copy, move buf to txqueue directly
			msg.Buffers = [][]byte{buf}
			bytesToSend += len(buf)
			txqueue = append(txqueue, msg)

			// transmit when chPostProcessing is empty or we've reached max batch size
			if len(s.chPostProcessing) == 0 || len(txqueue) >= maxBatchSize {
				if limiter, ok := s.rateLimiter.Load().(*rate.Limiter); ok {
					// WaitN only returns error if the limiter is misconfigured
					// or context is cancelled. In either case, we continue sending.
					_ = limiter.WaitN(ctx, bytesToSend)
				}
				s.tx(txqueue)
				s.kcp.debugLog(IKCP_LOG_OUTPUT, "conv", s.kcp.conv, "datalen", bytesToSend)
				// recycle
				for k := range txqueue {
					defaultBufferPool.Put(txqueue[k].Buffers[0])
					txqueue[k].Buffers = nil
				}
				txqueue = txqueue[:0]
				bytesToSend = 0
			}

			// re-enable die channel
			chDie = s.die

		case <-chDie:
			// remaining packets in txqueue should be sent out
			if len(s.chPostProcessing) > 0 {
				chDie = nil // block chDie temporarily
				continue
			}
			return
		}
	}
}

// sess update to trigger protocol
func (s *UDPSession) update() {
	select {
	case <-s.die:
	default:
		s.mu.Lock()
		interval := s.kcp.flush(IKCP_FLUSH_FULL)
		waitsnd := s.kcp.WaitSnd()
		if waitsnd < int(s.kcp.snd_wnd) {
			s.notifyWriteEvent()
		}
		s.mu.Unlock()
		// self-synchronized timed scheduling
		SystemTimedSched.Put(s.update, time.Now().Add(time.Duration(interval)*time.Millisecond))
	}
}

// GetConv gets conversation id of a session
func (s *UDPSession) GetConv() uint32 { return s.kcp.conv }

// GetRTO gets current rto of the session
func (s *UDPSession) GetRTO() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rto
}

// GetSRTT gets current srtt of the session
func (s *UDPSession) GetSRTT() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_srtt
}

// GetRTTVar gets current rtt variance of the session
func (s *UDPSession) GetSRTTVar() int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kcp.rx_rttvar
}

func (s *UDPSession) notifyReadEvent() {
	select {
	case s.chReadEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) notifyWriteEvent() {
	select {
	case s.chWriteEvent <- struct{}{}:
	default:
	}
}

func (s *UDPSession) notifyReadError(err error) {
	s.socketReadErrorOnce.Do(func() {
		s.socketReadError.Store(err)
		close(s.chSocketReadError)
	})
}

func (s *UDPSession) notifyWriteError(err error) {
	s.socketWriteErrorOnce.Do(func() {
		s.socketWriteError.Store(err)
		close(s.chSocketWriteError)
	})
}

// packet input pipeline:
// network -> [KCP input ->] stream -> application
func (s *UDPSession) packetInput(data []byte) {
	// basic check for minimum packet size
	if len(data) < IKCP_OVERHEAD {
		atomic.AddUint64(&DefaultSnmp.KCPInErrors, 1)
		return
	}

	s.kcpInput(data)
}

// kcpInput inputs a packet into kcp
func (s *UDPSession) kcpInput(data []byte) {
	atomic.AddUint64(&DefaultSnmp.InPkts, 1)
	atomic.AddUint64(&DefaultSnmp.InBytes, uint64(len(data)))

	s.mu.Lock()
	defer s.mu.Unlock()

	if ret := s.kcp.Input(data, IKCP_PACKET_REGULAR, s.ackNoDelay); ret != 0 {
		atomic.AddUint64(&DefaultSnmp.KCPInErrors, 1)
	}

	if n := s.kcp.PeekSize(); n > 0 {
		s.notifyReadEvent()
	}

	waitsnd := s.kcp.WaitSnd()
	if waitsnd < int(s.kcp.snd_wnd) {
		s.notifyWriteEvent()
	}
}

type (
	// Listener defines a server which will be waiting to accept incoming connections
	Listener struct {
		conn    net.PacketConn // the underlying packet connection
		ownConn bool           // true if we created conn internally, false if provided by caller

		sessions    map[uint32]*UDPSession // all sessions accepted by this Listener
		sessionLock sync.RWMutex
		chAccepts   chan *UDPSession // Listen() backlog

		die     chan struct{} // notify the listener has closed
		dieOnce sync.Once

		// socket error handling
		socketReadError     atomic.Value
		chSocketReadError   chan struct{}
		socketReadErrorOnce sync.Once

		rd atomic.Value // read deadline for Accept()
	}
)

// packet input stage
func (l *Listener) packetInput(data []byte, addr net.Addr) {
	// basic check for minimum kcp packet size
	if len(data) < IKCP_OVERHEAD {
		return
	}

	// extract conversation id from packet (first 4 bytes)
	conv := binary.LittleEndian.Uint32(data)

	l.sessionLock.RLock()
	s, exist := l.sessions[conv]
	l.sessionLock.RUnlock()

	// on an existing connection
	if exist {
		// Update the session's address mapping if roamed
		if s.RemoteAddr().String() != addr.String() {
			s.remote.Store(addr)
		}
		s.kcpInput(data)
		return
	}

	// Now we have a valid conversation id here without a session object, create a new session.
	// do not let the new sessions overwhelm accept queue
	if len(l.chAccepts) >= cap(l.chAccepts) {
		return
	}

	// new session
	s = newUDPSession(conv, l, l.conn, false, addr)
	s.kcpInput(data)
	l.sessionLock.Lock()
	l.sessions[conv] = s
	l.sessionLock.Unlock()
	l.chAccepts <- s
}

func (l *Listener) notifyReadError(err error) {
	l.socketReadErrorOnce.Do(func() {
		l.socketReadError.Store(err)
		close(l.chSocketReadError)

		// propagate read error to all sessions
		l.sessionLock.RLock()
		for _, s := range l.sessions {
			s.notifyReadError(err)
		}
		l.sessionLock.RUnlock()
	})
}

// SetReadBuffer sets the socket read buffer for the Listener
func (l *Listener) SetReadBuffer(bytes int) error {
	if conn, ok := l.conn.(setReadBuffer); ok {
		return conn.SetReadBuffer(bytes)
	}
	return errInvalidOperation
}

// SetWriteBuffer sets the socket write buffer for the Listener
func (l *Listener) SetWriteBuffer(bytes int) error {
	if conn, ok := l.conn.(setWriteBuffer); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return errInvalidOperation
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
//
// if the underlying connection has implemented `func SetDSCP(int) error`, SetDSCP() will invoke
// this function instead.
func (l *Listener) SetDSCP(dscp int) error {
	// interface enabled
	if conn, ok := l.conn.(setDSCP); ok {
		return conn.SetDSCP(dscp)
	}

	conn, ok := l.conn.(net.Conn)
	if !ok {
		return errInvalidOperation
	}

	var succeed bool
	if err := ipv4.NewConn(conn).SetTOS(dscp << 2); err == nil {
		succeed = true
	}

	if err := ipv6.NewConn(conn).SetTrafficClass(dscp); err == nil {
		succeed = true
	}

	if succeed {
		return nil
	}

	return errInvalidOperation
}

// Accept implements the Accept method in the Listener interface; it waits for the next call and returns a generic Conn.
func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptKCP()
}

// AcceptKCP accepts a KCP connection
func (l *Listener) AcceptKCP() (*UDPSession, error) {
	var timeout <-chan time.Time
	if tdeadline, ok := l.rd.Load().(time.Time); ok && !tdeadline.IsZero() {
		timer := time.NewTimer(time.Until(tdeadline))
		defer timer.Stop()

		timeout = timer.C
	}

	select {
	case <-timeout:
		return nil, errors.WithStack(errTimeout)
	case c := <-l.chAccepts:
		return c, nil
	case <-l.chSocketReadError:
		return nil, l.socketReadError.Load().(error)
	case <-l.die:
		return nil, errors.WithStack(io.ErrClosedPipe)
	}
}

// SetDeadline sets the deadline associated with the listener. A zero time value disables the deadline.
func (l *Listener) SetDeadline(t time.Time) error {
	l.SetReadDeadline(t)
	l.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (l *Listener) SetReadDeadline(t time.Time) error {
	l.rd.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (l *Listener) SetWriteDeadline(t time.Time) error {
	return errInvalidOperation
}

// Close stops listening on the UDP address, and closes the socket
func (l *Listener) Close() error {
	var once bool
	l.dieOnce.Do(func() {
		close(l.die)
		once = true
	})

	if !once {
		return errors.WithStack(io.ErrClosedPipe)
	}

	if l.ownConn {
		return l.conn.Close()
	}

	return nil
}

// Control applys a procedure to the underly socket fd.
// CAUTION: BE VERY CAREFUL TO USE THIS FUNCTION, YOU MAY BREAK THE PROTOCOL.
func (l *Listener) Control(f func(conn net.PacketConn) error) error {
	l.sessionLock.Lock()
	defer l.sessionLock.Unlock()

	return f(l.conn)
}

// closeSession notify the listener that a session has closed
func (l *Listener) closeSession(conv uint32) (ret bool) {
	l.sessionLock.Lock()
	defer l.sessionLock.Unlock()

	if _, ok := l.sessions[conv]; ok {
		delete(l.sessions, conv)
		return true
	}
	return false
}

// Addr returns the listener's network address, The Addr returned is shared by all invocations of Addr, so do not modify it.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
