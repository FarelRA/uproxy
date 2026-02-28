package kcp

// Config holds the tuning parameters for a KCP session, highly optimized
// for various network conditions (lossy mobile, high BDP, low latency).
type Config struct {
	NoDelay  int
	Interval int
	Resend   int
	NoCongestionCtrl int
	SndWnd   int
	RcvWnd   int
	MTU      int
}

// Apply applies the configuration to an active UDPSession.
func (c *Config) Apply(session *UDPSession) {
	session.SetNoDelay(c.NoDelay, c.Interval, c.Resend, c.NoCongestionCtrl)
	session.SetWindowSize(c.SndWnd, c.RcvWnd)
	session.SetMtu(c.MTU)
}
