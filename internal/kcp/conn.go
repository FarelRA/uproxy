package kcp

import (
	"crypto/rand"
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

// ServeConn serves KCP protocol for a single packet connection.
func ServeConn(conn net.PacketConn) (*Listener, error) {
	return serveConn(conn, false)
}

func serveConn(conn net.PacketConn, ownConn bool) (*Listener, error) {
	if conn == nil {
		return nil, errNoPacketConn
	}
	l := new(Listener)
	l.conn = conn
	l.ownConn = ownConn
	l.sessions = make(map[uint32]*UDPSession)
	l.chAccepts = make(chan *UDPSession, acceptBacklog)
	l.die = make(chan struct{})
	l.chSocketReadError = make(chan struct{})
	go l.monitor()
	return l, nil
}

// NewConn3 establishes a session and talks KCP protocol over a packet connection.
func NewConn3(convid uint32, raddr net.Addr, conn net.PacketConn) (*UDPSession, error) {
	if conn == nil {
		return nil, errNoPacketConn
	}
	if raddr == nil {
		return nil, errNoRemoteAddr
	}
	return newUDPSession(convid, nil, conn, false, raddr), nil
}

// NewConn2 establishes a session and talks KCP protocol over a packet connection.
func NewConn2(raddr net.Addr, conn net.PacketConn) (*UDPSession, error) {
	var convid uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &convid); err != nil {
		return nil, errors.WithStack(err)
	}
	return NewConn3(convid, raddr, conn)
}

// NewConn establishes a session and talks KCP protocol over a packet connection.
func NewConn(raddr string, conn net.PacketConn) (*UDPSession, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", raddr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return NewConn2(udpaddr, conn)
}
