package socks5

import "sync"

const (
	// UDPBufSize is the maximum UDP packet size (64KB - 1 byte)
	UDPBufSize = 65535
)

// udpBufferPool is a pool of UDP buffers to reduce allocations
var udpBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, UDPBufSize)
		return &buf
	},
}

// getUDPBuffer gets a buffer from the pool
func getUDPBuffer() *[]byte {
	return udpBufferPool.Get().(*[]byte)
}

// putUDPBuffer returns a buffer to the pool
func putUDPBuffer(buf *[]byte) {
	if buf != nil && len(*buf) == UDPBufSize {
		udpBufferPool.Put(buf)
	}
}
