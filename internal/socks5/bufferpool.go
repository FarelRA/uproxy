package socks5

import "uproxy/internal/common"

const (
	// udpBufSize is the maximum UDP packet size (64KB - 1 byte)
	udpBufSize = 65535
)

// udpBufferPool is a pool of UDP buffers to reduce allocations
var udpBufferPool = common.NewBufferPool(udpBufSize)

// getUDPBuffer gets a buffer from the pool
func getUDPBuffer() *[]byte {
	return udpBufferPool.Get()
}

// putUDPBuffer returns a buffer to the pool
func putUDPBuffer(buf *[]byte) {
	udpBufferPool.Put(buf)
}
