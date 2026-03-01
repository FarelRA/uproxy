// Package common provides shared utilities used across the uproxy codebase.
package common

import "sync"

// BufferPool is a generic buffer pool for efficient memory reuse
type BufferPool struct {
	pool *sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with the specified buffer size
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf *[]byte) {
	if buf != nil && len(*buf) == p.size {
		p.pool.Put(buf)
	}
}
