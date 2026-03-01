package common

import (
	"testing"
)

func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkBufferPoolConcurrent(b *testing.B) {
	pool := NewBufferPool(2048)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			pool.Put(buf)
		}
	})
}

func BenchmarkBufferPoolWrite(b *testing.B) {
	pool := NewBufferPool(2048)
	data := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		copy(*buf, data)
		pool.Put(buf)
	}
}
