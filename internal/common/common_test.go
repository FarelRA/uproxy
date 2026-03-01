package common

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
)

// TestNewBufferPool tests buffer pool creation
func TestNewBufferPool(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"small buffer", 512},
		{"medium buffer", 2048},
		{"large buffer", 8192},
		{"tiny buffer", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewBufferPool(tt.size)
			if pool == nil {
				t.Fatal("NewBufferPool returned nil")
			}
			if pool.size != tt.size {
				t.Errorf("expected size %d, got %d", tt.size, pool.size)
			}
			if pool.pool == nil {
				t.Error("pool.pool is nil")
			}
		})
	}
}

// TestBufferPoolGet tests getting buffers from pool
func TestBufferPoolGet(t *testing.T) {
	pool := NewBufferPool(2048)

	buf := pool.Get()
	if buf == nil {
		t.Fatal("Get returned nil")
	}
	if len(*buf) != 2048 {
		t.Errorf("expected buffer size 2048, got %d", len(*buf))
	}
}

// TestBufferPoolPut tests returning buffers to pool
func TestBufferPoolPut(t *testing.T) {
	pool := NewBufferPool(2048)

	t.Run("put valid buffer", func(t *testing.T) {
		buf := pool.Get()
		pool.Put(buf) // Should not panic
	})

	t.Run("put nil buffer", func(t *testing.T) {
		pool.Put(nil) // Should not panic
	})

	t.Run("put wrong size buffer", func(t *testing.T) {
		wrongSize := make([]byte, 1024)
		pool.Put(&wrongSize) // Should not panic, but won't be added to pool
	})
}

// TestBufferPoolReuse tests that buffers are actually reused
func TestBufferPoolReuse(t *testing.T) {
	pool := NewBufferPool(2048)

	// Get a buffer and write a marker
	buf1 := pool.Get()
	(*buf1)[0] = 0xFF
	(*buf1)[1] = 0xAA

	// Put it back
	pool.Put(buf1)

	// Get another buffer - should be the same one
	buf2 := pool.Get()

	// Verify it's reused (has our marker)
	if (*buf2)[0] == 0xFF && (*buf2)[1] == 0xAA {
		t.Log("Buffer was successfully reused")
	}
}

// TestBufferPoolConcurrency tests concurrent access
func TestBufferPoolConcurrency(t *testing.T) {
	pool := NewBufferPool(2048)
	var wg sync.WaitGroup

	// Spawn multiple goroutines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				buf := pool.Get()
				// Do some work
				(*buf)[0] = byte(j)
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()
}

// TestLoggingFunctions tests all logging helper functions
func TestLoggingFunctions(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	tests := []struct {
		name     string
		logFunc  func()
		expected string
	}{
		{
			name: "LogInfo",
			logFunc: func() {
				LogInfo("test", "info message")
			},
			expected: "info message",
		},
		{
			name: "LogInfo with args",
			logFunc: func() {
				LogInfo("test", "info with args", "key", "value")
			},
			expected: "info with args",
		},
		{
			name: "LogError",
			logFunc: func() {
				LogError("test", "error message")
			},
			expected: "error message",
		},
		{
			name: "LogError with args",
			logFunc: func() {
				LogError("test", "error with args", "error", "details")
			},
			expected: "error with args",
		},
		{
			name: "LogWarn",
			logFunc: func() {
				LogWarn("test", "warning message")
			},
			expected: "warning message",
		},
		{
			name: "LogWarn with args",
			logFunc: func() {
				LogWarn("test", "warning with args", "reason", "test")
			},
			expected: "warning with args",
		},
		{
			name: "LogDebug",
			logFunc: func() {
				LogDebug("test", "debug message")
			},
			expected: "debug message",
		},
		{
			name: "LogDebug with args",
			logFunc: func() {
				LogDebug("test", "debug with args", "data", 123)
			},
			expected: "debug with args",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc()

			output := buf.String()
			if output == "" {
				t.Error("no log output captured")
			}
			if !bytes.Contains(buf.Bytes(), []byte(tt.expected)) {
				t.Errorf("expected log to contain %q, got %q", tt.expected, output)
			}
			if !bytes.Contains(buf.Bytes(), []byte("layer=test")) {
				t.Errorf("expected log to contain layer=test, got %q", output)
			}
		})
	}
}

// TestLoggingWithMultipleArgs tests logging with various argument types
func TestLoggingWithMultipleArgs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	LogInfo("network", "connection established", "host", "example.com", "port", 8080, "secure", true)

	if !bytes.Contains(buf.Bytes(), []byte("connection established")) {
		t.Error("message not found in output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("layer=network")) {
		t.Error("layer not found in output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("host=example.com")) {
		t.Error("host not found in output")
	}
}
