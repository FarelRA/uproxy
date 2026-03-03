package framing

import (
	"bytes"
	"io"
	"testing"
)

func TestWriteFramed(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "small data",
			data:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "medium data",
			data:    bytes.Repeat([]byte("a"), 1000),
			wantErr: false,
		},
		{
			name:    "max size data",
			data:    bytes.Repeat([]byte("x"), MaxFrameSize),
			wantErr: false,
		},
		{
			name:    "oversized data",
			data:    bytes.Repeat([]byte("x"), MaxFrameSize+1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteFramed(&buf, tt.data)

			if (err != nil) != tt.wantErr {
				t.Errorf("WriteFramed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify the frame format: 2-byte length + data
				if buf.Len() != 2+len(tt.data) {
					t.Errorf("WriteFramed() wrote %d bytes, want %d", buf.Len(), 2+len(tt.data))
				}
			}
		})
	}
}

func TestReadFramed(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid small frame",
			input:   []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'},
			want:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "valid single byte",
			input:   []byte{0x00, 0x01, 'x'},
			want:    []byte("x"),
			wantErr: false,
		},
		{
			name:    "zero length frame",
			input:   []byte{0x00, 0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "incomplete length header",
			input:   []byte{0x00},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "incomplete data",
			input:   []byte{0x00, 0x05, 'h', 'i'},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			got, err := ReadFramed(r)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFramed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("ReadFramed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"small", []byte("test data")},
		{"medium", bytes.Repeat([]byte("abc"), 100)},
		{"large", bytes.Repeat([]byte("x"), 10000)},
		{"binary", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Write
			if err := WriteFramed(&buf, tt.data); err != nil {
				t.Fatalf("WriteFramed() error = %v", err)
			}

			// Read
			got, err := ReadFramed(&buf)
			if err != nil {
				t.Fatalf("ReadFramed() error = %v", err)
			}

			// Verify
			if !bytes.Equal(got, tt.data) {
				t.Errorf("Round trip failed: got %d bytes, want %d bytes", len(got), len(tt.data))
			}
		})
	}
}

func TestMultipleFrames(t *testing.T) {
	var buf bytes.Buffer

	frames := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	// Write multiple frames
	for _, frame := range frames {
		if err := WriteFramed(&buf, frame); err != nil {
			t.Fatalf("WriteFramed() error = %v", err)
		}
	}

	// Read multiple frames
	for i, want := range frames {
		got, err := ReadFramed(&buf)
		if err != nil {
			t.Fatalf("ReadFramed() frame %d error = %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Frame %d: got %v, want %v", i, got, want)
		}
	}
}

func TestWriteError(t *testing.T) {
	// Use a writer that always fails
	w := &failWriter{failAfter: 0}
	err := WriteFramed(w, []byte("test"))
	if err == nil {
		t.Error("WriteFramed() expected error on failing writer")
	}
}

func TestReadError(t *testing.T) {
	// Use a reader that fails after reading length
	r := &failReader{data: []byte{0x00, 0x05}, failAfter: 2}
	_, err := ReadFramed(r)
	if err == nil {
		t.Error("ReadFramed() expected error on failing reader")
	}
}

// failWriter is a writer that fails after writing a certain number of bytes
type failWriter struct {
	written   int
	failAfter int
}

func (w *failWriter) Write(p []byte) (n int, err error) {
	if w.written >= w.failAfter {
		return 0, io.ErrShortWrite
	}
	w.written += len(p)
	return len(p), io.ErrShortWrite
}

// failReader is a reader that fails after reading a certain number of bytes
type failReader struct {
	data      []byte
	pos       int
	failAfter int
}

func (r *failReader) Read(p []byte) (n int, err error) {
	if r.pos >= r.failAfter {
		return 0, io.ErrUnexpectedEOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= r.failAfter {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func TestLargeFrameBoundary(t *testing.T) {
	// Test at exactly the boundary
	data := bytes.Repeat([]byte("x"), MaxFrameSize)
	var buf bytes.Buffer

	if err := WriteFramed(&buf, data); err != nil {
		t.Fatalf("WriteFramed() at max size error = %v", err)
	}

	got, err := ReadFramed(&buf)
	if err != nil {
		t.Fatalf("ReadFramed() at max size error = %v", err)
	}

	if len(got) != MaxFrameSize {
		t.Errorf("ReadFramed() got %d bytes, want %d", len(got), MaxFrameSize)
	}
}

func TestWriteToLimitedWriter(t *testing.T) {
	// Test writing to a writer with limited capacity
	var buf bytes.Buffer
	limited := &limitedWriter{w: &buf, limit: 5}

	err := WriteFramed(limited, []byte("hello world"))
	if err == nil {
		t.Error("WriteFramed() expected error with limited writer")
	}
}

type limitedWriter struct {
	w       io.Writer
	written int
	limit   int
}

func (lw *limitedWriter) Write(p []byte) (n int, err error) {
	if lw.written >= lw.limit {
		return 0, io.ErrShortWrite
	}
	remaining := lw.limit - lw.written
	if len(p) > remaining {
		n, err = lw.w.Write(p[:remaining])
		lw.written += n
		return n, io.ErrShortWrite
	}
	n, err = lw.w.Write(p)
	lw.written += n
	return n, err
}

func TestReadFromPartialReader(t *testing.T) {
	// Reader that returns data in small chunks
	data := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	r := &chunkReader{data: data, chunkSize: 2}

	got, err := ReadFramed(r)
	if err != nil {
		t.Fatalf("ReadFramed() with chunked reader error = %v", err)
	}

	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("ReadFramed() = %v, want %v", got, []byte("hello"))
	}
}

type chunkReader struct {
	data      []byte
	pos       int
	chunkSize int
}

func (cr *chunkReader) Read(p []byte) (n int, err error) {
	if cr.pos >= len(cr.data) {
		return 0, io.EOF
	}

	end := cr.pos + cr.chunkSize
	if end > len(cr.data) {
		end = len(cr.data)
	}

	n = copy(p, cr.data[cr.pos:end])
	cr.pos += n

	if cr.pos >= len(cr.data) {
		return n, io.EOF
	}
	return n, nil
}

func BenchmarkWriteFramed(b *testing.B) {
	data := bytes.Repeat([]byte("benchmark"), 100)
	var buf bytes.Buffer

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		WriteFramed(&buf, data)
	}
}

func BenchmarkReadFramed(b *testing.B) {
	data := bytes.Repeat([]byte("benchmark"), 100)
	var buf bytes.Buffer
	WriteFramed(&buf, data)
	frameData := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(frameData)
		ReadFramed(r)
	}
}
