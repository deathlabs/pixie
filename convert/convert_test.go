package convert

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type errorReadCloser struct {
	closeErr error
	reader   io.Reader
}

type errorReader struct {
	err error
}

func (reader *errorReadCloser) Close() error {
	return reader.closeErr
}

func (reader *errorReadCloser) Read(buffer []byte) (int, error) {
	return reader.reader.Read(buffer)
}

func (reader *errorReader) Read(_ []byte) (int, error) {
	return 0, reader.err
}

func TestLoadConfigFromReaderReturnsCloseError(t *testing.T) {
	var (
		closeErr      error
		configuration *config
		err           error
		reader        *errorReadCloser
	)

	closeErr = errors.New("close error")
	reader = &errorReadCloser{
		closeErr: closeErr,
		reader:   strings.NewReader("benchmark: {}\n"),
	}

	configuration, err = loadConfigFromReader(reader)
	if configuration == nil {
		t.Fatal("expected decoded configuration")
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestLoadConfigFromReaderJoinsDecodeAndCloseErrors(t *testing.T) {
	var (
		closeErr  error
		decodeErr error
		err       error
		reader    *errorReadCloser
	)

	closeErr = errors.New("close error")
	decodeErr = errors.New("decode error")
	reader = &errorReadCloser{
		closeErr: closeErr,
		reader:   &errorReader{err: decodeErr},
	}

	_, err = loadConfigFromReader(reader)
	if err == nil {
		t.Fatal("expected decode and close errors")
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error, got %v", err)
	}
	if !strings.Contains(err.Error(), decodeErr.Error()) {
		t.Fatalf("expected decode error, got %v", err)
	}
}
