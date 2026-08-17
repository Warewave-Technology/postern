// Package proxy wires an inbound (user) channel to an outbound (target)
// channel and shuttles data and requests between them.
package proxy

import (
	"errors"
	"fmt"
	"io"
)

type halfCloser interface {
	CloseWrite() error
}

// pipe copies src into dst until EOF. When singleWriter is true it then
// half-closes dst's write side, so the peer sees EOF on ITS read side while
// the other direction keeps flowing (Ek C.6).
func pipe(dst io.Writer, src io.Reader, closeWrite halfCloser) (int64, error) {
	n, err := io.Copy(dst, src)
	if err != nil && !isBenignCloseErr(err) {
		return n, fmt.Errorf("proxy.pipe: %w", err)
	}

	if closeWrite != nil {
		err = closeWrite.CloseWrite()
		if err != nil && !isBenignCloseErr(err) {
			return n, fmt.Errorf("proxy.pipe: %w", err)
		}
	}

	return n, nil
}

// isBenignCloseErr reports whether err is just "the channel went away" noise
// rather than a real failure worth logging as an error.
func isBenignCloseErr(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}

	return false
}
