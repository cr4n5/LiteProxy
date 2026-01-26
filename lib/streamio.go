package lib

import (
	"time"

	"github.com/quic-go/quic-go"
)

func StreamRead(stream *quic.Stream, buf []byte, timeout int) (int, error) {
	if timeout > 0 {
		stream.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	} else {
		stream.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))
	}
	n, err := stream.Read(buf)
	stream.SetReadDeadline(time.Time{})
	return n, err
}

func StreamWrite(stream *quic.Stream, data []byte, timeout int) (int, error) {
	if timeout > 0 {
		stream.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	} else {
		stream.SetWriteDeadline(time.Now().Add(time.Duration(5) * time.Second))
	}
	n, err := stream.Write(data)
	stream.SetWriteDeadline(time.Time{})
	return n, err
}

func StreamWaitClosed(stream *quic.Stream) {
	buf := make([]byte, 1)
	stream.Read(buf)
}
