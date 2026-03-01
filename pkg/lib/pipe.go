package lib

import (
	"io"
	"net"

	"github.com/quic-go/quic-go"
)

func Copy(src, dst io.ReadWriteCloser) error {
	_, err := io.Copy(dst, src)
	if err != nil {
		return err
	}
	return src.Close()
}

func Pipe(conn1, conn2 io.ReadWriteCloser) error {
	defer conn1.Close()
	defer conn2.Close()
	errCh := make(chan error, 2)
	go func() {
		errCh <- Copy(conn1, conn2)
	}()
	go func() {
		errCh <- Copy(conn2, conn1)
	}()
	return <-errCh
}

func PipeUDPStream(stream *quic.Stream, udpConn *net.UDPConn) error {
	defer stream.Close()
	defer udpConn.Close()
	// Read UDP data from stream with length prefix and forward to target
	// Also receive responses from target and send back via stream
	errCh := make(chan error, 2)

	// Stream to UDP
	go func() {
		for {
			data, err := StreamReadWithLength(stream, -1)
			if err != nil {
				errCh <- err
				return
			}
			_, err = udpConn.Write(data)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// UDP to Stream
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			_, err = StreamWriteWithLength(stream, buf[:n], -1)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	return <-errCh
}
