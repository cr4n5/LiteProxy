package lib

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/cr4n5/liteproxy/common"
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
	defer stream.Close()
	buf := make([]byte, 1)
	stream.Read(buf)
}

func StreamAccept(ctx context.Context, conn *quic.Conn, timeout int) (*quic.Stream, error) {
	if timeout <= 0 {
		timeout = 5
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	return conn.AcceptStream(ctxTimeout)
}

func StreamOpen(ctx context.Context, conn *quic.Conn, timeout int) (*quic.Stream, error) {
	if timeout <= 0 {
		timeout = 5
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	return conn.OpenStreamSync(ctxTimeout)
}

func QuicDialAddr(ctx context.Context, addr string, timeout int) (*quic.Conn, error) {
	if timeout <= 0 {
		timeout = 5
	}
	ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	return quic.DialAddr(ctxTimeout, addr, common.GenerateClientTLSConfig(), common.QuicConfig)
}

// StreamReadWithLength reads data with 4-byte length prefix
func StreamReadWithLength(stream *quic.Stream, timeout int) ([]byte, error) {
	if timeout > 0 {
		stream.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	} else {
		stream.SetReadDeadline(time.Now().Add(time.Duration(5) * time.Second))
	}
	defer stream.SetReadDeadline(time.Time{})

	// Read 4-byte length prefix
	lengthBuf := make([]byte, 4)
	_, err := io.ReadFull(stream, lengthBuf)
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBuf)

	// Read actual data
	dataBuf := make([]byte, length)
	_, err = io.ReadFull(stream, dataBuf)
	if err != nil {
		return nil, err
	}
	return dataBuf, nil
}

// StreamWriteWithLength writes data with 4-byte length prefix
func StreamWriteWithLength(stream *quic.Stream, data []byte, timeout int) (int, error) {
	if timeout > 0 {
		stream.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	} else {
		stream.SetWriteDeadline(time.Now().Add(time.Duration(5) * time.Second))
	}
	defer stream.SetWriteDeadline(time.Time{})

	// Write 4-byte length prefix
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(data)))
	data = append(lengthBuf, data...)

	// Write actual data
	n, err := stream.Write(data)
	return n, err
}
