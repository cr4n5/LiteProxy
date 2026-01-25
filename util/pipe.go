package util

import "github.com/quic-go/quic-go"

func Copy(src, dst *quic.Stream) error {
	defer src.Close()
	defer dst.Close()
	buf := make([]byte, 4096)
	for {
		n, err := (*src).Read(buf)
		if err != nil {
			return err
		}
		_, err = (*dst).Write(buf[:n])
		if err != nil {
			return err
		}
	}
}

func Pipe(stream1, stream2 *quic.Stream) error {
	errCh := make(chan error, 2)
	go func() {
		errCh <- Copy(stream1, stream2)
	}()
	go func() {
		errCh <- Copy(stream2, stream1)
	}()
	return <-errCh
}
