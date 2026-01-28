package lib

import (
	"io"
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
