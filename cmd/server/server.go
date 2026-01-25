package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

var (
	bridgeAddr = flag.String("bridge", "127.0.0.1:10021", "bridge control address")
	listenAddr = flag.String("listen", ":8080", "listen address for external connections")
	clientID   = flag.String("client", "client1", "target client ID")
	targetHost = flag.String("target", "127.0.0.1", "internal target host")
	targetPort = flag.String("tport", "80", "internal target port")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer ln.Close()
	log.Printf("listening on %s", *listenAddr)

	go acceptLoop(ln)

	select {}
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			if err := handleClient(c); err != nil {
				log.Printf("handle client error: %v", err)
			}
		}(conn)
	}
}

func handleClient(c net.Conn) error {
	session, err := connectBridge()
	if err != nil {
		return fmt.Errorf("connect bridge: %w", err)
	}
	defer session.Close()

	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	log.Printf("accepted connection from %s, forwarding to bridge", c.RemoteAddr())

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, c)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(c, stream)
		errChan <- err
	}()

	// Wait for first error or both goroutines to complete
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			log.Printf("copy error: %v", err)
		}
	}

	log.Printf("connection closed from %s", c.RemoteAddr())
	return nil
}

func connectBridge() (*yamux.Session, error) {
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		ctl, err := net.Dial("tcp", *bridgeAddr)
		if err != nil {
			lastErr = err
			log.Printf("dial bridge (attempt %d): %v, retrying in 2s...", attempt, err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Send FORWARD command
		fmt.Fprintf(ctl, "FORWARD %s %s %s\n", *clientID, *targetHost, *targetPort)

		r := bufio.NewReader(ctl)
		ack, err := r.ReadString('\n')
		if err != nil {
			ctl.Close()
			log.Printf("read ack: %v", err)
			continue
		}

		ack = strings.TrimSpace(ack)
		if !strings.HasPrefix(ack, "OK") {
			ctl.Close()
			log.Printf("bridge responded: %s", ack)
			continue
		}

		session, err := yamux.Client(ctl, nil)
		if err != nil {
			ctl.Close()
			log.Printf("yamux client: %v", err)
			continue
		}

		log.Printf("connected to bridge successfully")
		return session, nil
	}

	return nil, fmt.Errorf("failed to connect bridge after 5 attempts: %w", lastErr)
}
