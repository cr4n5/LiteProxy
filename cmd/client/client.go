package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/hashicorp/yamux"
)

var (
	id         = flag.String("id", "client1", "client identifier")
	bridgeAddr = flag.String("bridge", "127.0.0.1:10020", "bridge control address")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	conn, err := net.Dial("tcp", *bridgeAddr)
	if err != nil {
		log.Fatalf("dial bridge error: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "REGISTER %s\n", *id)

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Fatalf("yamux client error: %v", err)
	}
	defer session.Close()

	log.Printf("registered as %s, listening for streams", *id)

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("accept stream error: %v", err)
			break
		}

		go handleStream(stream)
	}

	log.Printf("client %s disconnected", *id)
}

func handleStream(stream net.Conn) {
	defer stream.Close()

	r := bufio.NewReader(stream)
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("read connect command: %v", err)
		return
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "CONNECT ") {
		log.Printf("invalid command: %s", line)
		return
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		log.Printf("invalid CONNECT command format: %s", line)
		return
	}

	targetHost := parts[1]
	targetPort := parts[2]
	target := net.JoinHostPort(targetHost, targetPort)

	tconn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("dial target %s error: %v", target, err)
		return
	}
	defer tconn.Close()

	log.Printf("connected to target %s", target)

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, tconn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(tconn, stream)
		errChan <- err
	}()

	// Wait for first error or both goroutines to complete
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			log.Printf("copy error: %v", err)
		}
	}

	log.Printf("stream to target %s closed", target)
}
