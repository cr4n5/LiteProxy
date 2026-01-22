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
	id        = flag.String("id", "client1", "client id")
	bridgeCtl = flag.String("bridge", "127.0.0.1:10020", "bridge control addr (for client)")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	conn, err := net.Dial("tcp", *bridgeCtl)
	if err != nil {
		log.Fatalf("dial bridge control: %v", err)
	}
	fmt.Fprintf(conn, "REGISTER %s\n", *id)
	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Fatalf("yamux client: %v", err)
	}
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			log.Printf("accept stream: %v", err)
			break
		}
		go handleStream(stream)
	}
}

func handleStream(stream net.Conn) {
	defer stream.Close()
	r := bufio.NewReader(stream)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "CONNECT ") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			return
		}
		targetHost := parts[1]
		targetPort := parts[2]
		target := net.JoinHostPort(targetHost, targetPort)
		tconn, err := net.Dial("tcp", target)
		if err != nil {
			log.Printf("dial target %s err: %v", target, err)
			return
		}
		defer tconn.Close()
		// 双向转发
		go func() {
			io.Copy(stream, tconn)
		}()
		io.Copy(tconn, stream)
		log.Printf("connect session closed")
	}
}
