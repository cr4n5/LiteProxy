package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/hashicorp/yamux"
)

var (
	bridgeCtl  = flag.String("bridge", "127.0.0.1:10021", "bridge control addr (for server, yamux多路复用)")
	listenAddr = flag.String("listen", ":8080", "listen addr for external incoming")
	clientID   = flag.String("client", "client1", "target client id")
	targetHost = flag.String("target", "127.0.0.1", "internal target host (for client)")
	targetPort = flag.String("tport", "80", "internal target port (for client)")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	ctl, err := net.Dial("tcp", *bridgeCtl)
	if err != nil {
		log.Fatalf("dial bridge control: %v", err)
	}
	// 发送 FORWARD 命令
	fmt.Fprintf(ctl, "FORWARD %s %s %s\n", *clientID, *targetHost, *targetPort)
	r := bufio.NewReader(ctl)
	ok, _ := r.ReadString('\n')
	if ok == "" {
		log.Fatalf("no ack from bridge")
	}
	session, err := yamux.Client(ctl, nil)
	if err != nil {
		log.Fatalf("yamux client: %v", err)
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening %s", *listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleExternal(conn, session)
	}
}

func handleExternal(ext net.Conn, session *yamux.Session) {
	defer ext.Close()
	stream, err := session.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	defer stream.Close()
	go func() {
		io.Copy(stream, ext)
	}()
	io.Copy(ext, stream)
	log.Printf("external session closed")
}
