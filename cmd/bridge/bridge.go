package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"
)

const (
	clientCtrlAddr = "0.0.0.0:10020"
	serverCtrlAddr = "0.0.0.0:10021"
)

type Bridge struct {
	mu      sync.RWMutex
	clients map[string]*yamux.Session
	servers map[string]*yamux.Session
}

func NewBridge() *Bridge {
	return &Bridge{
		clients: make(map[string]*yamux.Session),
		servers: make(map[string]*yamux.Session),
	}
}

func (b *Bridge) Start() {
	go b.acceptClients()
	go b.acceptServers()
	select {}
}

func (b *Bridge) acceptClients() {
	ln, err := net.Listen("tcp", clientCtrlAddr)
	if err != nil {
		log.Fatalf("listen client control error: %v", err)
	}
	defer ln.Close()
	log.Printf("client control listening on %s", clientCtrlAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept client error: %v", err)
			continue
		}
		go b.handleClient(conn)
	}
}

func (b *Bridge) acceptServers() {
	ln, err := net.Listen("tcp", serverCtrlAddr)
	if err != nil {
		log.Fatalf("listen server control error: %v", err)
	}
	defer ln.Close()
	log.Printf("server control listening on %s", serverCtrlAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept server error: %v", err)
			continue
		}
		go b.handleServer(conn)
	}
}

func (b *Bridge) handleClient(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("read register command error: %v", err)
		return
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "REGISTER ") {
		log.Printf("invalid client command: %s", line)
		return
	}

	clientID := strings.TrimSpace(strings.TrimPrefix(line, "REGISTER "))

	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("yamux server error: %v", err)
		return
	}

	b.mu.Lock()
	b.clients[clientID] = session
	b.mu.Unlock()
	log.Printf("client registered: %s", clientID)

	<-session.CloseChan()

	b.mu.Lock()
	delete(b.clients, clientID)
	b.mu.Unlock()
	log.Printf("client disconnected: %s", clientID)
}

func (b *Bridge) handleServer(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		log.Printf("read forward command error: %v", err)
		return
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "FORWARD ") {
		fmt.Fprintln(conn, "ERR invalid command")
		return
	}

	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		fmt.Fprintln(conn, "ERR invalid format")
		return
	}

	clientID := parts[1]
	targetHost := parts[2]
	targetPort := parts[3]

	session, err := yamux.Server(conn, nil)
	if err != nil {
		fmt.Fprintln(conn, "ERR yamux error")
		log.Printf("yamux server error: %v", err)
		return
	}

	b.mu.Lock()
	b.servers[clientID] = session
	clientSession, ok := b.clients[clientID]
	b.mu.Unlock()

	if !ok {
		fmt.Fprintln(conn, "ERR no such client")
		b.mu.Lock()
		delete(b.servers, clientID)
		b.mu.Unlock()
		log.Printf("forward failed: client %s not found", clientID)
		return
	}

	fmt.Fprintln(conn, "OK")
	log.Printf("forward registered for client %s -> %s:%s", clientID, targetHost, targetPort)

	go b.forwardLoop(clientID, clientSession, session, targetHost, targetPort)
}

func (b *Bridge) forwardLoop(clientID string, clientSession, serverSession *yamux.Session, targetHost, targetPort string) {
	defer func() {
		serverSession.Close()
		b.mu.Lock()
		delete(b.servers, clientID)
		b.mu.Unlock()
		log.Printf("server disconnected: %s", clientID)
	}()

	for {
		srvStream, err := serverSession.AcceptStream()
		if err != nil {
			log.Printf("accept server stream error: %v", err)
			return
		}

		go func(srvStream net.Conn) {
			defer srvStream.Close()

			b.mu.RLock()
			clientSession := b.clients[clientID]
			b.mu.RUnlock()

			if clientSession == nil {
				log.Printf("client %s not available", clientID)
				return
			}

			clientStream, err := clientSession.OpenStream()
			if err != nil {
				log.Printf("open client stream error: %v", err)
				return
			}

			fmt.Fprintf(clientStream, "CONNECT %s %s\n", targetHost, targetPort)
			b.relay(clientStream, srvStream)
		}(srvStream)
	}
}

func (b *Bridge) relay(clientStream, serverStream net.Conn) {
	defer clientStream.Close()
	defer serverStream.Close()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverStream, clientStream)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(clientStream, serverStream)
		errChan <- err
	}()

	// Wait for first error or both goroutines to complete
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			log.Printf("relay error: %v", err)
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	b := NewBridge()
	b.Start()
}
