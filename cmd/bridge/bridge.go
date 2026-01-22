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
	ClientControlAddr = "0.0.0.0:10020"
	ServerControlAddr = "0.0.0.0:10021"
)

type Bridge struct {
	mu      sync.Mutex
	clients map[string]*yamux.Session // client_id -> client yamux session
	servers map[string]*yamux.Session // client_id -> server yamux session
}

func NewBridge() *Bridge {
	return &Bridge{
		clients: make(map[string]*yamux.Session),
		servers: make(map[string]*yamux.Session),
	}
}

func (b *Bridge) Start() {
	go b.listenClientControl()
	go b.listenServerControl()
	select {}
}

func (b *Bridge) listenClientControl() {
	ln, err := net.Listen("tcp", ClientControlAddr)
	if err != nil {
		log.Fatalf("client control listen %v", err)
	}
	log.Printf("client control listening %s", ClientControlAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("client control accept: %v", err)
			continue
		}
		go b.handleClientControl(conn)
	}
}

func (b *Bridge) listenServerControl() {
	ln, err := net.Listen("tcp", ServerControlAddr)
	if err != nil {
		log.Fatalf("server control listen %v", err)
	}
	log.Printf("server control listening %s", ServerControlAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("server control accept: %v", err)
			continue
		}
		go b.handleServerControl(conn)
	}
}

func (b *Bridge) handleClientControl(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "REGISTER ") {
		id := strings.TrimSpace(strings.TrimPrefix(line, "REGISTER "))
		session, err := yamux.Server(conn, nil)
		if err != nil {
			log.Printf("yamux session err: %v", err)
			return
		}
		b.mu.Lock()
		b.clients[id] = session
		b.mu.Unlock()
		log.Printf("client registered: %s", id)
		<-session.CloseChan()
		b.mu.Lock()
		delete(b.clients, id)
		b.mu.Unlock()
		log.Printf("client disconnected: %s", id)
		return
	}
}

func (b *Bridge) handleServerControl(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "FORWARD ") {
		// format: FORWARD <client_id> <target_host> <target_port>
		parts := strings.SplitN(line, " ", 4)
		if len(parts) < 4 {
			fmt.Fprintln(conn, "ERR bad FORWARD")
			return
		}
		clientID := parts[1]
		targetHost := parts[2]
		targetPort := parts[3]
		session, err := yamux.Server(conn, nil)
		if err != nil {
			fmt.Fprintln(conn, "ERR yamux server")
			return
		}
		b.mu.Lock()
		b.servers[clientID] = session
		b.mu.Unlock()
		b.mu.Lock()
		clientSession, ok := b.clients[clientID]
		b.mu.Unlock()
		if !ok {
			fmt.Fprintln(conn, "ERR no such client")
			return
		}
		fmt.Fprintln(conn, "OK")
		go func() {
			for {
				srvStream, err := session.AcceptStream()
				if err != nil {
					log.Printf("server AcceptStream err: %v", err)
					break
				}
				clientStream, err := clientSession.OpenStream()
				if err != nil {
					log.Printf("open stream to client err: %v", err)
					srvStream.Close()
					continue
				}
				fmt.Fprintf(clientStream, "CONNECT %s %s\n", targetHost, targetPort)
				go b.handleForward(clientStream, srvStream)
			}
			session.Close()
			b.mu.Lock()
			delete(b.servers, clientID)
			b.mu.Unlock()
			log.Printf("server disconnected: %s", clientID)
		}()
		<-session.CloseChan() // 阻塞直到session关闭
		return
	}
}

// 处理 server 端的转发连接
func (b *Bridge) handleForward(clientStream net.Conn, srvStream net.Conn) {
	defer srvStream.Close()
	defer clientStream.Close()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(srvStream, clientStream)
		wg.Done()
	}()
	go func() {
		io.Copy(clientStream, srvStream)
		wg.Done()
	}()
	wg.Wait()
	log.Printf("forward session closed")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	b := NewBridge()
	b.Start()
}
