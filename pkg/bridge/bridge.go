package bridge

import (
	"context"
	"sync"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/lib"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type Bridge struct {
	mu      sync.RWMutex
	clients map[string]*quic.Conn
	cfg     *config.Config
}

func NewBridge(cfg *config.Config) *Bridge {
	return &Bridge{
		clients: make(map[string]*quic.Conn),
		cfg:     cfg,
	}
}

func (b *Bridge) Start(ctx context.Context) {
	ln, err := quic.ListenAddr(b.cfg.BridgeAddr, common.GenerateTLSConfig(), common.QuicConfig)
	if err != nil {
		log.Fatalf("failed to start bridge listener: %v", err)
		return
	}
	defer ln.Close()
	log.Infof("bridge listening on %s", b.cfg.BridgeAddr)
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			log.Errorf("failed to accept connection: %v", err)
			continue
		}
		go b.handleConnection(ctx, conn)
	}
}

func (b *Bridge) handleConnection(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "closing connection")
	// Handle handshake
	stream, err := lib.StreamAccept(ctx, conn, 0)
	if err != nil {
		log.Errorf("Remote Addr %s: failed to accept stream: %v", conn.RemoteAddr().String(), err)
		return
	}
	buf := make([]byte, 1024)
	n, err := lib.StreamRead(stream, buf, 0)
	stream.Close()
	if err != nil {
		log.Errorf("Remote Addr %s: failed to read from stream: %v", conn.RemoteAddr().String(), err)
		return
	}
	hm, err := lib.DecodeHandshakeMessage(buf[:n])
	if err != nil {
		log.Errorf("Remote Addr %s: failed to decode handshake message: %v", conn.RemoteAddr().String(), err)
		return
	}
	// Verify access key
	if hm.AccessKey != b.cfg.AccessKey {
		log.Errorf("Remote Addr %s: invalid access key", conn.RemoteAddr().String())
		_ = conn.CloseWithError(0, "invalid access key")
		return
	}

	switch hm.ClientType {
	case "server":
		for {
			newStream, err := conn.AcceptStream(ctx)
			if err != nil {
				log.Errorf("Remote Addr %s: failed to accept server stream: %v", conn.RemoteAddr().String(), err)
				return
			}
			go b.handleServerStream(ctx, hm, newStream)
		}
	case "client":
		ok := b.SetClient(hm.ClientID, conn)
		if !ok {
			log.Errorf("Remote Addr %s: client ID %s already connected", conn.RemoteAddr().String(), hm.ClientID)
			_ = conn.CloseWithError(0, "client ID already connected")
			return
		}
		log.Infof("Remote Addr %s: client ID %s connected", conn.RemoteAddr().String(), hm.ClientID)
		// wait for disconnection
		<-conn.Context().Done()
		b.RemoveClient(hm.ClientID)
		log.Infof("Remote Addr %s: client ID %s disconnected", conn.RemoteAddr().String(), hm.ClientID)
	default:
		log.Errorf("Remote Addr %s: unknown client type %s", conn.RemoteAddr().String(), hm.ClientType)
		_ = conn.CloseWithError(0, "unknown client type")
		return
	}
}

func (b *Bridge) handleServerStream(ctx context.Context, hm *lib.HandshakeMessage, stream *quic.Stream) {
	defer stream.Close()
	clientConn, ok := b.GetClient(hm.ClientID)
	if !ok {
		log.Errorf("Server stream: client ID %s not connected", hm.ClientID)
		stream.CancelWrite(common.ErrClientNotFound)
		return
	}
	clientStream, err := lib.StreamOpen(ctx, clientConn, 0)
	if err != nil {
		log.Errorf("Server stream: failed to open stream to client ID %s: %v", hm.ClientID, err)
		stream.CancelWrite(common.ErrClientNotFound)
		return
	}
	defer clientStream.Close()

	// Start piping data between server stream and client stream
	err = lib.Pipe(stream, clientStream)
	if err != nil {
		log.Errorf("Server stream: piping between server and client ID %s ended: %v", hm.ClientID, common.TranslateStreamError(err))
		stream.CancelWrite(common.TranslateErrorCode(err))
		return
	}
	log.Infof("Server stream: piping between server and client ID %s ended normally", hm.ClientID)
}

func (b *Bridge) SetClient(id string, conn *quic.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.clients[id]; ok {
		return false
	}
	b.clients[id] = conn
	return true
}

func (b *Bridge) GetClient(id string) (*quic.Conn, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	conn, ok := b.clients[id]
	return conn, ok
}

func (b *Bridge) RemoveClient(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, id)
}
