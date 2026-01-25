package server

import (
	"context"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/quic-go/quic-go"
)

type Server struct {
	cfg *config.ServerConfig
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg.Server,
	}
}

func (s *Server) Start() {
	// Implement server start logic here
}

func (s *Server) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctxTimeout, s.cfg.BridgeAddr, common.GenerateTLSConfig(), nil)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "closing session")
	stream, err := conn.OpenStreamSync(ctxTimeout)
	if err != nil {
		return err
	}
	defer stream.Close()
	// Handle handshake
	hm := common.NewHandshakeMessage("server", s.cfg.AccessKey, s.cfg.ClientID, s.cfg.Type, s.cfg.Target)
	data, err := hm.Encode()
	stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = stream.Write(data)
	if err != nil {
		return err
	}

	return nil
}
