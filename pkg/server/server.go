package server

import (
	"context"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
)

type Server struct {
	cfg *config.Config
}

func NewServer(cfg *config.Config) *Server {
	return &Server{
		cfg: cfg,
	}
}

func (s *Server) Start(ctx context.Context) {
	s.Run(ctx)
}

func (s *Server) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	conn, err := common.HandshakeToBridge(ctx, s.cfg)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "closing connection")

	return nil
}
