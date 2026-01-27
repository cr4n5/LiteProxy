package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/lib"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
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
	for {
		err := s.Run(ctx)
		if err != nil {
			log.Errorf("server exited with error: %v", err)
		}
		<-time.After(5 * time.Second)
	}
}

func (s *Server) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	conn, err := lib.HandshakeToBridge(ctx, s.cfg)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "closing connection")

	switch s.cfg.Type {
	case "tcp":
		ln, err := net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return err
		}
		defer ln.Close()
		log.Infof("server listening on %s, forwarding to bridge", s.cfg.ListenAddr)

		acceptChan := make(chan net.Conn)
		acceptErrChan := make(chan error)
		go func() {
			for {
				clientConn, err := ln.Accept()
				if err != nil {
					acceptErrChan <- err
					return
				}
				acceptChan <- clientConn
			}
		}()

		for {
			select {
			case <-conn.Context().Done():
				return errors.New("bridge connection closed")
			case err := <-acceptErrChan:
				return err
			case clientConn := <-acceptChan:
				go s.handleClientConnection(ctx, conn, clientConn)
			}
		}
	default:
		// unsupported type
		return errors.New("unsupported server type")
	}
}

func (s *Server) handleClientConnection(ctx context.Context, bridgeConn *quic.Conn, clientConn net.Conn) {
	defer clientConn.Close()
	// Open new stream to bridge for this client connection
	stream, err := lib.StreamOpen(ctx, bridgeConn, 0)
	if err != nil {
		log.Errorf("open stream error: %v", err)
		return
	}
	defer stream.Close()

	log.Infof("accepted connection from %s, forwarding to bridge", clientConn.RemoteAddr())

	err = lib.Pipe(stream, clientConn)
	if err != nil {
		log.Errorf("pipe error: %v", common.TranslateStreamError(err))
		return
	}
	log.Infof("connection from %s closed normally", clientConn.RemoteAddr())
}
