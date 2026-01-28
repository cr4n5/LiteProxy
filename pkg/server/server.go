package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/lib"
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

	routeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errChan := make(chan error)
	for _, route := range s.cfg.Routes {
		go func(r config.RouteConfig) {
			err := s.handleRoute(routeContext, conn, r)
			if err != nil {
				errChan <- err
			}
		}(route)
	}

	select {
	case <-ctx.Done():
		return nil
	case <-conn.Context().Done():
		_, err := conn.AcceptStream(ctx)
		return err
	case err := <-errChan:
		return err
	}
}

func (s *Server) handleRoute(ctx context.Context, bridgeConn *quic.Conn, route config.RouteConfig) error {
	switch route.Protocol {
	case "tcp":
		ln, err := net.Listen("tcp", route.LocalAddr)
		if err != nil {
			return err
		}
		defer ln.Close()
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		log.Infof("server listening(TCP) on %s, forwarding to bridge", route.LocalAddr)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			go s.handleTCPConnection(ctx, route, bridgeConn, conn)
		}
	// case "udp":
	// ln, err := net.ListenPacket("udp", s.cfg.ListenAddr)
	// if err != nil {
	// 	return err
	// }
	// defer ln.Close()
	// log.Infof("server listening on %s, forwarding to bridge", s.cfg.ListenAddr)
	default:
		// unsupported type
		return errors.New("unsupported server type")
	}
}

func (s *Server) handleTCPConnection(ctx context.Context, route config.RouteConfig, bridgeConn *quic.Conn, conn net.Conn) {
	defer conn.Close()
	// Open new stream to bridge
	stream, err := lib.HandConnToTarget(ctx, &route, bridgeConn)
	if err != nil {
		log.Errorf("failed to open stream to bridge: %v", err)
		return
	}
	defer stream.Close()

	log.Infof("accepted connection from %s, forwarding to bridge", conn.RemoteAddr())
	err = lib.Pipe(stream, conn)
	if err != nil {
		log.Errorf("pipe error: %v", common.TranslateStreamError(err))
		return
	}
	log.Infof("connection from %s closed normally", conn.RemoteAddr())
}
