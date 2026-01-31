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
		log.Infof("(TCP) server listening on %s", route.LocalAddr)

		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			go s.handleTCPConnection(ctx, route, bridgeConn, conn)
		}
	case "udp":
		ln, err := net.ListenPacket("udp", route.LocalAddr)
		if err != nil {
			return err
		}
		defer ln.Close()
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		log.Infof("(UDP) server listening on %s", route.LocalAddr)
		udpSession := lib.NewUDPSession(ln)
		defer udpSession.Close()
		buf := make([]byte, 65535)
		for {
			n, addr, err := ln.ReadFrom(buf)
			if err != nil {
				return err
			}
			go s.handleUDPConnection(ctx, route, bridgeConn, addr, buf[:n], udpSession)
		}
	default:
		// unsupported protocol
		return errors.New("unsupported protocol: " + route.Protocol)
	}
}

func (s *Server) handleTCPConnection(ctx context.Context, route config.RouteConfig, bridgeConn *quic.Conn, conn net.Conn) {
	log.Infof("(TCP) accepted connection from %s to target %s", conn.RemoteAddr(), route.ClientAddr)
	defer conn.Close()
	// Open new stream to bridge
	stream, err := lib.HandConnToTarget(ctx, &route, bridgeConn)
	if err != nil {
		log.Errorf("(TCP) failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	err = lib.Pipe(stream, conn)
	if err != nil {
		log.Errorf("(TCP) pipe between %s and target %s ended: %v", conn.RemoteAddr(), route.ClientAddr, common.TranslateStreamError(err))
		return
	}
	log.Infof("(TCP) pipe between %s and target %s ended normally", conn.RemoteAddr(), route.ClientAddr)
}

func (s *Server) handleUDPConnection(ctx context.Context, route config.RouteConfig, bridgeConn *quic.Conn, addr net.Addr, data []byte, udpSession *lib.UDPSession) {
	stream, err := udpSession.GetOrCreateStream(ctx, route, bridgeConn, addr)
	if err != nil {
		log.Errorf("(UDP) failed to get or create stream for addr %s to target %s: %v", addr.String(), route.ClientAddr, err)
		return
	}
	// Use the stream to handle UDP data - use StreamWriteWithLength for proper framing
	_, err = lib.StreamWriteWithLength(stream, data, 0)
	if err != nil {
		log.Errorf("(UDP) failed to write UDP data for addr %s to target %s: %v", addr.String(), route.ClientAddr, err)
		udpSession.DeleteStream(addr)
		return
	}
	log.Debugf("(UDP) UDP data forwarded from %s to target %s", addr.String(), route.ClientAddr)
}
