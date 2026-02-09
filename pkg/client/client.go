package client

import (
	"context"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/lib"
	"github.com/cr4n5/liteproxy/pkg/lib/p2p"
	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	cfg *config.Config
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
	}
}

func (c *Client) Start(ctx context.Context) {
	for {
		err := c.Run(ctx)
		if err != nil {
			log.Errorf("client exited with error: %v", err)
		}
		<-time.After(5 * time.Second)
	}
}

func (c *Client) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	conn, err := lib.HandshakeToBridge(ctx, c.cfg)
	if err != nil {
		return err
	}
	log.Infof("Attempting to connect to bridge at %s, log an error if it fails, otherwise it succeeded.", c.cfg.BridgeAddr)
	defer conn.CloseWithError(0, "closing connection")

	for {
		newStream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.handleStream(ctx, newStream)
	}
}

func (c *Client) handleStream(ctx context.Context, stream *quic.Stream) {
	defer stream.Close()

	// Handle handconn message
	data, err := lib.StreamReadWithLength(stream, 0)
	if err != nil {
		log.Errorf("failed to read handconn message: %v", err)
		return
	}
	hcm, err := lib.DecodeHandConnMessage(data)
	if err != nil {
		log.Errorf("failed to decode handconn message: %v", err)
		return
	}

	// Connect to target
	switch hcm.Protocol {
	case "tcp":
		targetConn, err := net.Dial("tcp", hcm.ClientAddr)
		if err != nil {
			log.Errorf("(TCP) failed to connect to target %s: %v", hcm.ClientAddr, err)
			stream.CancelWrite(common.ErrTargetUnreachable)
			return
		}
		defer targetConn.Close()

		log.Infof("(TCP) connected to target %s ", hcm.ClientAddr)
		// Start piping data between stream and target connection
		err = lib.Pipe(stream, targetConn)
		if err != nil {
			log.Errorf("(TCP) piping between stream and target %s ended: %v", hcm.ClientAddr, common.TranslateStreamError(err))
			return
		}
		log.Infof("(TCP) piping between stream and target %s ended normally", hcm.ClientAddr)

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", hcm.ClientAddr)
		if err != nil {
			log.Errorf("(UDP) failed to resolve UDP address %s: %v", hcm.ClientAddr, err)
			stream.CancelWrite(common.ErrTargetUnreachable)
			return
		}

		udpConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Errorf("(UDP) failed to connect to UDP target %s: %v", hcm.ClientAddr, err)
			stream.CancelWrite(common.ErrTargetUnreachable)
			return
		}
		defer udpConn.Close()

		log.Infof("(UDP) connected to UDP target %s ", hcm.ClientAddr)
		// Handle UDP with proper length prefix protocol
		err = lib.PipeUDPStream(stream, udpConn)
		if err != nil {
			log.Errorf("(UDP) piping between stream and UDP target %s ended: %v", hcm.ClientAddr, common.TranslateStreamError(err))
			return
		}
		log.Infof("(UDP) piping between stream and UDP target %s ended normally", hcm.ClientAddr)

	case "ptcp", "pudp":
		p2pConn, err := p2p.EstablishP2PConnection(ctx, *c.cfg, stream)
		if err != nil {
			log.Errorf("(P2P) failed to establish P2P connection: %v", err)
			return
		}
		defer p2pConn.CloseWithError(0, "closing P2P connection")

		log.Info("(P2P) P2P connection established successfully")
		for {
			newStream, err := p2pConn.AcceptStream(ctx)
			if err != nil {
				log.Errorf("(P2P) failed to accept P2P stream: %v", err)
				return
			}
			go c.handleStream(ctx, newStream)
		}

	default:
		// Unsupported protocol
		log.Errorf("unsupported protocol %s from handconn message", hcm.Protocol)
		return
	}
}
