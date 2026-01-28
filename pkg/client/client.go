package client

import (
	"context"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/lib"
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
			log.Errorf("server exited with error: %v", err)
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
	defer conn.CloseWithError(0, "closing connection")
	for {
		newStream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go c.handleBridgeStream(ctx, newStream)
	}
}

func (c *Client) handleBridgeStream(ctx context.Context, stream *quic.Stream) {
	defer stream.Close()
	// Handle handconn message
	data, err := lib.StreamReadWithLength(stream, 0)
	if err != nil {
		log.Errorf("failed to read handconn message from server: %v", err)
		return
	}
	hcm, err := lib.DecodeHandConnMessage(data)
	if err != nil {
		log.Errorf("failed to decode handconn message from server: %v", err)
		return
	}
	// Connect to target
	switch hcm.Protocol {
	case "tcp":
		targetConn, err := net.Dial("tcp", hcm.ClientAddr)
		if err != nil {
			log.Errorf("failed to connect to target %s: %v", hcm.ClientAddr, err)
			stream.CancelWrite(common.ErrTargetUnreachable)
			return
		}
		defer targetConn.Close()
		log.Printf("connected to target %s for stream from bridge", hcm.ClientAddr)
		// Start piping data between stream and target connection
		err = lib.Pipe(stream, targetConn)
		if err != nil {
			log.Errorf("piping between bridge and target %s ended: %v", hcm.ClientAddr, common.TranslateStreamError(err))
			return
		}
		log.Printf("piping between bridge and target %s ended normally", hcm.ClientAddr)
	default:
		// Unsupported type
		// stream.CancelRead(common.ErrAccessDenied)
		return
	}
}
