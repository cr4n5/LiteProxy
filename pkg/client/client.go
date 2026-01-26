package client

import (
	"context"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
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
	err := c.Run(ctx)
	if err != nil {
		log.Fatalf("client exited with error: %v", err)
	}
}

func (c *Client) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	conn, err := common.HandshakeToBridge(ctx, c.cfg)
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
	// Handle handshake for new incoming stream
	buf := make([]byte, 1024)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := stream.Read(buf)
	if err != nil {
		return
	}
	hm, err := common.DecodeHandshakeMessage(buf[:n])
	if err != nil {
		return
	}
	// Connect to target
	switch hm.Type {
	case "tcp":
		_, err := net.Dial("tcp", hm.Target)
		if err != nil {
			stream.CancelRead(common.ErrAccessDenied)
			return
		}
	default:
		// Unsupported type
		stream.CancelRead(common.ErrAccessDenied)
		return
	}
}
