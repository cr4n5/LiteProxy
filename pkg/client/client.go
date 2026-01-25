package client

import (
	"context"
	"net"
	"time"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/quic-go/quic-go"
)

type Client struct {
	cfg *config.ClientConfig
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg.Client,
	}
}

func (c *Client) Start() {
	// Implement client start logic here
}

func (c *Client) Run(ctx context.Context) error {
	// connect to bridge and perform handshake
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctxTimeout, c.cfg.BridgeAddr, common.GenerateTLSConfig(), nil)
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
	hm := common.NewHandshakeMessage("client", c.cfg.AccessKey, c.cfg.ClientID, "", "")
	data, err := hm.Encode()
	stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = stream.Write(data)
	if err != nil {
		return err
	}

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
		targetConn, err := net.Dial("tcp", hm.Target)
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
