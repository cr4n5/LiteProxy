package lib

import (
	"context"
	"encoding/json"

	"github.com/cr4n5/liteproxy/config"
	"github.com/quic-go/quic-go"
)

type HandshakeMessage struct {
	ClientType string `json:"client_type"`
	AccessKey  string `json:"access_key"`
	ClientID   string `json:"client_id"`
}

func NewHandshakeMessage(cfg *config.Config) *HandshakeMessage {
	return &HandshakeMessage{
		ClientType: cfg.Mode,
		AccessKey:  cfg.AccessKey,
		ClientID:   cfg.ClientID,
	}
}

func (hm *HandshakeMessage) Encode() ([]byte, error) {
	return json.Marshal(hm)
}

func DecodeHandshakeMessage(data []byte) (*HandshakeMessage, error) {
	var hm HandshakeMessage
	err := json.Unmarshal(data, &hm)
	if err != nil {
		return nil, err
	}
	return &hm, nil
}

func HandshakeToBridge(ctx context.Context, cfg *config.Config) (*quic.Conn, error) {
	// connect to bridge and perform handshake
	conn, err := QuicDialAddr(ctx, cfg.BridgeAddr, 0)
	if err != nil {
		return nil, err
	}
	stream, err := StreamOpen(ctx, conn, 0)
	if err != nil {
		return nil, err
	}
	// Handle handshake
	hm := NewHandshakeMessage(cfg)
	data, err := hm.Encode()
	_, err = StreamWrite(stream, data, 0)
	if err != nil {
		return nil, err
	}
	// wait close
	StreamWaitClosed(stream)
	return conn, nil
}
