package common

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/lib"
	"github.com/quic-go/quic-go"
)

type HandshakeMessage struct {
	ClientType string `json:"client_type"`
	AccessKey  string `json:"access_key"`
	ClientID   string `json:"client_id"`
	Type       string `json:"type,omitempty"`
	Target     string `json:"target,omitempty"`
}

func NewHandshakeMessage(cfg *config.Config) *HandshakeMessage {
	return &HandshakeMessage{
		ClientType: cfg.Mode,
		AccessKey:  cfg.AccessKey,
		ClientID:   cfg.ClientID,
		Type:       cfg.Type,
		Target:     cfg.Target,
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
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctxTimeout, cfg.BridgeAddr, GenerateClientTLSConfig(), nil)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctxTimeout)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	// Handle handshake
	hm := NewHandshakeMessage(cfg)
	data, err := hm.Encode()
	_, err = lib.StreamWrite(stream, data, 0)
	if err != nil {
		return nil, err
	}
	// wait close
	lib.StreamWaitClosed(stream)
	return conn, nil
}
