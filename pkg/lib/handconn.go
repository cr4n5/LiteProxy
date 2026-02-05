package lib

import (
	"context"
	"encoding/json"

	"github.com/cr4n5/liteproxy/config"
	"github.com/quic-go/quic-go"
)

type HandConnMessage struct {
	Protocol   string `json:"protocol"`
	ClientAddr string `json:"client_addr"`
}

func NewHandConnMessage(cfg *config.RouteConfig) *HandConnMessage {
	return &HandConnMessage{
		Protocol:   cfg.Protocol,
		ClientAddr: cfg.ClientAddr,
	}
}

func (hcm *HandConnMessage) Encode() ([]byte, error) {
	return json.Marshal(hcm)
}

func DecodeHandConnMessage(data []byte) (*HandConnMessage, error) {
	var hcm HandConnMessage
	err := json.Unmarshal(data, &hcm)
	if err != nil {
		return nil, err
	}
	return &hcm, nil
}

func HandConnToTarget(ctx context.Context, cfg *config.RouteConfig, conn *quic.Conn) (*quic.Stream, error) {
	stream, err := StreamOpen(ctx, conn, 0)
	if err != nil {
		return nil, err
	}

	// Send HandConnMessage
	hcm := NewHandConnMessage(cfg)
	data, err := hcm.Encode()
	if err != nil {
		return nil, err
	}
	_, err = StreamWriteWithLength(stream, data, 0)
	if err != nil {
		return nil, err
	}

	return stream, nil
}
