package common

import "encoding/json"

type HandshakeMessage struct {
	ClientType string `json:"client_type"`
	AccessKey  string `json:"access_key"`
	ClientID   string `json:"client_id"`
	Type       string `json:"type,omitempty"`
	Target     string `json:"target,omitempty"`
}

func NewHandshakeMessage(clientType, accessKey, clientID, connType, target string) *HandshakeMessage {
	return &HandshakeMessage{
		ClientType: clientType,
		AccessKey:  accessKey,
		ClientID:   clientID,
		Type:       connType,
		Target:     target,
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
